//! GitHub remotes: a file in a repository (Contents API, conditional on the blob sha) or
//! a file of a secret gist (checked against the latest revision before writing).
//!
//! `OTPX_GITHUB_API` replaces `https://api.github.com` (tests, GitHub Enterprise).

use serde_json::{Value, json};

use super::{Backend, PushError, Version, agent};
use crate::{exit, fail};

fn api() -> String {
    std::env::var("OTPX_GITHUB_API")
        .unwrap_or_else(|_| "https://api.github.com".to_owned())
        .trim_end_matches('/')
        .to_owned()
}

fn status_error(what: &str, status: u16, body: &str) -> anyhow::Error {
    let msg = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let hint = match status {
        401 => " (token refused: expired or revoked?)",
        403 => " (token lacks access: needs Contents read/write on that repo, or Gists)",
        404 => " (not found, or the token cannot see it)",
        _ => "",
    };
    fail(exit::NETWORK, format!("{what}: HTTP {status} {msg}{hint}"))
}

fn send(
    req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    token: &str,
) -> anyhow::Result<(u16, String)> {
    let mut resp = req
        .header("Authorization", &format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|e| fail(exit::NETWORK, format!("GitHub unreachable: {e}")))?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    Ok((status, body))
}

fn send_json(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    token: &str,
    body: &Value,
) -> anyhow::Result<(u16, String)> {
    let mut resp = req
        .header("Authorization", &format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send_json(body)
        .map_err(|e| fail(exit::NETWORK, format!("GitHub unreachable: {e}")))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    Ok((status, text))
}

/// A file in a repository.
pub struct Repo {
    token: String,
    repo: String,
    path: String,
    branch: String,
}

impl Repo {
    /// `repo` is `owner/name`.
    pub fn new(token: String, repo: &str, path: &str, branch: &str) -> Repo {
        Repo {
            token,
            repo: repo.to_owned(),
            path: path.trim_start_matches('/').to_owned(),
            branch: branch.to_owned(),
        }
    }

    fn url(&self) -> String {
        let path: String = self
            .path
            .split('/')
            .map(percent)
            .collect::<Vec<_>>()
            .join("/");
        format!("{}/repos/{}/contents/{path}", api(), self.repo)
    }

    /// Checks the repository exists and is private.
    pub fn check(&self) -> anyhow::Result<bool> {
        let (status, body) = send(
            agent().get(&format!("{}/repos/{}", api(), self.repo)),
            &self.token,
        )?;
        if status != 200 {
            return Err(status_error(&self.repo, status, &body));
        }
        let v: Value = serde_json::from_str(&body)?;
        Ok(v["private"].as_bool().unwrap_or(false))
    }
}

fn percent(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl Backend for Repo {
    fn fetch(&self) -> anyhow::Result<Option<(String, Version)>> {
        let mut url = self.url();
        if !self.branch.is_empty() {
            url.push_str(&format!("?ref={}", percent(&self.branch)));
        }
        let (status, body) = send(agent().get(&url), &self.token)?;
        match status {
            200 => {
                let v: Value = serde_json::from_str(&body)?;
                let sha = v["sha"].as_str().unwrap_or_default().to_owned();
                let content = match v["content"].as_str() {
                    Some(c) if !c.is_empty() => {
                        let bytes = otpx_core::crypto::unb64(c).map_err(crate::core_failure)?;
                        String::from_utf8(bytes)?
                    }
                    // Over 1 MB the API leaves `content` empty: fetch the raw blob.
                    _ => {
                        let raw = agent()
                            .get(&url)
                            .header("Accept", "application/vnd.github.raw+json");
                        let mut r = raw
                            .header("Authorization", &format!("Bearer {}", self.token))
                            .call()
                            .map_err(|e| fail(exit::NETWORK, format!("GitHub unreachable: {e}")))?;
                        r.body_mut()
                            .with_config()
                            .limit(64 << 20)
                            .read_to_string()?
                    }
                };
                Ok(Some((content, sha)))
            }
            404 => {
                // Distinguish "no file yet" from "no repository / no access".
                let (st, b) = send(
                    agent().get(&format!("{}/repos/{}", api(), self.repo)),
                    &self.token,
                )?;
                if st == 200 {
                    Ok(None)
                } else {
                    Err(status_error(&self.repo, st, &b))
                }
            }
            _ => Err(status_error(&self.repo, status, &body)),
        }
    }

    fn push(
        &self,
        content: &str,
        base: Option<&Version>,
        message: &str,
    ) -> Result<Version, PushError> {
        let mut body =
            json!({ "message": message, "content": otpx_core::crypto::b64(content.as_bytes()) });
        if let Some(sha) = base {
            body["sha"] = json!(sha);
        }
        if !self.branch.is_empty() {
            body["branch"] = json!(self.branch);
        }
        let (status, text) = send_json(agent().put(&self.url()), &self.token, &body)?;
        match status {
            200 | 201 => {
                let v: Value = serde_json::from_str(&text).map_err(anyhow::Error::from)?;
                Ok(v["content"]["sha"].as_str().unwrap_or_default().to_owned())
            }
            // A stale or missing sha.
            409 | 422 => Err(PushError::Conflict),
            _ => Err(PushError::Other(status_error(&self.repo, status, &text))),
        }
    }
}

/// A file of a gist.
pub struct Gist {
    token: String,
    id: String,
    file: String,
}

impl Gist {
    /// The gist `id`, file `file`.
    pub fn new(token: String, id: &str, file: &str) -> Gist {
        Gist {
            token,
            id: id.to_owned(),
            file: file.to_owned(),
        }
    }

    /// Creates a secret gist holding `content`; returns its id.
    pub fn create(token: &str, file: &str, content: &str) -> anyhow::Result<String> {
        let body = json!({
            "description": "otpx vault (encrypted)",
            "public": false,
            "files": { file: { "content": content } },
        });
        let (status, text) = send_json(agent().post(&format!("{}/gists", api())), token, &body)?;
        if status != 201 {
            return Err(status_error("creating the gist", status, &text));
        }
        let v: Value = serde_json::from_str(&text)?;
        Ok(v["id"].as_str().unwrap_or_default().to_owned())
    }
}

impl Backend for Gist {
    fn fetch(&self) -> anyhow::Result<Option<(String, Version)>> {
        let (status, body) = send(
            agent().get(&format!("{}/gists/{}", api(), self.id)),
            &self.token,
        )?;
        if status != 200 {
            return Err(status_error(&format!("gist {}", self.id), status, &body));
        }
        let v: Value = serde_json::from_str(&body)?;
        let version = v["history"][0]["version"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let f = &v["files"][&self.file];
        if f.is_null() {
            return Ok(None);
        }
        let content = if f["truncated"].as_bool() == Some(true) {
            let raw = f["raw_url"].as_str().unwrap_or_default();
            let mut r = agent()
                .get(raw)
                .call()
                .map_err(|e| fail(exit::NETWORK, format!("gist unreachable: {e}")))?;
            r.body_mut()
                .with_config()
                .limit(64 << 20)
                .read_to_string()?
        } else {
            f["content"].as_str().unwrap_or_default().to_owned()
        };
        Ok(Some((content, version)))
    }

    fn push(
        &self,
        content: &str,
        base: Option<&Version>,
        _message: &str,
    ) -> Result<Version, PushError> {
        // Gists have no conditional write: check the revision right before writing.
        let (status, body) = send(
            agent().get(&format!("{}/gists/{}", api(), self.id)),
            &self.token,
        )?;
        if status != 200 {
            return Err(PushError::Other(status_error(
                &format!("gist {}", self.id),
                status,
                &body,
            )));
        }
        let v: Value = serde_json::from_str(&body).map_err(anyhow::Error::from)?;
        let current = v["history"][0]["version"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let has_file = !v["files"][&self.file].is_null();
        if (base.is_none() && has_file) || base.is_some_and(|b| *b != current) {
            return Err(PushError::Conflict);
        }
        let body = json!({ "files": { self.file.clone(): { "content": content } } });
        let (status, text) = send_json(
            agent().patch(&format!("{}/gists/{}", api(), self.id)),
            &self.token,
            &body,
        )?;
        if status != 200 {
            return Err(PushError::Other(status_error(
                &format!("gist {}", self.id),
                status,
                &text,
            )));
        }
        let v: Value = serde_json::from_str(&text).map_err(anyhow::Error::from)?;
        let version = v["history"][0]["version"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        // No conditional write on gists: if another write landed between our check and our
        // PATCH, our parent is not the version we merged. Fetch it so the caller merges it.
        let parent = v["history"][1]["version"].as_str().unwrap_or_default();
        if let Some(b) = base
            && !parent.is_empty()
            && parent != b
        {
            let (st, body) = send(
                agent().get(&format!("{}/gists/{}/{parent}", api(), self.id)),
                &self.token,
            )?;
            if st == 200 {
                let pv: Value = serde_json::from_str(&body).map_err(anyhow::Error::from)?;
                let f = &pv["files"][&self.file];
                let content = if f["truncated"].as_bool() == Some(true) {
                    let raw = f["raw_url"].as_str().unwrap_or_default();
                    let mut r = agent()
                        .get(raw)
                        .call()
                        .map_err(|e| fail(exit::NETWORK, format!("gist unreachable: {e}")))?;
                    Some(
                        r.body_mut()
                            .with_config()
                            .limit(64 << 20)
                            .read_to_string()
                            .map_err(anyhow::Error::from)?,
                    )
                } else {
                    f["content"].as_str().map(str::to_owned)
                };
                if let Some(c) = content {
                    return Err(PushError::Overwrote(c));
                }
            }
        }
        Ok(version)
    }
}
