# Sync and new devices

The vault file is the same on every remote; `otpx sync` fetches it, merges
account by account (both sides keep their changes, deletions propagate, HOTP
counters never go back), and writes back only if the remote did not change
meanwhile. Snapshots of every local write: `otpx backup ls`.

## Set up (the user runs these: they prompt for a token)

- Private GitHub repository (recommended, git history = every version):
  `! otpx sync setup github --repo you/otpx-vault` (add `--create` to create it
  with the GitHub CLI). Token: fine-grained, only that repository,
  Contents read and write: https://github.com/settings/personal-access-tokens/new
- Secret gist: `! otpx sync setup gist` (token with Gists read and write; reaches all gists).
- Folder (iCloud Drive, Dropbox, Syncthing, USB): `otpx sync setup folder <path> --json`
  (no token, the agent may run it).

Several remotes can be active; `otpx sync ls --json`, `otpx sync --json`,
`otpx sync remove <name> --json`.

## New computer

1. `brew install maxgfr/tap/otpx`
2. Either the same `! otpx sync setup github --repo you/otpx-vault` (fetches the
   vault), or on the old machine `! otpx link` (passphrase-protected link
   carrying remotes and tokens, valid 15 min) then on the new one
   `! otpx receive '<link>'`.
3. `! otpx unlock`, optionally `! otpx quick-unlock enable touchid` (macOS) or `pin`.

The web app takes the same GitHub repo, or the device link, in Sync.

## Problems

- exit 7 "holds another vault": the remote has a different vault; on a new
  device with nothing to keep: `! otpx sync setup … --replace-local`.
- exit 8 HTTP 401/403: token expired or too narrow; set it up again.
- `otpx doctor --json` lists what is missing (no remote, old sync, token, recovery code).
