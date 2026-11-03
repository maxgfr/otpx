//! Copying codes, cleared after a delay.
//!
//! A detached `otpx __clear-clipboard` process takes the text on stdin, puts it on the
//! clipboard, waits, and clears it if it is still the same text. On Linux the clipboard
//! belongs to the process that set it, so that process must outlive the command anyway.

use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use crate::{exit, fail};

/// Arguments of the hidden helper.
#[derive(Debug, clap::Args)]
pub struct ClearArgs {
    /// Seconds before clearing.
    #[arg(long, default_value_t = 20)]
    after: u64,
}

/// Copies `text`, cleared after `secs` seconds (0: never cleared).
pub fn copy(text: &str, secs: u64) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .args(["__clear-clipboard", "--after", &secs.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            fail(
                exit::ERROR,
                format!("cannot start the clipboard helper: {e}"),
            )
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| fail(exit::ERROR, "clipboard helper has no stdin"))?;
    stdin.write_all(text.as_bytes())?;
    drop(stdin);
    // Wait for the copy itself (the helper writes nothing; it closes stdout once copied).
    std::thread::sleep(Duration::from_millis(150));
    Ok(())
}

/// The helper: copy stdin, wait, clear if unchanged.
pub fn clear(args: ClearArgs) -> anyhow::Result<ExitCode> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let mut cb =
        arboard::Clipboard::new().map_err(|e| fail(exit::ERROR, format!("clipboard: {e}")))?;
    let deadline = Instant::now() + Duration::from_secs(args.after);
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use arboard::SetExtLinux;
        if args.after > 0 {
            // Serves the clipboard until the deadline, then lets go of it.
            let _ = cb.set().wait_until(deadline).text(text.clone());
            return Ok(ExitCode::SUCCESS);
        }
    }
    cb.set_text(text.clone())
        .map_err(|e| fail(exit::ERROR, format!("clipboard: {e}")))?;
    if args.after == 0 {
        return Ok(ExitCode::SUCCESS);
    }
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    if cb.get_text().is_ok_and(|now| now == text) {
        let _ = cb.clear();
    }
    Ok(ExitCode::SUCCESS)
}
