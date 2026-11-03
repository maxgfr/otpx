//! Touch ID (macOS LocalAuthentication).
//!
//! A command-line tool cannot be signed with the entitlements that let the keychain itself
//! demand biometrics, so otpx asks LocalAuthentication first and reads its keychain item
//! only once Touch ID succeeded. The item is still protected by the login keychain (other
//! apps get a system prompt), and the Touch ID check stops anyone at an unlocked session
//! from reading codes without your finger.

/// True when this Mac can check a fingerprint now.
pub fn available() -> bool {
    imp::available()
}

/// Asks for Touch ID with `reason` ("otpx wants to unlock your vault"). `Ok(false)` when
/// the user cancelled or chose the password instead.
pub fn authenticate(reason: &str) -> anyhow::Result<bool> {
    imp::authenticate(reason)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod imp {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn available() -> bool {
        // SAFETY: `new` returns an owned, initialized LAContext; `canEvaluatePolicy:error:`
        // only reads it and returns its error by value.
        unsafe {
            let ctx = LAContext::new();
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .is_ok()
        }
    }

    pub fn authenticate(reason: &str) -> anyhow::Result<bool> {
        let (tx, rx) = mpsc::channel::<bool>();
        let reply = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let _ = tx.send(ok.as_bool());
        });
        let reason = NSString::from_str(reason);
        // SAFETY: the context, the reason and the block outlive the call (the block is
        // reference-counted and copied by LocalAuthentication); the reply only sends a bool
        // on a channel, from whatever queue LocalAuthentication calls it on.
        let ctx = unsafe { LAContext::new() };
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &reason,
                &reply,
            );
        }
        match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(ok) => Ok(ok),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}
