//! Clipboard copy with auto-clear for `kpd` secrets.
//!
//! [`copy_autoclear`] writes a secret to the system clipboard and schedules an
//! automatic clear after a timeout. The clear is *conditional*: it only fires
//! when the clipboard still holds the exact text we put there, so it never
//! clobbers something the user copied afterwards.
//!
//! The secret is held in a [`secrecy::SecretString`] and zeroized when the
//! returned [`ClipboardGuard`] is dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};

/// Errors that can occur when copying to the clipboard.
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    /// The clipboard could not be opened (for example, no display server).
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
    /// The clipboard could not be written to.
    #[error("failed to write clipboard: {0}")]
    Set(String),
}

/// Copy `text` to the clipboard and schedule an auto-clear after `timeout`.
///
/// Returns a [`ClipboardGuard`] that keeps the clipboard content hosted (on
/// Linux the process that last set the clipboard hosts its content) and owns
/// the secret so it is zeroized on drop. If the guard is dropped without first
/// calling [`ClipboardGuard::cancel`], the auto-clear still fires.
///
/// # Errors
///
/// Returns [`ClipboardError::Unavailable`] if the clipboard cannot be opened,
/// or [`ClipboardError::Set`] if the text cannot be written.
pub fn copy_autoclear(
    text: SecretString,
    timeout: Duration,
) -> Result<ClipboardGuard, ClipboardError> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| ClipboardError::Unavailable(e.to_string()))?;

    clipboard
        .set_text(text.expose_secret())
        .map_err(|e| ClipboardError::Set(e.to_string()))?;

    // The timer thread needs its own copy of the text to compare against the
    // clipboard when it fires. This copy is also zeroized when the thread's
    // closure returns.
    let expected = text.clone();

    let active = Arc::new(AtomicBool::new(true));
    let thread = spawn_autoclear_thread(timeout, Arc::clone(&active), move || {
        clear_if_unchanged(&expected);
    });

    Ok(ClipboardGuard {
        clipboard: ClipboardHandle(clipboard),
        secret: text,
        active,
        thread: Some(thread),
    })
}

/// A guard for a clipboard copy with a scheduled auto-clear.
///
/// Dropping the guard zeroizes the secret and detaches the timer thread (which
/// still auto-clears if the content matches). Use [`clear_now`](Self::clear_now)
/// to clear immediately, or [`cancel`](Self::cancel) to keep the text and stop
/// the auto-clear.
#[derive(Debug)]
pub struct ClipboardGuard {
    /// Kept alive so Linux keeps hosting the copied content.
    clipboard: ClipboardHandle,
    /// The copied secret; zeroized when the guard drops.
    #[expect(dead_code, reason = "held only for zeroization on drop")]
    secret: SecretString,
    /// `true` while the auto-clear is still scheduled.
    active: Arc<AtomicBool>,
    /// The timer thread, detached when the guard is dropped.
    #[expect(dead_code, reason = "held only so dropping the guard detaches it")]
    thread: Option<JoinHandle<()>>,
}

impl ClipboardGuard {
    /// Clear the clipboard immediately and cancel the scheduled auto-clear.
    pub fn clear_now(&mut self) {
        self.active.store(false, Ordering::Release);
        // Best effort: `clear_now` has no error channel, so a failed clear is
        // ignored. The timer has been disarmed regardless.
        let _ = self.clipboard.0.clear();
    }

    /// Consume the guard to cancel the scheduled auto-clear, leaving the text
    /// on the clipboard.
    pub fn cancel(self) {
        self.active.store(false, Ordering::Release);
        // `self` drops here: the secret is zeroized, the clipboard is released
        // (on Linux the content is handed to a running clipboard manager, if
        // any), and the timer thread is detached — it will observe
        // `active == false` and skip clearing.
    }
}

/// Holds an [`arboard::Clipboard`] alive and provides a redacted `Debug`
/// (the inner type does not implement `Debug`).
struct ClipboardHandle(arboard::Clipboard);

impl std::fmt::Debug for ClipboardHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardHandle").finish_non_exhaustive()
    }
}

/// Spawns a thread that sleeps `timeout` and then runs `on_fire` only if
/// `active` is still `true`. There is no busy-wait: the thread sleeps once and
/// checks the flag a single time after waking.
fn spawn_autoclear_thread(
    timeout: Duration,
    active: Arc<AtomicBool>,
    on_fire: impl FnOnce() + Send + 'static,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        if active.load(Ordering::Acquire) {
            on_fire();
        }
    })
}

/// Clears the clipboard if (and only if) it still holds `expected`.
fn clear_if_unchanged(expected: &SecretString) {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(_) => return,
    };
    let current = clipboard.get_text().ok();
    if should_clear(current.as_deref(), expected.expose_secret()) {
        let _ = clipboard.clear();
    }
}

/// Returns `true` when the clipboard should be cleared: it currently holds
/// exactly `expected` (and not something the user copied later).
fn should_clear(current: Option<&str>, expected: &str) -> bool {
    current == Some(expected)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn should_clear_only_when_text_matches() {
        assert!(should_clear(Some("s3cret"), "s3cret"));
        assert!(!should_clear(Some("someone-elses-text"), "s3cret"));
        assert!(!should_clear(None, "s3cret"));
    }

    #[test]
    fn timer_runs_action_when_armed() {
        let active = Arc::new(AtomicBool::new(true));
        let ran = Arc::new(AtomicBool::new(false));
        let ran_for_thread = Arc::clone(&ran);
        let handle = spawn_autoclear_thread(Duration::ZERO, active, move || {
            ran_for_thread.store(true, Ordering::SeqCst);
        });
        handle.join().unwrap();
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn timer_skips_action_when_disarmed() {
        let active = Arc::new(AtomicBool::new(true));
        let ran = Arc::new(AtomicBool::new(false));
        let ran_for_thread = Arc::clone(&ran);
        let handle =
            spawn_autoclear_thread(Duration::from_millis(100), Arc::clone(&active), move || {
                ran_for_thread.store(true, Ordering::SeqCst)
            });
        // Disarm before the timer fires, as `cancel()` / `clear_now()` would.
        active.store(false, Ordering::SeqCst);
        handle.join().unwrap();
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn zero_timeout_still_fires_action() {
        // A zero timeout means "clear immediately": the action still runs.
        let active = Arc::new(AtomicBool::new(true));
        let ran = Arc::new(AtomicBool::new(false));
        let ran_for_thread = Arc::clone(&ran);
        let handle = spawn_autoclear_thread(Duration::ZERO, active, move || {
            ran_for_thread.store(true, Ordering::SeqCst);
        });
        handle.join().unwrap();
        assert!(ran.load(Ordering::SeqCst));
    }

    // Integration tests that need a real clipboard. Run with:
    //   cargo test -- --ignored

    #[test]
    #[ignore = "requires a real X11/Wayland clipboard"]
    fn autoclear_clears_clipboard_after_timeout() {
        let secret_text = "kpd-clipboard-integration-secret";
        let secret = SecretString::from(secret_text.to_string());
        let guard = copy_autoclear(secret, Duration::from_millis(50)).unwrap();

        // Keep the guard alive so the content stays hosted until after the
        // timer fires.
        std::thread::sleep(Duration::from_millis(500));

        let mut clipboard = arboard::Clipboard::new().unwrap();
        let current = clipboard.get_text().unwrap_or_default();
        assert_ne!(current, secret_text, "clipboard should have been cleared");

        drop(guard);
    }

    #[test]
    #[ignore = "requires a real X11/Wayland clipboard (and a clipboard manager)"]
    fn cancel_leaves_text_on_clipboard() {
        let secret_text = "kpd-clipboard-integration-cancel";
        let secret = SecretString::from(secret_text.to_string());
        let guard = copy_autoclear(secret, Duration::from_millis(50)).unwrap();
        guard.cancel();

        // On Linux, `cancel` drops the clipboard, which hands the content to a
        // running clipboard manager. Give it time to settle before reading.
        std::thread::sleep(Duration::from_millis(300));

        let mut clipboard = arboard::Clipboard::new().unwrap();
        let current = clipboard.get_text().unwrap_or_default();
        assert_eq!(current, secret_text, "cancel should leave the text");
    }
}
