//! Defence in depth behind BR-846: one round of one source, or one relay, run so that a panic
//! inside it is an error for that source and that round, not the end of the daemon.
//!
//! The requirement is that nothing a provider says can panic (checked arithmetic, bounds
//! checks). This is what stands behind it if something still does: the guardian keeps signing
//! for its other chains and keeps serving the signature API. The panic is still printed by the
//! panic hook, and the error is logged by the caller like any other.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::task::Poll;

use anyhow::{anyhow, Result};

/// Runs `fut`; a panic while it is polled becomes `Err`, and the future is dropped unfinished.
/// What it had written is what a crash at that point would have left, which the stores are
/// built for: records are written atomically, and a cursor moves only after what it passes.
pub async fn isolated<T>(what: &str, fut: impl Future<Output = Result<T>>) -> Result<T> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        match catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(poll) => poll,
            Err(panic) => {
                let message = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a panic with no message".into());
                Poll::Ready(Err(anyhow!(
                    "{what}: PANICKED ({message}); treated as an error for this round — this is a bug, report it"
                )))
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panic_inside_is_an_error_outside_and_a_result_passes_through() {
        let overflow = |n: u64| async move {
            tokio::task::yield_now().await;
            // What BR-846 was: an addition on a provider's number, with overflow checks on.
            Ok::<u64, anyhow::Error>(n.checked_add(1).expect("attempt to add with overflow"))
        };
        assert_eq!(isolated("eth", overflow(1)).await.unwrap(), 2);
        let err = format!("{:#}", isolated("eth", overflow(u64::MAX)).await.unwrap_err());
        assert!(err.contains("eth: PANICKED") && err.contains("overflow"), "{err}");
        let refused = isolated("eth", async { Err::<(), _>(anyhow!("refused")) }).await;
        assert_eq!(format!("{:#}", refused.unwrap_err()), "refused");
    }
}
