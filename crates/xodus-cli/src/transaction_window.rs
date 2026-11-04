use std::process::ExitCode;

use xodus::models::live::DAProperty;

use crate::webview::{HandlerControl, RuntimeCommands, SessionHandler, SessionId, WebviewRequest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionOutcome {
    Completed,
    Resumable,
    RolledBack,
    RecoveryRequired,
    Cancelled,
    Failed,
}

impl TransactionOutcome {
    fn from_exit_code(code: ExitCode) -> Self {
        if code == ExitCode::SUCCESS {
            Self::Completed
        } else if code == ExitCode::from(crate::transaction_status::RESUMABLE_EXIT_STATUS) {
            Self::Resumable
        } else if code == ExitCode::from(crate::transaction_status::ROLLED_BACK_EXIT_STATUS) {
            Self::RolledBack
        } else if code == ExitCode::from(crate::transaction_status::QUARANTINED_EXIT_STATUS) {
            Self::RecoveryRequired
        } else if code == ExitCode::from(crate::CANCELLED_EXIT_STATUS) {
            Self::Cancelled
        } else {
            Self::Failed
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::Completed => "Package operation complete",
            Self::Resumable => "Package operation paused",
            Self::RolledBack => "Previous package state restored",
            Self::RecoveryRequired => "Package recovery required",
            Self::Cancelled => "Package operation cancelled",
            Self::Failed => "Package operation failed",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Completed => "The package operation completed successfully.",
            Self::Resumable => {
                "A partial download was retained and will be revalidated before use in a transaction."
            }
            Self::RolledBack => {
                "The operation failed, and the previous package state was restored."
            }
            Self::RecoveryRequired => {
                "Rollback could not restore the previous state. Preserve the recovery data and review the terminal output."
            }
            Self::Cancelled => {
                "The operation was cancelled. Review the terminal output before retrying."
            }
            Self::Failed => "The operation failed. Review the terminal output for details.",
        }
    }

    const fn tone(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::Resumable => "notice",
            Self::RolledBack => "notice",
            Self::RecoveryRequired | Self::Failed => "error",
            Self::Cancelled => "neutral",
        }
    }

    fn html(self) -> String {
        STATUS_PAGE
            .replace("{{tone}}", self.tone())
            .replace("{{title}}", &escape_html(self.title()))
            .replace("{{message}}", &escape_html(self.message()))
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const STATUS_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Package operation status</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #111827; color: #f9fafb; }
    main { box-sizing: border-box; width: min(34rem, calc(100% - 2rem)); padding: 2rem; border: 1px solid #374151; border-radius: 1rem; background: #1f2937; }
    .brand { margin: 0 0 1.5rem; color: #9ca3af; font-size: .9rem; letter-spacing: .08em; text-transform: uppercase; }
    .state { display: inline-block; margin: 0 0 1rem; padding: .35rem .7rem; border-radius: 999px; font-weight: 650; }
    .success { background: #064e3b; color: #d1fae5; }
    .notice { background: #78350f; color: #fef3c7; }
    .error { background: #7f1d1d; color: #fee2e2; }
    .neutral { background: #374151; color: #f3f4f6; }
    h1 { margin: 0; font-size: 1.6rem; line-height: 1.25; }
    .message { margin: 1rem 0 0; color: #d1d5db; line-height: 1.6; }
    .hint { margin: 1.5rem 0 0; color: #9ca3af; font-size: .9rem; }
  </style>
</head>
<body>
  <main>
    <p class="brand">Xodus</p>
    <p class="state {{tone}}" aria-hidden="true">{{title}}</p>
    <h1>{{title}}</h1>
    <p class="message" role="status" aria-live="polite">{{message}}</p>
    <p class="hint">Close this window to return to the terminal.</p>
  </main>
</body>
</html>"#;

struct TransactionWindowHandler {
    outcome: TransactionOutcome,
}

impl SessionHandler for TransactionWindowHandler {
    type Output = ();

    fn bootstrap(
        &mut self,
        runtime: &mut RuntimeCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        runtime.open_session(WebviewRequest::local_html(
            self.outcome.title(),
            self.outcome.html(),
        ));
        Ok(())
    }

    fn on_token(
        &mut self,
        _session_id: SessionId,
        _data: DAProperty,
        _runtime: &mut RuntimeCommands,
    ) -> Result<HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(HandlerControl::Continue)
    }

    fn on_closed(
        &mut self,
        _session_id: SessionId,
        _runtime: &mut RuntimeCommands,
    ) -> Result<HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(HandlerControl::Complete(()))
    }
}

pub(crate) fn show(code: ExitCode) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = TransactionOutcome::from_exit_code(code);
    crate::webview::run_sessions(TransactionWindowHandler { outcome })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::{TransactionOutcome, escape_html};

    #[test]
    fn exit_codes_map_to_distinct_transaction_outcomes() {
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::SUCCESS),
            TransactionOutcome::Completed
        );
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::from(
                crate::transaction_status::RESUMABLE_EXIT_STATUS
            )),
            TransactionOutcome::Resumable
        );
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::from(
                crate::transaction_status::ROLLED_BACK_EXIT_STATUS
            )),
            TransactionOutcome::RolledBack
        );
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::from(
                crate::transaction_status::QUARANTINED_EXIT_STATUS
            )),
            TransactionOutcome::RecoveryRequired
        );
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::from(crate::CANCELLED_EXIT_STATUS)),
            TransactionOutcome::Cancelled
        );
        assert_eq!(
            TransactionOutcome::from_exit_code(ExitCode::FAILURE),
            TransactionOutcome::Failed
        );
    }

    #[test]
    fn status_page_is_local_static_and_escapes_dynamic_text() {
        for outcome in [
            TransactionOutcome::Completed,
            TransactionOutcome::Resumable,
            TransactionOutcome::RolledBack,
            TransactionOutcome::RecoveryRequired,
            TransactionOutcome::Cancelled,
            TransactionOutcome::Failed,
        ] {
            let html = outcome.html();
            assert!(html.contains(outcome.title()));
            assert!(html.contains(outcome.message()));
            assert!(!html.contains("https://"));
            assert!(!html.contains("<script"));
        }

        assert_eq!(
            escape_html("<unsafe & \"quoted\">"),
            "&lt;unsafe &amp; &quot;quoted&quot;&gt;"
        );
    }

    #[test]
    fn resumable_status_does_not_claim_partial_bytes_are_already_verified() {
        let message = TransactionOutcome::Resumable.message();

        assert!(message.contains("revalidated before use"));
        assert!(!message.contains("verified partial"));
    }
}
