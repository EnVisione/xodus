use std::error::Error;
use std::fmt;
use std::io;
use std::process::ExitCode;

pub(crate) const RESUMABLE_EXIT_STATUS: u8 = 75;
pub(crate) const ROLLED_BACK_EXIT_STATUS: u8 = 74;
pub(crate) const QUARANTINED_EXIT_STATUS: u8 = 76;

#[derive(Debug)]
struct RolledBackTransactionError(io::Error);

impl fmt::Display for RolledBackTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "operation failed but rollback restored the prior package state: {}",
            self.0
        )
    }
}

impl Error for RolledBackTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
struct QuarantinedTransactionError {
    operation: io::Error,
    rollback: io::Error,
}

impl fmt::Display for QuarantinedTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rollback could not restore the prior package state; transaction quarantined for recovery: {}; rollback error: {}",
            self.operation, self.rollback
        )
    }
}

impl Error for QuarantinedTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.operation)
    }
}

pub(crate) fn rolled_back_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), RolledBackTransactionError(error))
}

pub(crate) fn quarantined_error(operation: io::Error, rollback: io::Error) -> io::Error {
    io::Error::new(
        operation.kind(),
        QuarantinedTransactionError {
            operation,
            rollback,
        },
    )
}

fn source_contains<T: Error + 'static>(source: &(dyn Error + 'static)) -> bool {
    if source.is::<T>() {
        return true;
    }
    if let Some(error) = source.downcast_ref::<io::Error>()
        && error_contains::<T>(error)
    {
        return true;
    }
    source.source().is_some_and(source_contains::<T>)
}

fn error_contains<T: Error + 'static>(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source_contains::<T>(source))
}

pub(crate) fn is_rolled_back_error(error: &io::Error) -> bool {
    error_contains::<RolledBackTransactionError>(error)
}

pub(crate) fn is_quarantined_error(error: &io::Error) -> bool {
    error_contains::<QuarantinedTransactionError>(error)
}

pub(crate) fn exit_code_for_transaction_error(error: &io::Error) -> ExitCode {
    if is_quarantined_error(error) {
        ExitCode::from(QUARANTINED_EXIT_STATUS)
    } else if is_rolled_back_error(error) {
        if error.kind() == io::ErrorKind::Interrupted {
            ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        } else {
            ExitCode::from(ROLLED_BACK_EXIT_STATUS)
        }
    } else {
        ExitCode::FAILURE
    }
}

pub(crate) fn exit_code_for_download_error(error: &io::Error, resumable: bool) -> ExitCode {
    if resumable {
        ExitCode::from(RESUMABLE_EXIT_STATUS)
    } else {
        exit_code_for_transaction_error(error)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::ExitCode;

    use super::{
        QUARANTINED_EXIT_STATUS, RESUMABLE_EXIT_STATUS, ROLLED_BACK_EXIT_STATUS,
        exit_code_for_download_error, exit_code_for_transaction_error, quarantined_error,
        rolled_back_error,
    };

    #[test]
    fn resumable_exit_status_is_nonzero_and_distinct_from_failure() {
        assert_ne!(RESUMABLE_EXIT_STATUS, 0);
        assert_ne!(RESUMABLE_EXIT_STATUS, 1);
    }

    #[test]
    fn download_status_reports_resumable_only_when_a_durable_prefix_remains() {
        let interrupted = io::Error::new(io::ErrorKind::Interrupted, "connection ended");

        assert_eq!(
            exit_code_for_download_error(&interrupted, true),
            ExitCode::from(RESUMABLE_EXIT_STATUS)
        );
        assert_eq!(
            exit_code_for_download_error(&interrupted, false),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn transaction_error_reports_rolled_back_status_only_after_rollback() {
        let rolled_back = rolled_back_error(io::Error::other("promotion failed"));
        let failed = io::Error::other("rollback incomplete");

        assert_eq!(
            exit_code_for_transaction_error(&rolled_back),
            ExitCode::from(ROLLED_BACK_EXIT_STATUS)
        );
        assert_eq!(exit_code_for_transaction_error(&failed), ExitCode::FAILURE);
    }

    #[test]
    fn interrupted_transaction_with_completed_rollback_reports_cancellation() {
        let error = rolled_back_error(io::Error::new(
            io::ErrorKind::Interrupted,
            "transaction cancelled",
        ));

        assert_eq!(
            exit_code_for_transaction_error(&error),
            ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        );
    }

    #[test]
    fn incomplete_rollback_reports_quarantine_through_nested_io_errors() {
        let error = quarantined_error(
            io::Error::other("promotion failed"),
            io::Error::other("backup restore failed"),
        );
        let nested = io::Error::other(error);

        assert_eq!(
            exit_code_for_transaction_error(&nested),
            ExitCode::from(QUARANTINED_EXIT_STATUS)
        );
    }
}
