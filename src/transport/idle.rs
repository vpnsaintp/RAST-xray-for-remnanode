//! Reusable write-stall deadline for raw relay operations.
//!
//! Never guard a raw read with this timer: inactivity in one direction says
//! nothing about the health of its peer direction.

use std::{io, pin::Pin, time::Duration};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    time::{Instant, Sleep},
};

#[derive(Debug, Default)]
pub(super) struct RelayIdleDeadline {
    sleep: Option<Pin<Box<Sleep>>>,
}

#[derive(Debug)]
pub(super) enum RelayIdleError {
    Timeout,
    Io(io::Error),
}

impl RelayIdleDeadline {
    pub(super) const fn new() -> Self {
        Self { sleep: None }
    }

    pub(super) fn reset(&mut self, timeout: Duration) -> Result<(), RelayIdleError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(RelayIdleError::Timeout)?;
        match &mut self.sleep {
            Some(sleep) => sleep.as_mut().reset(deadline),
            None => self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        Ok(())
    }

    pub(super) async fn guard<T, F>(&mut self, operation: F) -> Result<T, RelayIdleError>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        let Some(sleep) = self.sleep.as_mut() else {
            return Err(RelayIdleError::Timeout);
        };
        tokio::select! {
            biased;
            result = operation => result.map_err(RelayIdleError::Io),
            () = sleep => Err(RelayIdleError::Timeout),
        }
    }

    pub(super) async fn shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), RelayIdleError> {
        self.guard(writer.shutdown()).await
    }
}
