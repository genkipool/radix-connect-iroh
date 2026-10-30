//! Forwards the library's `tracing` events to a logger of the host (Timber on
//! Android), so iroh problems show up next to the app's own logs. Every line carries
//! the context it happened in (`session=… role=… local=… peer=… conn=… send_seq=…`),
//! and IP addresses are redacted.

use std::sync::{Arc, Once, RwLock};

use radix_connect_iroh::logging::{
    DiagnosticsLayer, format_event_with_context, host_log_enabled, needed_for_diagnostics,
};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum IrohLogLevel {
    /// Something failed.
    Error,
    /// Something unexpected happened.
    Warn,
    /// Lifecycle (session started, connected, disconnected...).
    Info,
    /// Details useful when diagnosing a connection.
    Debug,
    /// Everything.
    Trace,
}

impl From<IrohLogLevel> for Level {
    fn from(level: IrohLogLevel) -> Self {
        match level {
            IrohLogLevel::Error => Self::ERROR,
            IrohLogLevel::Warn => Self::WARN,
            IrohLogLevel::Info => Self::INFO,
            IrohLogLevel::Debug => Self::DEBUG,
            IrohLogLevel::Trace => Self::TRACE,
        }
    }
}

impl From<Level> for IrohLogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::Error,
            Level::WARN => Self::Warn,
            Level::INFO => Self::Info,
            Level::DEBUG => Self::Debug,
            Level::TRACE => Self::Trace,
        }
    }
}

/// Receives the library's log lines. Called from the library's own threads.
#[uniffi::export(with_foreign)]
pub trait IrohLogSink: Send + Sync {
    /// One log line.
    fn log(&self, level: IrohLogLevel, target: String, message: String);
}

struct Installed {
    sink: Arc<dyn IrohLogSink>,
    max_level: Level,
}

static SINK: RwLock<Option<Installed>> = RwLock::new(None);
static SUBSCRIBER: Once = Once::new();

/// Sends log lines up to `max_level` to `sink`, replacing any previous sink. iroh and
/// QUIC internals are capped (see `radix_connect_iroh::logging::host_log_enabled`).
#[uniffi::export]
pub fn iroh_install_log_sink(sink: Arc<dyn IrohLogSink>, max_level: IrohLogLevel) {
    if let Ok(mut installed) = SINK.write() {
        *installed = Some(Installed {
            sink,
            max_level: max_level.into(),
        });
    }
    install_subscriber();
    tracing::callsite::rebuild_interest_cache();
}

/// Installs the library's subscriber, once. Sessions need it even without a sink: it
/// notices when another holder of a link's key takes this end's place on the relay.
pub(crate) fn install_subscriber() {
    SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::registry()
            .with(DiagnosticsLayer)
            .with(SinkLayer);
        // Fails only if the process already has a global subscriber, which then
        // receives our events instead.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

fn enabled(metadata: &Metadata<'_>) -> bool {
    SINK.read().ok().is_some_and(|installed| {
        installed.as_ref().is_some_and(|installed| {
            host_log_enabled(metadata.target(), *metadata.level(), installed.max_level)
        })
    })
}

struct SinkLayer;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for SinkLayer {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        enabled(metadata) || needed_for_diagnostics(metadata)
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if !enabled(metadata) {
            return;
        }
        let sink = SINK
            .read()
            .ok()
            .and_then(|installed| installed.as_ref().map(|installed| installed.sink.clone()));
        if let Some(sink) = sink {
            sink.log(
                (*metadata.level()).into(),
                metadata.target().to_owned(),
                format_event_with_context(event, &ctx),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_round_trip() {
        for level in [
            IrohLogLevel::Error,
            IrohLogLevel::Warn,
            IrohLogLevel::Info,
            IrohLogLevel::Debug,
            IrohLogLevel::Trace,
        ] {
            assert_eq!(IrohLogLevel::from(Level::from(level)), level);
        }
    }
}
