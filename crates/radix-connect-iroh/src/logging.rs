//! Helpers for the bindings that forward `tracing` events to a host logger (Timber on
//! Android, the extension's logger in the browser).
//!
//! Neither this crate nor its bindings log passwords, keys or message contents.

use std::fmt::{self, Write as _};

use tracing::field::{Field, Visit};
use tracing::{Event, Level};

/// Whether an event at `level` from `target` should reach a host logger configured
/// at `max_level`.
///
/// Events of this library follow `max_level`. iroh and QUIC internals are far
/// chattier: they are capped at `INFO`, and at `WARN` unless `max_level` is `DEBUG` or
/// more verbose.
pub fn host_log_enabled(target: &str, level: Level, max_level: Level) -> bool {
    let cap = if target.starts_with("radix_connect_iroh") {
        max_level
    } else if max_level >= Level::DEBUG {
        Level::INFO
    } else {
        max_level.min(Level::WARN)
    };
    level <= cap
}

/// Renders an event as one line: its message followed by ` key=value` pairs.
pub fn format_event(event: &Event<'_>) -> String {
    let mut line = LineVisitor::default();
    event.record(&mut line);
    line.message + &line.fields
}

#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: String,
}

impl Visit for LineVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_events_follow_the_requested_level() {
        assert!(host_log_enabled(
            "radix_connect_iroh::session",
            Level::DEBUG,
            Level::DEBUG
        ));
        assert!(!host_log_enabled(
            "radix_connect_iroh::session",
            Level::TRACE,
            Level::DEBUG
        ));
        assert!(host_log_enabled(
            "radix_connect_iroh_uniffi",
            Level::TRACE,
            Level::TRACE
        ));
    }

    #[test]
    fn third_party_events_are_capped() {
        assert!(host_log_enabled("iroh::socket", Level::INFO, Level::TRACE));
        assert!(!host_log_enabled(
            "iroh::socket",
            Level::DEBUG,
            Level::TRACE
        ));
        assert!(!host_log_enabled("noq_proto", Level::INFO, Level::INFO));
        assert!(host_log_enabled("noq_proto", Level::WARN, Level::INFO));
        assert!(!host_log_enabled("iroh", Level::WARN, Level::ERROR));
    }
}
