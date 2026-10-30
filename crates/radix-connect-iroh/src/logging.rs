//! Helpers for the bindings that forward `tracing` events to a host logger (Timber on
//! Android, the extension's logger in the browser).
//!
//! Neither this crate nor its bindings log passwords, keys or message contents, and the
//! lines meant for a host never contain IP addresses: [`format_event`] and
//! [`format_event_with_context`] redact them, from iroh's own events too.
//!
//! A host subscriber stacks a [`DiagnosticsLayer`] under its own layer:
//!
//! ```text
//! tracing_subscriber::registry().with(DiagnosticsLayer).with(HostLayer)
//! ```
//!
//! keeps the callsites [`needed_for_diagnostics`] enabled whatever level the host asked
//! for, and renders the events it forwards with [`format_event_with_context`]. The layer
//! remembers the fields of this crate's spans, so that every line carries the context
//! it happened in (`session=… role=… local=… peer=… conn=… send_seq=…`), and picks out
//! of iroh's events the relay's health notices, which iroh only logs: they tell when
//! another holder of the link's key took this end's place on the relay (see
//! [`Diagnostics::key_collision`](crate::Diagnostics::key_collision)).

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::relay_health::{self, RelayNotice};

/// Target prefix of this crate's events and spans (and of its bindings').
const OWN_TARGET: &str = "radix_connect_iroh";
/// Module of iroh's relay transport; its actor's spans carry the session span down to
/// the tasks that talk to the relay.
const RELAY_TARGET: &str = "iroh::socket::transports::relay";
/// Module of iroh's relay actor, which logs the relay's health notices.
const RELAY_ACTOR_TARGET: &str = "iroh::socket::transports::relay::actor";

/// Whether an event at `level` from `target` should reach a host logger configured
/// at `max_level`.
///
/// Events of this library follow `max_level`. iroh and QUIC internals are far
/// chattier: they are capped at `INFO`, and at `WARN` unless `max_level` is `DEBUG` or
/// more verbose (so iroh's warnings about relays and hole punching reach a host logging
/// at `WARN`).
pub fn host_log_enabled(target: &str, level: Level, max_level: Level) -> bool {
    let cap = if target.starts_with(OWN_TARGET) {
        max_level
    } else if max_level >= Level::DEBUG {
        Level::INFO
    } else {
        max_level.min(Level::WARN)
    };
    level <= cap
}

/// Whether the [`DiagnosticsLayer`] needs a callsite enabled whatever level the host
/// logs at: this crate's spans (the context of every line), the spans iroh's relay
/// tasks run in (they keep that context down to the relay actor) and the relay actor's
/// notices. They are few: one per session, connection and message, and per relay
/// connection.
pub fn needed_for_diagnostics(metadata: &Metadata<'_>) -> bool {
    let target = metadata.target();
    if metadata.is_span() {
        target.starts_with(OWN_TARGET)
            || (target.starts_with(RELAY_TARGET)
                && matches!(metadata.name(), "relay-actor" | "active-relay"))
    } else {
        target == RELAY_ACTOR_TARGET && *metadata.level() <= Level::INFO
    }
}

/// Renders an event as one line: its message followed by ` key=value` pairs, with IP
/// addresses redacted.
pub fn format_event(event: &Event<'_>) -> String {
    let mut line = LineVisitor::default();
    event.record(&mut line);
    redact_ip_addresses(&(line.message + &line.fields)).into_owned()
}

/// [`format_event`], followed by the fields of the spans of this crate the event
/// happened in (session, connection, message), outermost first. Needs a
/// [`DiagnosticsLayer`] in the subscriber.
pub fn format_event_with_context<S>(event: &Event<'_>, ctx: &Context<'_, S>) -> String
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let mut line = LineVisitor::default();
    event.record(&mut line);
    let mut text = line.message + &line.fields;
    if let Some(scope) = ctx.event_scope(event) {
        for span in scope.from_root() {
            if let Some(fields) = span.extensions().get::<SpanFields>() {
                text.push_str(&fields.text);
            }
        }
    }
    redact_ip_addresses(&text).into_owned()
}

/// Replaces every IPv4 and IPv6 address in `text` with `<ip>`, keeping ports: logs get
/// exported and shared, and an IP address is personal data. iroh's own events, errors
/// and relay URLs can contain them.
pub fn redact_ip_addresses(text: &str) -> Cow<'_, str> {
    if !text.contains(['.', ':']) {
        return Cow::Borrowed(text);
    }
    let mut redacted = String::new();
    let mut copied = 0;
    let mut previous: Option<char> = None;
    let mut chars = text.char_indices().peekable();
    while let Some((start, first)) = chars.next() {
        if !is_address_char(first) || previous.is_some_and(is_word_char) {
            previous = Some(first);
            continue;
        }
        // The longest run of characters an address (with its port) is made of.
        let mut end = start + first.len_utf8();
        let mut last = first;
        while let Some(&(index, next)) = chars.peek() {
            if !is_address_char(next) {
                break;
            }
            end = index + next.len_utf8();
            last = next;
            chars.next();
        }
        previous = Some(last);
        let next = chars.peek().map(|&(_, next)| next);
        if next.is_some_and(|next| is_word_char(next) && next != '%') {
            continue;
        }
        let Some(address) = text.get(start..end).and_then(address_length) else {
            continue;
        };
        let mut address_end = start + address;
        // An IPv6 zone (`fe80::1%wlan0`) names a local interface: redact it too.
        if address_end == end && next == Some('%') {
            chars.next();
            address_end += 1;
            while let Some(&(index, zone)) = chars.peek() {
                if !(zone.is_ascii_alphanumeric() || matches!(zone, '_' | '-')) {
                    break;
                }
                address_end = index + zone.len_utf8();
                previous = Some(zone);
                chars.next();
            }
        }
        redacted.push_str(text.get(copied..start).unwrap_or_default());
        redacted.push_str("<ip>");
        copied = address_end;
    }
    if copied == 0 {
        return Cow::Borrowed(text);
    }
    redacted.push_str(text.get(copied..).unwrap_or_default());
    Cow::Owned(redacted)
}

fn is_address_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':' || c == '.'
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Length of the IP address `run` starts with, if it does: the whole run for an IPv6
/// address or a bare IPv4 address, the host part for `IPv4:port`.
fn address_length(run: &str) -> Option<usize> {
    // A sentence may end right after an address.
    let run = run.trim_end_matches('.');
    if run.contains(':') && run.parse::<Ipv6Addr>().is_ok() || run.parse::<Ipv4Addr>().is_ok() {
        return Some(run.len());
    }
    let (host, _port) = run.split_once(':')?;
    host.parse::<Ipv4Addr>().is_ok().then_some(host.len())
}

/// Wraps a value so that it is displayed with its IP addresses redacted. For errors
/// and URLs that come from iroh.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Redacted<T>(pub(crate) T);

impl<T: fmt::Display> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_ip_addresses(&self.0.to_string()))
    }
}

/// A [`tracing_subscriber`] layer for the bindings: it keeps the fields of this crate's
/// spans for [`format_event_with_context`], and hands the relay's health notices, which
/// iroh only logs, to the session they concern.
///
/// It enables nothing by itself: the host's layer must keep the callsites
/// [`needed_for_diagnostics`] enabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiagnosticsLayer;

/// What [`DiagnosticsLayer`] keeps about one of this crate's spans.
#[derive(Debug, Default)]
struct SpanFields {
    /// ` key=value` pairs, as appended to log lines.
    text: String,
    /// The `session` field of a session span.
    session: Option<u64>,
}

impl Visit for SpanFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "session" {
            self.session = Some(value);
        }
        let _ = write!(self.text, " {}={value}", field.name());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        push_field(&mut self.text, field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        push_field(&mut self.text, field.name(), &format!("{value:?}"));
    }
}

impl<S> Layer<S> for DiagnosticsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if !attrs.metadata().target().starts_with(OWN_TARGET) {
            return;
        }
        let mut fields = SpanFields::default();
        attrs.record(&mut fields);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(fields);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<SpanFields>()
        {
            values.record(fields);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != RELAY_ACTOR_TARGET {
            return;
        }
        let Some(notice) = relay_notice(event) else {
            return;
        };
        let session = ctx.event_scope(event).and_then(|scope| {
            scope
                .into_iter()
                .find_map(|span| span.extensions().get::<SpanFields>()?.session)
        });
        if let Some(session) = session {
            relay_health::notify(session, notice);
        }
    }
}

/// The relay's health notice an event of iroh's relay actor reports, if any. iroh logs
/// the relay's `Status` with its `Display` text:
/// `Relay server reports problem: Another endpoint connected with the same endpoint id…`
/// and `Relay server reports: The connection is healthy…`.
fn relay_notice(event: &Event<'_>) -> Option<RelayNotice> {
    let mut line = LineVisitor::default();
    event.record(&mut line);
    let message = line.message.to_ascii_lowercase();
    if !message.contains("relay server reports") {
        None
    } else if message.contains("same endpoint id") {
        Some(RelayNotice::Displaced)
    } else if message.contains("is healthy") {
        Some(RelayNotice::Restored)
    } else {
        None
    }
}

/// Appends ` name=value`, quoting values that contain spaces so lines stay parseable.
fn push_field(line: &mut String, name: &str, value: &str) {
    if value.contains(char::is_whitespace) && !value.starts_with('"') {
        let _ = write!(line, " {name}={value:?}");
    } else {
        let _ = write!(line, " {name}={value}");
    }
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
            push_field(&mut self.fields, field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            push_field(&mut self.fields, field.name(), &format!("{value:?}"));
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
        assert!(host_log_enabled("iroh", Level::WARN, Level::WARN));
        assert!(!host_log_enabled("iroh", Level::WARN, Level::ERROR));
    }

    #[test]
    fn ip_addresses_are_redacted() {
        for (input, expected) in [
            ("from 192.168.1.20:3340 now", "from <ip>:3340 now"),
            ("addr=10.0.0.7", "addr=<ip>"),
            ("Ip(127.0.0.1:4433)", "Ip(<ip>:4433)"),
            ("https://127.0.0.1:1234/", "https://<ip>:1234/"),
            ("[2001:db8::1]:4433", "[<ip>]:4433"),
            ("path=[::1]:4433", "path=[<ip>]:4433"),
            ("via fe80::1ff:fe23:4567:890a%wlan0.", "via <ip>."),
            ("mapped ::ffff:192.0.2.128 ok", "mapped <ip> ok"),
            ("ends with 8.8.8.8.", "ends with <ip>."),
            ("a 1.2.3.4 and a 2001:db8:0:0:0:0:2:1", "a <ip> and a <ip>"),
        ] {
            assert_eq!(redact_ip_addresses(input), expected, "{input}");
        }
    }

    #[test]
    fn other_text_is_left_alone() {
        for input in [
            "iroh::socket::transports::relay",
            "ConnectionError::TimedOut",
            "iroh 1.4.1 at 12:34:56.789",
            "local=4d99dc649e peer=efcc89cfbf",
            "rtt=1.5ms deadbeef:cafe v1.2.3",
            "https://euw1-1.relay.n0.iroh-canary.iroh.link./",
            "no addresses here",
        ] {
            assert!(
                matches!(redact_ip_addresses(input), Cow::Borrowed(_)),
                "{input} -> {}",
                redact_ip_addresses(input)
            );
        }
    }

    #[test]
    fn diagnostics_keep_the_context_and_relay_callsites() {
        use tracing::callsite::Identifier;
        use tracing::field::FieldSet;
        use tracing::metadata::Kind;

        struct Callsite;
        impl tracing::Callsite for Callsite {
            fn set_interest(&self, _: tracing::subscriber::Interest) {}
            fn metadata(&self) -> &Metadata<'_> {
                unreachable!()
            }
        }
        static CALLSITE: Callsite = Callsite;
        let metadata = |name: &'static str, target: &'static str, level, kind| {
            Metadata::new(
                name,
                target,
                level,
                None,
                None,
                None,
                FieldSet::new(&[], Identifier(&CALLSITE)),
                kind,
            )
        };
        assert!(needed_for_diagnostics(&metadata(
            "session",
            "radix_connect_iroh::session",
            Level::INFO,
            Kind::SPAN
        )));
        assert!(needed_for_diagnostics(&metadata(
            "active-relay",
            RELAY_ACTOR_TARGET,
            Level::INFO,
            Kind::SPAN
        )));
        assert!(needed_for_diagnostics(&metadata(
            "relay-actor",
            RELAY_TARGET,
            Level::INFO,
            Kind::SPAN
        )));
        assert!(!needed_for_diagnostics(&metadata(
            "tx",
            RELAY_ACTOR_TARGET,
            Level::INFO,
            Kind::SPAN
        )));
        assert!(needed_for_diagnostics(&metadata(
            "event",
            RELAY_ACTOR_TARGET,
            Level::WARN,
            Kind::EVENT
        )));
        assert!(!needed_for_diagnostics(&metadata(
            "event",
            RELAY_ACTOR_TARGET,
            Level::DEBUG,
            Kind::EVENT
        )));
        assert!(!needed_for_diagnostics(&metadata(
            "event",
            "radix_connect_iroh::session",
            Level::DEBUG,
            Kind::EVENT
        )));
    }
}
