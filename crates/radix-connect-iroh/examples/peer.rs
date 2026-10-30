//! A command-line end of a link, to try the transport against the real wallet or the
//! real Connector Extension (or against another `peer`).
//!
//! ```text
//! RADIX_CONNECT_PASSWORD=<password-hex> cargo run --example peer -- <wallet|connector> [relay-url]
//! ```
//!
//! Every line read from stdin is sent as one message, except `/network`, which reports a
//! network change (as hosts do on connectivity changes and when the app returns to the
//! foreground); events are printed to stdout as `state <state>` and `message <json>`
//! lines. The password is the link's 64-character hex connection password; it is read
//! from the environment rather than the command line, which other local users can see.
//!
//! The library's log lines go to stderr, as hosts get them, up to `RADIX_CONNECT_LOG`
//! (`error`, `warn`, `info` — the default —, `debug` or `trace`).

use std::process::ExitCode;

use radix_connect_iroh::logging::{
    DiagnosticsLayer, format_event_with_context, host_log_enabled, needed_for_diagnostics,
};
use radix_connect_iroh::{ConnectionPassword, Role, Session, SessionConfig, SessionEvent};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Prints the library's events to stderr, filtered and rendered as for a host.
struct Stderr(Level);

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Stderr {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        host_log_enabled(metadata.target(), *metadata.level(), self.0)
            || needed_for_diagnostics(metadata)
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if host_log_enabled(metadata.target(), *metadata.level(), self.0) {
            let line = format_event_with_context(event, &ctx);
            eprintln!("{} {}: {line}", metadata.level(), metadata.target());
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let level = match std::env::var("RADIX_CONNECT_LOG").as_deref() {
        Ok("error") => Level::ERROR,
        Ok("warn") => Level::WARN,
        Ok("debug") => Level::DEBUG,
        Ok("trace") => Level::TRACE,
        _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(DiagnosticsLayer)
            .with(Stderr(level)),
    )?;
    let mut args = std::env::args().skip(1);
    let usage = "usage: RADIX_CONNECT_PASSWORD=<password-hex> peer <wallet|connector> [relay-url]";
    let role = match args.next().as_deref() {
        Some("wallet") => Role::Wallet,
        Some("connector") => Role::Connector,
        _ => return Err(usage.into()),
    };
    let password =
        ConnectionPassword::from_hex(&std::env::var("RADIX_CONNECT_PASSWORD").map_err(|_| usage)?)?;
    // No relay argument: n0's public relays, as the wallet and the extension default to.
    let relay_url = args.next();

    let config = SessionConfig::for_relay(relay_url.as_deref())?;
    let session = Session::start(&password, role, config).await?;
    let relays = relay_url.as_deref().unwrap_or("n0's public relays");
    eprintln!(
        "{role:?} {} -> peer {} via {relays}",
        session.local_id(),
        session.peer_id()
    );

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            event = session.next_event() => match event {
                Some(SessionEvent::StateChanged(state)) => {
                    println!("state {state:?}");
                    eprintln!("diagnostics: {}", session.diagnostics());
                }
                Some(SessionEvent::Message(message)) => println!("message {message}"),
                None => break,
            },
            line = stdin.next_line() => match line? {
                Some(line) if line.trim().is_empty() => {}
                Some(line) if line.trim() == "/network" => session.network_changed().await,
                Some(line) => match session.send(line.trim()).await {
                    Ok(()) => println!("sent"),
                    Err(error) => {
                        println!("send-failed {error}");
                        eprintln!("diagnostics: {}", session.diagnostics());
                    }
                },
                None => break,
            },
        }
    }
    session.close().await;
    Ok(())
}
