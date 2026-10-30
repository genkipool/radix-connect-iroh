//! A command-line end of a link, to try the transport against the real wallet or the
//! real Connector Extension (or against another `peer`).
//!
//! ```text
//! RADIX_CONNECT_PASSWORD=<password-hex> cargo run --example peer -- <wallet|connector> [relay-url]
//! ```
//!
//! Every line read from stdin is sent as one message; events are printed to stdout as
//! `state <state>` and `message <json>` lines. The password is the link's 64-character
//! hex connection password; it is read from the environment rather than the command
//! line, which other local users can see.

use std::process::ExitCode;

use radix_connect_iroh::{ConnectionPassword, Role, Session, SessionConfig, SessionEvent};
use tokio::io::{AsyncBufReadExt, BufReader};

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
