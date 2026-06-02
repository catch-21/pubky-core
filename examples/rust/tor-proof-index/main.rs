//! Resolve a homeserver via live pkarr/DHT and index events over Tor only.
//!
//! Requires a running Tor daemon with SOCKS on 127.0.0.1:9050 (not bundled with homeserver).
//!
//! ```bash
//! cargo run -p pubky-core-examples --bin tor-proof-index -- \
//!   --homeserver <hs_z32> --user <user_z32>
//! ```

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pubky::{Pubky, PubkyHttpClient, PubkyResource, PublicKey};
use reqwest::Method;
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about = "Tor proof: resolve pkarr and fetch homeserver events via Tor SOCKS")]
struct Cli {
    /// Homeserver public key (z32)
    #[arg(long)]
    homeserver: String,

    /// User public key (z32) — verifies _pubky points at this homeserver
    #[arg(long)]
    user: String,

    /// Tor SOCKS address (Tor must be running; default Tor daemon port)
    #[arg(long, default_value = "127.0.0.1:9050")]
    socks: String,

    /// Max events to poll from /events/
    #[arg(long, default_value = "20")]
    limit: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    preflight_tor_socks(&cli.socks).await?;

    let homeserver = PublicKey::try_from(cli.homeserver.as_str())
        .context("invalid homeserver public key")?;
    let user = PublicKey::try_from(cli.user.as_str()).context("invalid user public key")?;

    let client = PubkyHttpClient::builder().tor_indexer(&cli.socks).build()?;
    let pubky = Pubky::with_client(client.clone());

    log_onion_endpoint(&client, &homeserver).await?;

    let resolved_hs = pubky
        .get_homeserver_of(&user)
        .await
        .context("could not resolve user _pubky from DHT")?;
    if resolved_hs != homeserver {
        bail!(
            "user _pubky resolves to {}, expected {}",
            resolved_hs.z32(),
            homeserver.z32()
        );
    }
    println!("Verified user _pubky -> homeserver {}", homeserver.z32());

    let events_url = format!(
        "https://{}/events/?cursor=0&limit={}",
        homeserver.z32(),
        cli.limit
    );
    println!("Polling events over Tor: {events_url}");

    let response = client
        .cross_request(Method::GET, Url::parse(&events_url)?)
        .await?
        .send()
        .await
        .context("GET /events/ over Tor")?;

    let status = response.status();
    let body = response.text().await.context("read events body")?;
    if !status.is_success() {
        bail!("events poll failed: HTTP {status} body={body}");
    }

    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    println!("Received {} event line(s)", lines.len());
    for line in &lines {
        println!("  {line}");
    }

    let mut fetched = 0u32;
    for line in &lines {
        if let Some(cursor) = line.strip_prefix("cursor:") {
            println!("Next cursor: {}", cursor.trim());
            continue;
        }
        let Some((op, uri)) = line.split_once(' ') else {
            println!("Skipping unrecognized line: {line}");
            continue;
        };
        if op != "PUT" {
            println!("Skipping {op}: {uri}");
            continue;
        }
        let resource: PubkyResource = uri.parse().context("parse pubky URI from event")?;
        if resource.owner != user {
            println!(
                "Skipping event for other user: {}",
                resource.to_pubky_url()
            );
            continue;
        }
        let fetch_url = resource
            .to_transport_url()
            .context("build transport URL for resource")?;
        println!(
            "Fetching {} over Tor -> {fetch_url}",
            resource.to_pubky_url()
        );
        let resp = client
            .cross_request(Method::GET, fetch_url)
            .await?
            .send()
            .await
            .with_context(|| format!("fetch {}", resource.to_pubky_url()))?;
        let code = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !code.is_success() {
            bail!(
                "fetch {} failed: HTTP {code} body={text:?}",
                resource.to_pubky_url()
            );
        }
        println!("  HTTP {code} ({} bytes)", text.len());
        println!("  content: {text}");
        fetched += 1;
    }

    println!();
    println!("--- tor-proof-index done ---");
    println!("events_lines={}", lines.len());
    println!("resources_fetched={fetched}");

    Ok(())
}

async fn preflight_tor_socks(socks: &str) -> Result<()> {
    let proxy = if socks.starts_with("socks5") {
        socks.to_string()
    } else {
        format!("socks5h://{socks}")
    };
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy)?)
        .timeout(Duration::from_secs(30))
        .build()?;
    match client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("Tor SOCKS preflight OK ({proxy})");
            Ok(())
        }
        Ok(resp) => bail!(
            "Tor SOCKS reachable but check.torproject.org returned HTTP {}",
            resp.status()
        ),
        Err(e) => bail!(
            "Tor SOCKS preflight failed ({proxy}): {e}. \
             Install and start Tor (see pubky-homeserver/docs/tor-proof.md)."
        ),
    }
}

async fn log_onion_endpoint(client: &PubkyHttpClient, homeserver: &PublicKey) -> Result<()> {
    use futures_util::StreamExt;

    let qname = homeserver.z32();
    let mut stream = client.pkarr().resolve_https_endpoints(&qname);
    while let Some(ep) = stream.next().await {
        if let Some(domain) = ep.domain() {
            if domain.ends_with(".onion") {
                println!(
                    "Resolved onion endpoint from DHT: {domain} port {:?}",
                    ep.port()
                );
                return Ok(());
            }
        }
    }
    bail!(
        "no .onion SVCB in pkarr packet for {qname}; \
         set tor_onion on homeserver and republish"
    );
}
