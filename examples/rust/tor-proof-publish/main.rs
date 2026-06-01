//! Sign up on a local homeserver and write a file to emit a homeserver event.
//!
//! Uses clearnet/LAN (hybrid pkarr with localhost or direct hints). Does not use Tor.
//!
//! ```bash
//! cargo run -p pubky-core-examples --bin tor-proof-publish -- <homeserver_z32> \
//!   --signup-token <token>
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use pubky::{ClientId, Keypair, Pubky, PublicKey};

#[derive(Parser, Debug)]
#[command(version, about = "Tor proof: signup and write on a local homeserver (LAN only)")]
struct Cli {
    /// Homeserver public key (z32)
    homeserver: String,

    /// Admin signup token (required when homeserver signup_mode is token_required)
    #[arg(long)]
    signup_token: Option<String>,

    /// Path to write under the new user's storage
    #[arg(long, default_value = "/pub/tor-proof/demo.txt")]
    path: String,

    /// File content
    #[arg(short, long, default_value = "hello from tor-proof-publish")]
    content: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let homeserver = PublicKey::try_from(cli.homeserver.as_str())
        .context("invalid homeserver public key")?;

    let keypair = Keypair::random();
    let user_pk = keypair.public_key();
    println!("Generated user: {}", user_pk.z32());

    let pubky = Pubky::new()?;
    let signer = pubky.signer(keypair);

    println!("Signing up on homeserver {} ...", homeserver.z32());
    signer
        .signup(&homeserver, cli.signup_token.as_deref())
        .await
        .context("signup failed (check homeserver is running and signup_token)")?;

    println!("Signed up; publishing _pubky to DHT.");

    let session = signer
        .signin(ClientId::new("tor-proof.publish")?)
        .await
        .context("signin after signup")?;

    session
        .storage()
        .put(&cli.path, cli.content.as_bytes().to_vec())
        .await
        .context("storage put")?;

    let uri = format!("pubky://{}/{}", user_pk.z32(), cli.path.trim_start_matches('/'));
    println!();
    println!("--- tor-proof-publish done ---");
    println!("homeserver_z32={}", homeserver.z32());
    println!("user_z32={}", user_pk.z32());
    println!("resource_uri={uri}");
    println!();
    println!("Next: wait ~1-2 min for DHT, then run tor-proof-index with the z32 keys above.");

    Ok(())
}
