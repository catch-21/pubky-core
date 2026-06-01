use serde::{Deserialize, Serialize};

/// How the homeserver advertises reachability in its apex pkarr packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PkdnsEndpointMode {
    /// Direct Pubky TLS + optional ICANN + optional Tor onion.
    #[default]
    Hybrid,
    /// Tor onion only (omit direct SVCB and `A` records). Requires `tor_onion`.
    TorOnly,
}
