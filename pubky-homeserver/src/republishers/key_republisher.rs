//! Background task to republish the homeserver's pkarr packet to the DHT.
//!
//! This task is started by the [crate::HomeserverCore] and runs until the homeserver is stopped.
//!
//! The task is responsible for:
//! - Republishing the homeserver's pkarr packet to the DHT every hour.
//! - Stopping the task when the homeserver is stopped.

use std::borrow::Cow;
use std::net::IpAddr;
use anyhow::Result;
use pkarr::dns::Name;
use pkarr::errors::PublishError;
use pkarr::{
    dns::rdata::{SVCParam, SVCB},
    SignedPacket,
};

use crate::app_context::AppContext;
use crate::data_directory::{OnionAddress, PkdnsEndpointMode};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

/// Errors that can occur when building a `Republishers`.
#[derive(Debug, thiserror::Error)]
pub enum KeyRepublisherBuildError {
    /// Failed to run the key republisher.
    #[error("Key republisher error: {0}")]
    KeyRepublisher(anyhow::Error),
}

/// Republishes the homeserver's pkarr packet to the DHT every hour.
pub(crate) struct HomeserverKeyRepublisher {
    join_handle: JoinHandle<()>,
}

impl HomeserverKeyRepublisher {
    pub async fn start(
        context: &AppContext,
        icann_http_port: u16,
        pubky_tls_port: u16,
    ) -> Result<Self> {
        let signed_packet = create_signed_packet(context, icann_http_port, pubky_tls_port)?;
        let join_handle =
            Self::start_periodic_republish(context.pkarr_client.clone(), &signed_packet).await?;
        Ok(Self { join_handle })
    }

    async fn publish_once(
        client: &pkarr::Client,
        signed_packet: &SignedPacket,
    ) -> Result<(), PublishError> {
        let res = client.publish(signed_packet, None).await;
        if let Err(e) = &res {
            tracing::warn!(
                "Failed to publish the homeserver's pkarr packet to the DHT: {}",
                e
            );
        } else {
            tracing::info!("Published the homeserver's pkarr packet to the DHT.");
        }
        res
    }

    /// Start the periodic republish task which will republish the server packet to the DHT every hour.
    ///
    /// # Errors
    /// - Throws an error if the initial publish fails.
    /// - Throws an error if the periodic republish task is already running.
    async fn start_periodic_republish(
        client: pkarr::Client,
        signed_packet: &SignedPacket,
    ) -> anyhow::Result<JoinHandle<()>> {
        // Publish once to make sure the packet is published to the DHT before this
        // function returns.
        // Throws an error if the packet is not published to the DHT.
        Self::publish_once(&client, signed_packet).await?;

        // Start the periodic republish task.
        let signed_packet = signed_packet.clone();
        let handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60 * 60)); // 1 hour in seconds
            interval.tick().await; // This ticks immediatly. Wait for first interval before starting the loop.
            loop {
                interval.tick().await;
                let _ = Self::publish_once(&client, &signed_packet).await;
            }
        });

        Ok(handle)
    }

    /// Stop the periodic republish task.
    pub fn stop(&self) {
        self.join_handle.abort();
    }
}

impl Drop for HomeserverKeyRepublisher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Resolve configured Tor onion hostname from `tor_onion` or `tor_onion_file`.
pub fn resolve_tor_onion(pkdns: &crate::data_directory::PkdnsToml) -> Result<Option<String>> {
    if let Some(onion) = &pkdns.tor_onion {
        return Ok(Some(onion.0.clone()));
    }
    if let Some(path) = &pkdns.tor_onion_file {
        let contents = std::fs::read_to_string(path)?;
        let trimmed = contents.trim().to_string();
        OnionAddress::new(trimmed.clone())?;
        return Ok(Some(trimmed));
    }
    Ok(None)
}

pub fn create_signed_packet(
    context: &AppContext,
    local_icann_http_port: u16,
    local_pubky_tls_port: u16,
) -> Result<SignedPacket> {
    let pkdns = &context.config_toml.pkdns;
    let tor_only = pkdns.endpoint_mode == PkdnsEndpointMode::TorOnly;
    let tor_onion = resolve_tor_onion(pkdns)?;

    if tor_only && tor_onion.is_none() {
        anyhow::bail!(
            "pkdns.endpoint_mode is tor_only but neither tor_onion nor tor_onion_file is set"
        );
    }

    let root_name: Name = "."
        .try_into()
        .expect(". is the root domain and always valid");

    let mut signed_packet_builder = SignedPacket::builder();

    let public_ip = pkdns.public_ip;
    let public_pubky_tls_port = pkdns
        .public_pubky_tls_port
        .unwrap_or(local_pubky_tls_port);
    let public_icann_http_port = pkdns
        .public_icann_http_port
        .unwrap_or(local_icann_http_port);
    let public_onion_http_port = pkdns.public_onion_http_port.unwrap_or(80);

    if !tor_only {
        // `SVCB(HTTPS)` record pointing to the pubky tls port and the public ip address
        let mut svcb = SVCB::new(1, root_name.clone());
        svcb.set_port(public_pubky_tls_port);
        match &public_ip {
            IpAddr::V4(ip) => {
                svcb.set_ipv4hint(&[ip.to_bits()]);
            }
            IpAddr::V6(ip) => {
                svcb.set_ipv6hint(&[ip.to_bits()]);
            }
        };
        signed_packet_builder = signed_packet_builder.https(root_name.clone(), svcb, 60 * 60);
    }

    if let Some(onion) = &tor_onion {
        let mut svcb = SVCB::new(20, root_name.clone());
        svcb.set_port(public_onion_http_port);
        svcb.target = onion.as_str().try_into()?;
        signed_packet_builder = signed_packet_builder.https(root_name.clone(), svcb, 60 * 60);
        tracing::info!("Publishing Tor onion endpoint {onion} port {public_onion_http_port}");
    }

    if let Some(domain) = &pkdns.icann_domain {
        let mut svcb = SVCB::new(10, root_name.clone());

        let http_port_be_bytes = public_icann_http_port.to_be_bytes();
        if domain.0 == "localhost" {
            svcb.set_param(SVCParam::Unknown(
                pubky_common::constants::reserved_param_keys::HTTP_PORT,
                Cow::Borrowed(&http_port_be_bytes),
            ));
        }
        svcb.target = domain.0.as_str().try_into()?;
        signed_packet_builder = signed_packet_builder.https(root_name.clone(), svcb, 60 * 60);
    }

    if !tor_only {
        signed_packet_builder =
            signed_packet_builder.address(root_name.clone(), public_ip, 60 * 60);
    }

    Ok(signed_packet_builder.build(&context.keypair)?)
}

#[cfg(test)]
mod tests {
    use futures_lite::StreamExt;
    use pkarr::extra::endpoints::Endpoint;
    use std::net::{Ipv4Addr, SocketAddr};

    use std::str::FromStr;

    use super::*;
    use crate::data_directory::{OnionAddress, PkdnsEndpointMode};

    const TEST_ONION: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_resolve_https_endpoint_with_pkarr_client() {
        let context = AppContext::test().await;
        let _republisher = HomeserverKeyRepublisher::start(&context, 8080, 8080)
            .await
            .unwrap();
        let pkarr_client = context.pkarr_client.clone();
        let hs_pubky = context.keypair.public_key();
        // Make sure the pkarr packet of the hs is resolvable.
        let _packet = pkarr_client.resolve(&hs_pubky).await.unwrap();
        // Make sure the pkarr client can resolve the endpoint of the hs.
        let qname = hs_pubky.z32();
        let endpoint = pkarr_client
            .resolve_https_endpoint(qname.as_str())
            .await
            .unwrap();
        assert_eq!(
            endpoint.to_socket_addrs().first().unwrap().clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_tor_onion_svcb_in_packet() {
        let mut context = AppContext::test().await;
        context.config_toml.pkdns.tor_onion =
            Some(OnionAddress::from_str(TEST_ONION).unwrap());
        let _republisher = HomeserverKeyRepublisher::start(&context, 6286, 6287)
            .await
            .unwrap();
        let client = context.pkarr_client.clone();
        let packet = client.resolve(&context.keypair.public_key()).await.unwrap();
        let endpoints: Vec<Endpoint> = client
            .resolve_https_endpoints(&context.keypair.public_key().to_z32())
            .collect()
            .await;
        let onion_ep = endpoints
            .iter()
            .find(|e| e.domain() == Some(TEST_ONION))
            .expect("onion SVCB present");
        assert_eq!(onion_ep.port(), Some(80));
        assert!(packet.all_resource_records().count() >= 2);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_tor_only_omits_direct_and_a() {
        let mut context = AppContext::test().await;
        context.config_toml.pkdns.endpoint_mode = PkdnsEndpointMode::TorOnly;
        context.config_toml.pkdns.tor_onion =
            Some(OnionAddress::from_str(TEST_ONION).unwrap());
        let _republisher = HomeserverKeyRepublisher::start(&context, 6286, 6287)
            .await
            .unwrap();
        let packet = context
            .pkarr_client
            .resolve(&context.keypair.public_key())
            .await
            .unwrap();
        let has_a = packet.all_resource_records().any(|rr| {
            matches!(
                rr.rdata,
                pkarr::dns::rdata::RData::A(_) | pkarr::dns::rdata::RData::AAAA(_)
            )
        });
        assert!(!has_a, "tor_only must not publish A/AAAA");
        let endpoints: Vec<Endpoint> = context
            .pkarr_client
            .resolve_https_endpoints(&context.keypair.public_key().to_z32())
            .collect()
            .await;
        assert!(
            endpoints.iter().any(|e| e.domain() == Some(TEST_ONION)),
            "tor_only must publish onion SVCB"
        );
        assert!(
            !endpoints.iter().any(|e| e.target() == "."),
            "tor_only must not publish direct (.) SVCB"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_endpoints() {
        let mut context = AppContext::test().await;
        context.keypair = pubky_common::crypto::Keypair::random();
        let _republisher = HomeserverKeyRepublisher::start(&context, 8080, 8080)
            .await
            .unwrap();
        let pubkey = context.keypair.public_key();

        let client = pkarr::Client::builder().build().unwrap();
        let packet = client.resolve(&pubkey).await.unwrap();
        let rr: Vec<&pkarr::dns::ResourceRecord> = packet.all_resource_records().collect();
        assert_eq!(rr.len(), 3);

        let endpoints: Vec<Endpoint> = client
            .resolve_https_endpoints(&pubkey.to_z32())
            .collect()
            .await;
        assert_eq!(endpoints.len(), 2);
    }
}
