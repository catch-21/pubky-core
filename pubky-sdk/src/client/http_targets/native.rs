use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::net::TcpStream;

use crate::actors::pkdns::extract_host_from_packet;
use crate::errors::RequestError;
use crate::{PubkyHttpClient, PublicKey, Result, cross_log};
use reqwest::{IntoUrl, Method, RequestBuilder};
use url::Url;

const TRANSPORT_CACHE_TTL: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone)]
pub(crate) enum ResolvedTransport {
    PubkyTls,
    Icann { domain: String, port: Option<u16> },
    Onion { domain: String, port: Option<u16> },
}

fn is_onion_host(domain: &str) -> bool {
    domain.ends_with(".onion")
}

#[derive(Default)]
struct EndpointHints {
    has_direct: bool,
    direct_addrs: Vec<std::net::SocketAddr>,
    onion: Option<(String, Option<u16>)>,
    icann: Option<(String, Option<u16>)>,
}

/// Resolves and caches per-host transport decisions (`PubkyTLS` vs ICANN vs Tor onion).
///
/// Accepts a `&pkarr::Client` reference when resolution is needed — does not
/// own the pkarr client, which is shared across the SDK.
#[derive(Debug, Clone)]
pub(crate) struct TransportResolver {
    cache: Arc<RwLock<HashMap<String, (Instant, ResolvedTransport)>>>,
    guards: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    tor_only_transport: bool,
    prefer_onion: bool,
}

impl TransportResolver {
    pub(crate) fn new(tor_only_transport: bool, prefer_onion: bool) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            guards: Arc::new(Mutex::new(HashMap::new())),
            tor_only_transport,
            prefer_onion,
        }
    }

    /// Look up the transport for `pk`, resolving via PKARR on cache miss.
    pub(crate) async fn resolve(&self, pk: &str, pkarr: &pkarr::Client) -> ResolvedTransport {
        if let Some(t) = self.cached(pk) {
            return t;
        }
        self.resolve_and_cache(pk, pkarr).await
    }

    /// Fast path: return a cached, non-expired transport decision.
    fn cached(&self, pk: &str) -> Option<ResolvedTransport> {
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(pk)
            .filter(|(ts, _)| ts.elapsed() < TRANSPORT_CACHE_TTL)
            .map(|(_, t)| t.clone())
    }

    /// Slow path: acquire a per-key guard, double-check the cache, resolve,
    /// and store the result.
    async fn resolve_and_cache(&self, pk: &str, pkarr: &pkarr::Client) -> ResolvedTransport {
        let guard = {
            let mut guards = self.guards.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(guards.entry(pk.to_string()).or_default())
        };
        let _lock = guard.lock().await;

        if let Some(t) = self.cached(pk) {
            return t;
        }

        let t = self.resolve_from_pkarr(pkarr, pk).await;
        self.cache
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(pk.to_string(), (Instant::now(), t.clone()));
        t
    }

    /// Inspect PKARR endpoints and probe reachability to pick a transport.
    async fn resolve_from_pkarr(&self, pkarr: &pkarr::Client, qname: &str) -> ResolvedTransport {
        let mut hints = Self::collect_endpoint_hints(pkarr, qname, self.tor_only_transport).await;

        // Hosted users publish `_pubky` → homeserver, not onion on their own apex packet.
        if self.tor_only_transport && hints.onion.is_none() && hints.icann.is_none() {
            if let Some(hs_z32) = Self::resolve_homeserver_z32(pkarr, qname).await {
                if hs_z32 != qname {
                    let hs_hints =
                        Self::collect_endpoint_hints(pkarr, &hs_z32, self.tor_only_transport)
                            .await;
                    if hs_hints.onion.is_some() || hs_hints.icann.is_some() {
                        hints = hs_hints;
                    }
                }
            }
        }

        let EndpointHints {
            has_direct,
            direct_addrs,
            onion,
            icann,
        } = hints;

        if self.tor_only_transport {
            if let Some((domain, port)) = onion {
                return ResolvedTransport::Onion { domain, port };
            }
            if let Some((domain, port)) = icann {
                return ResolvedTransport::Icann { domain, port };
            }
            return ResolvedTransport::PubkyTls;
        }

        if !has_direct {
            return Self::domain_fallback(onion, icann, self.prefer_onion)
                .unwrap_or(ResolvedTransport::PubkyTls);
        }

        let Some(icann_pair) = icann else {
            return ResolvedTransport::PubkyTls;
        };

        if probe_reachable(&direct_addrs, PROBE_TIMEOUT).await {
            return ResolvedTransport::PubkyTls;
        }

        cross_log!(
            warn,
            "Direct endpoint unreachable for {qname}; fallback"
        );
        if let Some(t) = Self::domain_fallback(onion, Some(icann_pair.clone()), self.prefer_onion) {
            return t;
        }
        let (domain, port) = icann_pair;
        ResolvedTransport::Icann { domain, port }
    }

    async fn collect_endpoint_hints(
        pkarr: &pkarr::Client,
        qname: &str,
        tor_only_transport: bool,
    ) -> EndpointHints {
        let stream = pkarr.resolve_https_endpoints(qname);
        futures_util::pin_mut!(stream);

        let mut hints = EndpointHints::default();

        while let Some(ep) = stream.next().await {
            if let Some(domain) = ep.domain() {
                if is_onion_host(domain) {
                    if hints.onion.is_none() {
                        hints.onion = Some((domain.to_string(), ep.port()));
                    }
                } else if hints.icann.is_none() {
                    hints.icann = Some((domain.to_string(), ep.port()));
                }
            } else if !tor_only_transport {
                hints.has_direct = true;
                hints.direct_addrs.extend(ep.to_socket_addrs());
            }
        }

        hints
    }

    async fn resolve_homeserver_z32(pkarr: &pkarr::Client, user_pk: &str) -> Option<String> {
        let user = PublicKey::try_from_z32(user_pk).ok()?;
        let packet = pkarr.resolve(&user).await?;
        extract_host_from_packet(&packet)
    }

    fn domain_fallback(
        onion: Option<(String, Option<u16>)>,
        icann: Option<(String, Option<u16>)>,
        prefer_onion: bool,
    ) -> Option<ResolvedTransport> {
        if prefer_onion {
            if let Some((domain, port)) = onion {
                return Some(ResolvedTransport::Onion { domain, port });
            }
        }
        if let Some((domain, port)) = icann {
            return Some(ResolvedTransport::Icann { domain, port });
        }
        if let Some((domain, port)) = onion {
            return Some(ResolvedTransport::Onion { domain, port });
        }
        None
    }
}

async fn probe_reachable(addrs: &[std::net::SocketAddr], timeout: Duration) -> bool {
    for addr in addrs {
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    ResolvedPubky,
    Icann,
    Pubky,
}

fn classify_host(host: &str) -> HostKind {
    if let Some(pk_host) = host.strip_prefix("_pubky.") {
        if PublicKey::is_pubky_prefixed(pk_host) {
            return HostKind::Icann;
        }
        if PublicKey::try_from_z32(pk_host).is_ok() {
            return HostKind::ResolvedPubky;
        }
    } else if PublicKey::is_pubky_prefixed(host) || PublicKey::try_from_z32(host).is_err() {
        return HostKind::Icann;
    }
    HostKind::Pubky
}

impl PubkyHttpClient {
    /// Constructs a [`reqwest::RequestBuilder`] for the given HTTP `method` and `url`,
    /// routing through the client's unified request path.
    /// Build an HTTP request with pkarr-aware transport (Pubky TLS, ICANN, or Tor onion).
    pub async fn cross_request(
        &self,
        method: Method,
        mut url: Url,
    ) -> Result<RequestBuilder> {
        let Some(pk) = self.prepare_request(&mut url).await? else {
            return Ok(self.request(method, &url));
        };
        let transport = self.transport.resolve(&pk, &self.pkarr).await;
        self.build_pubky_request(method, &url, &pk, &transport)
    }

    /// Build a [`RequestBuilder`] for a resolved pubky host transport.
    fn build_pubky_request(
        &self,
        method: Method,
        url: &Url,
        pk: &str,
        transport: &ResolvedTransport,
    ) -> Result<RequestBuilder> {
        match transport {
            ResolvedTransport::PubkyTls => Ok(self.http.request(method, url.as_str())),
            ResolvedTransport::Icann { domain, port } => {
                let mut icann_url = url.clone();
                icann_url.set_host(Some(domain))?;
                if let Some(p) = port {
                    icann_url
                        .set_port(Some(*p))
                        .map_err(|_err| url::ParseError::InvalidPort)?;
                }
                cross_log!(debug, "ICANN fallback for {pk} via {domain}");
                Ok(self
                    .icann_http
                    .request(method, icann_url.as_str())
                    .header("pubky-host", pk))
            }
            ResolvedTransport::Onion { domain, port } => {
                let tor_http = self.tor_http.as_ref().ok_or_else(|| {
                    RequestError::Validation {
                        message: "Tor SOCKS proxy not configured; use \
                                   PubkyHttpClientBuilder::tor_socks_proxy()"
                            .to_string(),
                    }
                })?;
                let mut tor_url = url.clone();
                let _ = tor_url.set_scheme("http");
                tor_url.set_host(Some(domain))?;
                if let Some(p) = port {
                    tor_url
                        .set_port(Some(*p))
                        .map_err(|_err| url::ParseError::InvalidPort)?;
                }
                cross_log!(debug, "Tor onion transport for {pk} via {domain}");
                Ok(tor_http
                    .request(method, tor_url.as_str())
                    .header("pubky-host", pk))
            }
        }
    }

    /// Detect pubky hosts and return the z32 public key when applicable.
    #[allow(
        clippy::unused_async,
        reason = "keep async signature aligned with WASM build"
    )]
    pub async fn prepare_request(&self, url: &mut Url) -> Result<Option<String>> {
        let host = url.host_str().unwrap_or("");

        if let Some(stripped) = host.strip_prefix("_pubky.") {
            if PublicKey::is_pubky_prefixed(stripped) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(stripped).is_ok() {
                return Ok(Some(stripped.to_string()));
            }
        } else {
            if PublicKey::is_pubky_prefixed(host) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(host).is_ok() {
                return Ok(Some(host.to_string()));
            }
        }

        Ok(None)
    }

    /// Start building a request with platform-specific host handling (native-only).
    pub fn request<U: IntoUrl>(&self, method: Method, url: &U) -> RequestBuilder {
        let url_str = url.as_str();

        let host = Url::parse(url_str)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));

        if let Some(ref host) = host {
            match classify_host(host) {
                HostKind::ResolvedPubky => {
                    cross_log!(debug, "PubkyTLS request for resolved _pubky host {}", host);
                    return self.http.request(method, url_str);
                }
                HostKind::Icann => {
                    cross_log!(debug, "Standard TLS request for ICANN host {}", host);
                    return self.icann_http.request(method, url_str);
                }
                HostKind::Pubky => {
                    cross_log!(debug, "PubkyTLS request for pubky host {}", host);
                }
            }
        }

        self.http.request(method, url_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::dns::rdata::SVCB;
    use pkarr::{Keypair, SignedPacket};

    #[test]
    fn classify_hosts() {
        assert_eq!(classify_host("example.com"), HostKind::Icann);
        let z32 = "o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy";
        assert_eq!(
            classify_host(&format!("_pubky.{z32}")),
            HostKind::ResolvedPubky
        );
        assert_eq!(classify_host(z32), HostKind::Pubky);
    }

    #[tokio::test]
    async fn probe_unreachable_returns_false() {
        let addr = "192.0.2.1:1".parse().unwrap();
        assert!(!probe_reachable(&[addr], Duration::from_millis(100)).await);
    }

    fn pkarr_with_packet(keypair: &Keypair, packet: &SignedPacket) -> pkarr::Client {
        let mut builder = PubkyHttpClient::builder();
        builder.pkarr(|b| b.no_default_network().bootstrap(&["127.0.0.1:1"]));
        let client = builder.build().unwrap();
        let cache_key: pkarr::CacheKey = keypair.public_key().into();
        client.pkarr.cache().unwrap().put(&cache_key, packet);
        client.pkarr
    }

    #[test]
    fn build_pubky_request_icann_rewrites_url_and_sets_header() {
        let client = PubkyHttpClient::builder()
            .pkarr(|b| b.no_default_network().bootstrap(&["127.0.0.1:1"]))
            .build()
            .unwrap();
        let z32 = "o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy";
        let url = Url::parse(&format!("https://{z32}/pub/app/file.txt")).unwrap();
        let transport = ResolvedTransport::Icann {
            domain: "example.com".to_string(),
            port: Some(8443),
        };

        let req = client
            .build_pubky_request(Method::GET, &url, z32, &transport)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(req.url().host_str(), Some("example.com"));
        assert_eq!(req.url().port(), Some(8443));
        assert_eq!(req.headers().get("pubky-host").unwrap(), z32);
    }

    #[tokio::test]
    async fn resolve_transport_direct_only() {
        let kp = Keypair::random();
        let mut svcb = SVCB::new(1, ".".try_into().unwrap());
        svcb.set_port(6881);
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), svcb, 3600)
            .address(".".try_into().unwrap(), "192.0.2.1".parse().unwrap(), 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);
        let resolver = TransportResolver::new(false, false);

        let t = resolver.resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(matches!(t, ResolvedTransport::PubkyTls));
    }

    #[tokio::test]
    async fn resolve_transport_icann_only() {
        let kp = Keypair::random();
        let svcb = SVCB::new(1, "example.com".try_into().unwrap());
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), svcb, 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);
        let resolver = TransportResolver::new(false, false);

        let t = resolver.resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(matches!(t, ResolvedTransport::Icann { .. }));
    }

    #[tokio::test]
    async fn resolve_transport_onion_only_tor_mode() {
        const ONION: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
        let kp = Keypair::random();
        let mut svcb = SVCB::new(20, ONION.try_into().unwrap());
        svcb.set_port(80);
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), svcb, 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);
        let resolver = TransportResolver::new(true, true);

        let t = resolver.resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(
            matches!(t, ResolvedTransport::Onion { ref domain, port: Some(80) } if domain == ONION)
        );
    }

    #[tokio::test]
    async fn resolve_transport_tor_mode_follows_pubky_homeserver_onion() {
        const ONION: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion";
        let user = Keypair::random();
        let homeserver = Keypair::random();

        let mut hs_onion = SVCB::new(20, ONION.try_into().unwrap());
        hs_onion.set_port(80);
        let hs_packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), hs_onion, 3600)
            .sign(&homeserver)
            .unwrap();

        let hs_z32 = homeserver.public_key().to_z32();
        let pubky_record = SVCB::new(
            1,
            hs_z32.as_str().try_into().expect("homeserver z32 as SVCB target"),
        );
        let user_packet = SignedPacket::builder()
            .https("_pubky".try_into().unwrap(), pubky_record, 3600)
            .sign(&user)
            .unwrap();

        let mut builder = PubkyHttpClient::builder();
        builder.pkarr(|b| b.no_default_network().bootstrap(&["127.0.0.1:1"]));
        let client = builder.build().unwrap();
        let cache = client.pkarr.cache().unwrap();
        cache.put(
            &pkarr::PublicKey::from(user.public_key()).into(),
            &user_packet,
        );
        cache.put(
            &pkarr::PublicKey::from(homeserver.public_key()).into(),
            &hs_packet,
        );
        let resolver = TransportResolver::new(true, true);
        let t = resolver
            .resolve_from_pkarr(client.pkarr(), &user.public_key().to_z32())
            .await;
        assert!(
            matches!(t, ResolvedTransport::Onion { ref domain, port: Some(80) } if domain == ONION),
            "expected homeserver onion via _pubky fallback, got {t:?}"
        );
    }

    #[tokio::test]
    async fn resolve_transport_both_unreachable_direct_falls_back() {
        let kp = Keypair::random();
        let mut direct = SVCB::new(1, ".".try_into().unwrap());
        direct.set_port(6881);
        let icann = SVCB::new(10, "example.com".try_into().unwrap());
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), direct, 3600)
            .https(".".try_into().unwrap(), icann, 3600)
            .address(".".try_into().unwrap(), "192.0.2.1".parse().unwrap(), 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);
        let resolver = TransportResolver::new(false, false);

        let t = resolver.resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(
            matches!(t, ResolvedTransport::Icann { ref domain, .. } if domain == "example.com"),
            "expected ICANN fallback, got {t:?}"
        );
    }
}
