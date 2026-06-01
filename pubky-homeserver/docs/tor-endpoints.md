# Tor onion endpoints in pkarr

Homeservers can advertise a **Tor v3 hidden service** (`.onion`) in their apex pkarr `SignedPacket` alongside existing direct and ICANN endpoints.

## Protocol unchanged

- Same `pkarr` library, **Mainline DHT over UDP**, and HTTP relays.
- Only **record content** changes (optional SVCB with `target = <onion>`).
- User `_pubky` records still point at the **homeserver pubkey (z32)**.

## SVCB priorities

| Priority | Target | Use |
|----------|--------|-----|
| 1 | `.` + IP hints | Pubky TLS (native clients) — most preferred |
| 10 | ICANN domain | HTTP via reverse proxy / localhost |
| 20 | `.onion` | HTTP via Tor hidden service — least preferred (no DNS required) |

Lower priority numbers are tried first (RFC 9460). Use `endpoint_mode = "tor_only"` when only the onion path should be advertised.

## Homeserver config

See `[pkdns]` in `config.sample.toml`:

- `tor_onion` or `tor_onion_file` — v3 hostname
- `public_onion_http_port` — virtual port on the HS (default `80`)
- `endpoint_mode` — `hybrid` (default) or `tor_only` (omit direct `A` and Pubky TLS SVCB)

Tor is **not** embedded in the homeserver. Map the hidden service to `icann_listen_socket` (plain HTTP, default port `6286`) using a system Tor daemon.
