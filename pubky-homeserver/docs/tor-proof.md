# Tor proof: homeserver over onion + SDK examples

This guide proves end-to-end reachability using the **real Tor network** and **live Mainline DHT**. All tooling lives in the **pubky-core** repository.

## Tor is not bundled with the homeserver

You must install and run **Tor separately**. The homeserver only reads your `.onion` hostname and publishes it in pkarr.

### Install Tor

| Platform | Command |
|----------|---------|
| macOS | `brew install tor` then `brew services start tor` |
| Debian/Ubuntu | `sudo apt install tor` then `sudo systemctl enable --now tor` |
| Umbrel | Use the Tor service included in the Umbrel stack |

### Configure hidden service + SOCKS

Add to your `torrc` (path varies, e.g. `/opt/homebrew/etc/tor/torrc` or `/etc/tor/torrc`):

```text
SocksPort 9050
HiddenServiceDir /var/lib/tor/pubky-homeserver/
HiddenServicePort 80 127.0.0.1:6286
```

Reload Tor, then read the onion hostname:

```bash
sudo systemctl reload tor   # or: brew services restart tor
cat /var/lib/tor/pubky-homeserver/hostname
```

### Verify Tor before the proof

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## Homeserver config (hybrid for this demo)

Use **hybrid** mode so the publish script can reach the server on LAN while the indexer uses onion only.

In `~/.pubky/config.toml` (or your data directory):

```toml
[pkdns]
public_ip = "127.0.0.1"
icann_domain = "localhost"
tor_onion_file = "/var/lib/tor/pubky-homeserver/hostname"
# or: tor_onion = "your....onion"
public_onion_http_port = 80
endpoint_mode = "hybrid"

[general]
signup_mode = "open"
# Or keep token_required and create a token via admin API (port 6288).
```

Restart the homeserver and confirm logs show pkarr publish success.

## Step 1 — Publish user + event (LAN, no Tor)

From `pubky-core`:

```bash
cargo run -p pubky-core-examples --bin tor-proof-publish -- \
  <HOMESERVER_Z32> \
  --signup-token <TOKEN_IF_REQUIRED>
```

Output includes `user_z32` and `resource_uri`. No Tor is used; traffic goes to `localhost` via hybrid pkarr.

## Step 2 — Wait for DHT

Wait **1–2 minutes** so the homeserver apex packet and user `_pubky` propagate on Mainline/relays.

## Step 3 — Index over Tor only

```bash
cargo run -p pubky-core-examples --bin tor-proof-index -- \
  --homeserver <HOMESERVER_Z32> \
  --user <USER_Z32>
```

This script:

1. Preflights Tor SOCKS (`127.0.0.1:9050`)
2. Resolves the homeserver `.onion` from **live DHT**
3. Verifies `user` → `_pubky` → `homeserver`
4. Polls `GET /events/` and fetches `pubky://` resources **only via Tor**

**Strong proof:** run step 3 on another machine that only knows the z32 keys (not your LAN IP).

## Troubleshooting

| Problem | Check |
|---------|--------|
| SOCKS preflight fails | `tor` running? `SocksPort 9050`? |
| No onion in DHT | `tor_onion` set? homeserver publish log? wait longer |
| Signup fails | homeserver up? `signup_mode` / token? hybrid `localhost` pkarr |
| Events empty | run publish script first; check path under `/pub/tor-proof/` |
| Indexer hits LAN | use `tor-proof-index` (sets `tor_only_transport`) not raw `request()` |

## Related

- [tor-endpoints.md](./tor-endpoints.md) — pkarr SVCB layout
- [config.sample.toml](../config.sample.toml) — `[pkdns]` Tor fields
