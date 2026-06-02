# Tor proof: homeserver over onion + SDK examples

This guide proves end-to-end reachability using the **real Tor network** and **live Mainline DHT**. All tooling lives in the **pubky-core** repository.

## Retrieval flow (`tor-proof-index`)

Two phases: **resolve** where the homeserver is (clearnet pkarr), then **fetch** with plain **HTTP** to `http://….onion/…` via local **SOCKS5** (`socks5h://127.0.0.1:9050`).

```mermaid
flowchart TB
  C["Client<br/>tor-proof-index / SDK"]

  P["pkarr / DHT<br/>clearnet — not Tor"]

  TOR["Tor daemon<br/>SOCKS5 127.0.0.1:9050"]
  HS["Homeserver<br/>HTTP :6286 via .onion :80"]

  C -->|① resolve| P
  P -->|".onion" + _pubky"| C

  C -->|"② HTTP request<br/>socks5h"| TOR
  TOR -->|"http://….onion/…"| HS
  HS -->|"HTTP response"| TOR
  TOR -->|"events + files"| C

  style TOR fill:#ffe8a3,stroke:#b8860b,color:#000
```

- **Publish** (`tor-proof-publish`) uses only ① on LAN (hybrid pkarr), not Tor.
- **Onion in pkarr** is published by the homeserver; see [tor-endpoints.md](./tor-endpoints.md).

## Tor is not bundled with the homeserver

You must install and run **Tor separately**. The homeserver only reads your `.onion` hostname and publishes it in pkarr.

### Install Tor

| Platform | Command |
|----------|---------|
| macOS | `brew install tor` then `brew services start tor` |
| Debian/Ubuntu | `sudo apt install tor` then `sudo systemctl enable --now tor` |
| Umbrel | Use the Tor service included in the Umbrel stack |

### Configure hidden service

Tor’s default **SOCKS port is already 9050** — you do not need to set `SocksPort` in `torrc`.

Pick a `HiddenServiceDir` path Tor can write to, create it with permission mode **700**, then add only these lines to `torrc`:

| Platform | Typical `torrc` path | Example `HiddenServiceDir` |
|----------|----------------------|----------------------------|
| macOS (Homebrew) | `/opt/homebrew/etc/tor/torrc` | `/opt/homebrew/var/lib/tor/pubky-homeserver/` |
| Linux | `/etc/tor/torrc` | `/var/lib/tor/pubky-homeserver/` |

```text
HiddenServiceDir /opt/homebrew/var/lib/tor/pubky-homeserver/
HiddenServicePort 80 127.0.0.1:6286
```

(Use the Linux paths on Debian/Ubuntu if you prefer.)

**Create the directory and set permissions** (adjust the path to match your `torrc`):

```bash
# macOS (Homebrew) example
sudo mkdir -p /opt/homebrew/var/lib/tor/pubky-homeserver
sudo chown "$(whoami)" /opt/homebrew/var/lib/tor/pubky-homeserver
chmod 700 /opt/homebrew/var/lib/tor/pubky-homeserver

# Linux example
sudo mkdir -p /var/lib/tor/pubky-homeserver
sudo chown debian-tor:debian-tor /var/lib/tor/pubky-homeserver   # user may be _tor on some distros
sudo chmod 700 /var/lib/tor/pubky-homeserver
```

**Restart Tor** after editing `torrc`:

```bash
# macOS
brew services restart tor

# Linux
sudo systemctl restart tor
```

Read the generated onion hostname (path must match `HiddenServiceDir`):

```bash
# macOS (Homebrew)
cat /opt/homebrew/var/lib/tor/pubky-homeserver/hostname

# Linux
cat /var/lib/tor/pubky-homeserver/hostname
```

Point `tor_onion_file` in homeserver config at that `hostname` file.

### Verify Tor before the proof

SOCKS is on the default port **9050**:

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
tor_onion_file = "/opt/homebrew/var/lib/tor/pubky-homeserver/hostname"  # macOS Homebrew; see paths above
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
4. Polls `GET /events/` (lines like `PUT pubky://…`) and fetches file bodies **only via Tor** (`https://_pubky.<user>/…`; SDK follows `_pubky` to the homeserver’s onion and sets `pubky-host` to the user)

**Strong proof:** run step 3 on another machine that only knows the z32 keys (not your LAN IP).

## Troubleshooting

| Problem | Check |
|---------|--------|
| SOCKS preflight fails | `tor` running? default SOCKS on `127.0.0.1:9050`? |
| Tor fails to start after HS config | `HiddenServiceDir` exists and is mode **700**? `brew services restart tor` (macOS) |
| No onion in DHT | `tor_onion` set? homeserver publish log? wait longer |
| Signup fails | homeserver up? `signup_mode` / token? hybrid `localhost` pkarr |
| Events empty | run publish script first; check path under `/pub/tor-proof/` |
| Indexer hits LAN | use `tor-proof-index` (sets `tor_only_transport`) not raw `request()` |

## Related

- [tor-endpoints.md](./tor-endpoints.md) — pkarr SVCB layout
- [config.sample.toml](../config.sample.toml) — `[pkdns]` Tor fields
