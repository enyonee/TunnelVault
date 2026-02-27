<div align="center">

<img src="logo.png" alt="TunnelVault" width="600">

**Multi-tunnel VPN orchestrator for macOS, Linux & Windows**

<a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
<a href="#-cross-platform"><img src="https://img.shields.io/badge/macOS_|_Linux_|_Windows-lightgrey?style=for-the-badge&logo=apple&logoColor=white" alt="Platform"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"></a>
<a href="pyproject.toml"><img src="https://img.shields.io/badge/v1.2-00B4AB?style=for-the-badge&logo=semantic-release&logoColor=white" alt="Version"></a>
<img src="https://img.shields.io/badge/tests-804_passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Tests">

<kbd>OpenVPN</kbd> &nbsp; <kbd>FortiVPN</kbd> &nbsp; <kbd>sing-box</kbd> &nbsp; <kbd>+ your plugin</kbd>

<a href="#-quick-start">Quick Start</a> · <a href="#-how-it-works">How It Works</a> · <a href="#-configuration">Configuration</a> · <a href="#-cli">CLI</a> · <a href="#-plugin-system">Plugins</a>

</div>

---

## <img src="https://img.shields.io/badge/🚀_Quick_Start-2FBFBF?style=for-the-badge" alt="Quick Start">

```bash
git clone https://github.com/enyonee/tunnelvault.git
cd tunnelvault
cp defaults.toml.example defaults.toml   # edit with your infrastructure
./setup.sh                                # creates venv, installs deps
sudo ./tvpn                               # interactive wizard on first run
```

> [!TIP]
> On first launch, the wizard collects missing parameters and saves them. Subsequent runs are automatic.

Parameters are resolved through: `defaults.toml` ──▸ `ENV` ──▸ `.vpn-settings.json` ──▸ `wizard`

## <img src="https://img.shields.io/badge/⚙_How_It_Works-2FBFBF?style=for-the-badge" alt="How It Works">

### Startup sequence

**1. Cleanup** — `pkill` stale VPN processes from previous runs, flush orphaned routes.

**2. IPv6** — Disable on all interfaces to prevent leaks.
- macOS: `networksetup -setv6off` per service
- Linux: `sysctl net.ipv6.conf.all.disable_ipv6=1`

**3. Server routes** — Pin VPN server IPs to current default gateway so VPN traffic itself doesn't get rerouted after tunnels come up.
- Hostnames from `[global.vpn_server_routes].resolve` resolved via system DNS
- Static IPs from `[global.vpn_server_routes].hosts` added directly
- macOS: `route add -host <ip> <gw>`
- Linux: `ip route add <ip> via <gw>`

**4. Bypass routes** — Same mechanism for IPs/domains from `[global.bypass_routes]` that must always skip VPN. Domain suffix bypass starts a DNS proxy (see below).

**5. Connect** — For each tunnel in `order`:
- Spawn daemon (`openvpn` / `openfortivpn` / `sing-box`) with config
- Wait for interface (`tun0`, `ppp0`, `utun99`) to appear
- Add routes from `[tunnels.<name>.routes]`:
  - macOS: `route add -net <cidr> -interface <iface>` / `route add -host <ip> <gw>`
  - Linux: `ip route add <cidr> dev <iface>` / `ip route add <ip> via <gw>`
- Create DNS resolver entries from `[tunnels.<name>.dns]`:
  - macOS: write `/etc/resolver/<domain>` with `nameserver <ip>`
  - Linux: `resolvectl dns <iface> <ip>`, `resolvectl domain <iface> <domain>`

**6. Health checks** — Per tunnel, run checks defined in `[tunnels.<name>.checks]`:
- `ports` — TCP connect to `host:port`
- `ping` — ICMP, with `fallback = "port:53"` if ICMP blocked
- `dns` — `dig @<server> <name>`, verify non-empty answer
- `http` — `curl` endpoint, check HTTP 200
- `external_ip_url` — fetch external IP, display in summary

**7. Summary** — Print pass/fail table and log paths.

### Routing

Two formats for defining per-tunnel routes:

**targets** (auto-parsed):
```toml
targets = ["*.example.local", "10.0.0.0/8", "192.168.1.1", "git.internal.com"]
```
| Pattern | Parsed as | System effect |
|---------|-----------|---------------|
| `*.example.local` | DNS domain | `/etc/resolver/example.local` → tunnel nameservers |
| `10.0.0.0/8` | Network CIDR | `route add -net 10.0.0.0/8 -interface ppp0` |
| `192.168.1.1` | Host IP | `route add -host 192.168.1.1 <tunnel_gw>` |
| `git.internal.com` | Hostname | Resolve → IP → host route |

**Explicit** (when you need full control):
```toml
[tunnels.fortivpn.routes]
networks = ["10.0.0.0/8"]
hosts = ["10.0.1.1"]

[tunnels.fortivpn.dns]
nameservers = ["10.0.1.1"]
domains = ["example.local"]
```

### DNS bypass proxy

For domain suffixes that must **not** go through VPN (configured in `[global.bypass_routes].domain_suffix`):

```
  App resolves *.ru
       │
       ▼
  /etc/resolver/ru  →  nameserver 127.0.0.1
       │
       ▼
  TunnelVault DNS proxy (127.0.0.1:53)
       │
       ├─ Matches suffix? ──▸ Forward to upstream_dns (e.g. 8.8.8.8)
       │                      Route 8.8.8.8 pinned to default GW
       │                      Add host route for resolved IP → default GW
       │
       └─ No match ──▸ Forward to system default DNS
```

All injected routes are cleaned up on disconnect.

### Disconnect

`--disconnect` — reverse order:
1. Kill VPN daemon by PID (fallback: `pkill -f <pattern>`)
2. Delete routes: `route delete -net <cidr>`, `route delete -host <ip>`
3. Remove `/etc/resolver/<domain>` files (macOS) or reset `resolvectl` (Linux)
4. Stop DNS proxy, delete injected routes
5. Restore IPv6

`--reset` — emergency mode: `pkill` all known process names (`openvpn`, `openfortivpn`, `sing-box`) without config context.

<kbd>Ctrl</kbd>+<kbd>C</kbd> / <kbd>SIGTERM</kbd> triggers graceful disconnect. Broken state falls back to emergency kill.

## <img src="https://img.shields.io/badge/📝_Configuration-FF8C00?style=for-the-badge" alt="Configuration">

Each tunnel is a `[tunnels.<name>]` section in `defaults.toml`:

<details>
<summary><strong>Full example</strong></summary>

```toml
[global.vpn_server_routes]
hosts = ["203.0.113.10"]
resolve = ["vpn.example.com"]

[global.bypass_routes]
domains = ["external-service.com"]
domain_suffix = [".ru"]
upstream_dns = "8.8.8.8"

# ─── OpenVPN ──────────────────────────────────────────────────
[tunnels.openvpn]
type = "openvpn"
order = 1
config_file = "client.ovpn"

[tunnels.openvpn.checks]
http = ["https://google.com"]
external_ip_url = "https://ifconfig.me"

# ─── FortiVPN ─────────────────────────────────────────────────
[tunnels.fortivpn]
type = "fortivpn"
order = 2

[tunnels.fortivpn.auth]
host = "vpn.example.com"
port = "44333"
cert_mode = "auto"

[tunnels.fortivpn.routes]
targets = ["*.example.local", "10.0.0.0/8", "192.168.100.0/24"]

[tunnels.fortivpn.dns]
nameservers = ["10.0.1.1", "10.0.1.2"]

[tunnels.fortivpn.checks]
ports = [{ host = "192.168.100.1", port = 8080 }]
ping = [{ host = "10.0.1.1", label = "DNS-1", fallback = "port:53" }]
dns = [{ name = "app.example.local", server = "10.0.1.1" }]

# ─── sing-box ─────────────────────────────────────────────────
[tunnels.singbox]
type = "singbox"
order = 3
config_file = "singbox.json"
interface = "utun99"

[tunnels.singbox.routes]
networks = ["172.18.0.0/16"]

[tunnels.singbox.checks]
ports = [{ host = "203.0.113.30", port = 443 }]
```

</details>

| File | Purpose |
|------|---------|
| `defaults.toml.example` | Template - copy and edit |
| `defaults.toml` | Your config (gitignored) |
| `.vpn-settings.json` | Wizard-saved credentials (gitignored) |

<details>
<summary><strong>Environment Variables</strong></summary>

```bash
export VPN_FORTI_HOST="vpn.company.com"
export VPN_FORTI_LOGIN="user"
export VPN_FORTI_PASS="secret"
export VPN_FORTI_PORT="44333"
export VPN_CERT_MODE="auto"
export VPN_TRUSTED_CERT="sha256hash..."
export VPN_OVPN_CONFIG="client.ovpn"
export VPN_SINGBOX_CONFIG="singbox.json"
```

</details>

## <img src="https://img.shields.io/badge/🖥_CLI-FF8C00?style=for-the-badge" alt="CLI">

<table>
<tr><td><strong>Connect</strong></td><td>

```bash
sudo ./tvpn                     # all tunnels (wizard on first run)
sudo ./tvpn --setup             # force wizard
sudo ./tvpn --clear             # kill stale sessions first
sudo ./tvpn --only fortivpn     # specific tunnel
```

</td></tr>
<tr><td><strong>Disconnect</strong></td><td>

```bash
sudo ./tvpn --disconnect                  # all tunnels
sudo ./tvpn --disconnect --only fortivpn  # specific tunnel
sudo ./tvpn --reset                       # emergency kill
```

</td></tr>
<tr><td><strong>Monitor</strong></td><td>

```bash
sudo ./tvpn --check             # health checks on running tunnels
sudo ./tvpn --status            # interfaces, routes, DNS, processes
sudo ./tvpn --watch             # live dashboard
```

</td></tr>
<tr><td><strong>Tools</strong></td><td>

```bash
sudo ./tvpn --validate          # validate config without connecting
sudo ./tvpn --logs              # list log paths
sudo ./tvpn --logs fortivpn     # tail specific log
```

</td></tr>
</table>

## <img src="https://img.shields.io/badge/🧩_Plugin_System-2FBFBF?style=for-the-badge" alt="Plugin System">

Each VPN type extends `TunnelPlugin` and registers via `@register`:

```python
from tv.vpn.base import TunnelPlugin, VPNResult, ConfigParam
from tv.vpn.registry import register

@register("myvpn")
class MyVPNPlugin(TunnelPlugin):
    type_display_name = "MyVPN"
    process_names = ["myvpn-daemon"]

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(key="host", label="param.host", required=True, env_var="VPN_MY_HOST"),
            ConfigParam(key="token", label="param.token", required=True, secret=True),
        ]

    @property
    def process_name(self) -> str:
        return "myvpn-daemon"

    def connect(self) -> VPNResult:
        ...
        return VPNResult(ok=True, pid=pid, detail="connected")
```

> [!TIP]
> Drop your plugin into `tv/vpn/`, import in `tunnelvault.py`, add `[tunnels.myname]` with `type = "myvpn"`.

| Plugin | Process | Interface | Highlights |
|--------|---------|-----------|------------|
| **OpenVPN** | `openvpn` | `tun0` | Tunnelblick detection, `.ovpn` config, external IP |
| **FortiVPN** | `openfortivpn` | `ppp0` | Auto cert trust, PPP gateway discovery, split routing |
| **sing-box** | `sing-box` | `utun99` | JSON config, custom interface |

<details>
<summary><strong>Cross-platform implementation</strong></summary>

| Function | macOS | Linux | Windows |
|----------|-------|-------|---------|
| Routing | `route add/delete` | `ip route add/del` | `route ADD/DELETE` |
| DNS | `/etc/resolver/*` | `resolvectl` | NRPT rules (PowerShell) |
| Interfaces | `ifconfig -a` | `ip -br addr` | `ipconfig` |
| IPv6 | `networksetup` | `sysctl` | `Disable-NetAdapterBinding` |
| Gateway | `route -n get default` | `ip route show default` | `route PRINT` |
| Processes | `pgrep`/`pkill` | `pgrep`/`pkill` | `wmic`/`taskkill` |
| Port check | `nc -z` | `nc -z` | `socket.connect` |

</details>

## <img src="https://img.shields.io/badge/🗺_Roadmap-2FBFBF?style=for-the-badge" alt="Roadmap">

- [ ] `--check` rerun - re-run health checks with retry/loop until all pass
- [ ] Plugin-defined checks - each VPN plugin declares default checks in code, no manual TOML needed
- [ ] Configurable check list - override/extend plugin checks via external file
- [x] Windows support - routing, DNS, process management for Windows
- [ ] Windows VPN plugins - adapt openvpn/sing-box plugins for Windows paths and adapters
- [ ] Windows daemon - Task Scheduler integration for keepalive mode

## <img src="https://img.shields.io/badge/📋_Requirements-FF8C00?style=for-the-badge" alt="Requirements">

**Python 3.10+** · **macOS, Linux, or Windows** · **sudo / Run as Administrator** · VPN tools you need (`openvpn`, `openfortivpn`, `sing-box`)

> [!WARNING]
> TunnelVault modifies routing tables and DNS configuration. Review your `defaults.toml` before running. Use `--validate` to dry-run.

---

<div align="center">
<sub>Built for teams that run multiple VPNs and hate doing it manually ⚡</sub>
</div>
