# qFibre Firewall (QFF)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/qfiber/qff)
[![Go Version](https://img.shields.io/badge/go-1.24%2B-blue)](https://golang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**A modern, modular, and stateful firewall and Intrusion Prevention System (IPS) for Linux, built with Go and powered by `nftables`.**

QFF provides robust, configurable network security for Linux servers.  
It runs as a background service (`qff-engine`) that manages the kernel’s `nftables` subsystem.  
Management is done securely through a local **Unix domain socket**, controlled by a powerful CLI (`qff`).

---

## Key Features

- 🛡️ **Stateful Firewalling**: Efficient packet inspection via `nftables`, with a default-deny policy.
- 🕵️ **Intrusion Prevention (IPS)**: Monitors logs, processes, and the filesystem; blocks suspicious activity.
- 🌍 **GeoIP & VPN Filtering**: Detects/block traffic from VPNs, proxies, Tor, or specific countries.
- 🐳 **Docker Integration**: Auto-detects Docker networks and configures rules.
- ⚡ **Rate Limiting**: Protects against brute-force and flood attacks (SSH, SYN, ICMP, etc.).
- 🔗 **Connection Limits**: Prevents abuse by capping concurrent sessions per IP.
- ✅ **Protocol Sanity Checks**: Drops malformed/invalid packets at kernel level.
- 🔬 **Safe Test Mode**: Apply configs with auto-rollback to avoid lockouts.
- 📊 **Prometheus Metrics**: Full observability with Prometheus integration.
- 📨 **Notifications**: Alerts via Email and Webhooks (Slack, Discord, etc.).

---

## Architecture

QFF uses a **decoupled client–server model**.  
The engine (`qff-engine`) runs as root and exposes a local Unix socket, while the CLI (`qff`) communicates with it.

```plaintext
┌───────────┐
│   User    │ (root or sudo)
└─────┬─────┘
      │
┌─────▼─────┐
│  qff  │
└─────┬─────┘
      │ (API over Unix Socket)
┌─────▼────────────────────────┐
│ ╔══════════════════════════╗ │
│ ║  /var/run/qff.sock       ║ │ (Filesystem Permissions)
│ ╚══════════════════════════╝ │
│  qff-engine Service (root)   │
└─────┬────────────────────────┘
      │
┌─────┴──────────────────────────────────────┬──────────────────────────┐
│ ┌─────────────────┐  ┌───────────────────┐ │ ┌──────────────────────┐ │
│ │ Firewall Manager│  │  IPS & Monitors   │ │ │ API & Config Manager │ │
│ └───────┬─────────┘  └─────────┬─────────┘ │ └──────────────────────┘ │
└─────────│──────────────────────│───────────┴──────────────────────────┘
          │ (go-nftables)        │ (gopsutil, log parsing)
┌─────────▼──────────────────────▼──────────┐
│     Linux Kernel (nftables, procfs)       │
└───────────────────────────────────────────┘
```

---

## Installation

### Prerequisites
- Go **1.24+**
- Linux with `nftables`
- Git

### Build & Install
```bash
git clone https://github.com/google/nftables.git
git clone https://github.com/qfiber/qff.git
cd qff
make build
sudo make install
```

This installs binaries, configs, and the systemd service.  

### Start the Service
Edit `/etc/qff/qff.conf` and ensure `api_socket_path` matches `socket_path` in `cli.conf`.  
Then:

```bash
sudo systemctl enable qff.service
sudo systemctl start qff.service
```

---

## Usage (qff)

All commands require **sudo/root** to access the Unix socket.

### Quick Flags
| Flag  | Argument | Description |
|-------|----------|-------------|
| `-a`  | `<ip>` | Add IP to whitelist. |
| `-d`  | `<ip>` | Add IP to blacklist. |
| `-ta` | `"<ip> <dur> [note]"` | Temp allow IP (e.g., `1h`, `30m`). |
| `-td` | `"<ip> <dur> [note]"` | Temp block IP. |
| `-tr` | `<ip>` | Remove a temp rule. |

**Examples:**
```bash
sudo qff -a 1.2.3.4
sudo qff -td "8.8.8.8 6h Investigating traffic spike"
```

### Commands
| Command | Args | Description |
|---------|------|-------------|
| `status` | | Show firewall status. |
| `metrics` | | Display metrics. |
| `logs [n]` | | Show logs. |
| `reload` | | Reload config. |
| `enable` / `disable` | | Control systemd service. |
| `whitelist list` | | List whitelisted IPs. |
| `blacklist list` | | List blacklisted IPs. |
| `ips status` | | IPS engine status. |
| `ips blocked` | | Show blocked IPs. |
| `ips unblock <ip>` | | Remove IP from blocklist. |
| `ips geoip-check <ip>` | | GeoIP lookup. |
| `ips vpn-check <ip>` | | VPN/proxy check. |
| `ports list` | | List port rules. |
| `ports add ...` | | Add rule. |
| `ports remove ...` | | Remove rule. |

---

## API Documentation

API is exposed at `/var/run/qff.sock`.  
Example with `curl`:

```bash
sudo curl --unix-socket /var/run/qff.sock http://unix/status
```

### General
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Service status & uptime. |
| GET | `/metrics` | JSON metrics. |
| GET | `/prometheus` | Prometheus metrics. |
| POST | `/reload` | Reload config. |

### Firewall
| Method | Endpoint | Params | Description |
|--------|----------|--------|-------------|
| POST | `/whitelist` | `ip=<ip>` | Add to whitelist. |
| DELETE | `/whitelist` | `ip=<ip>` | Remove from whitelist. |
| POST | `/blacklist` | `ip=<ip>` | Add to blacklist. |
| DELETE | `/blacklist` | `ip=<ip>` | Remove from blacklist. |

### IPS
| Method | Endpoint | Params | Description |
|--------|----------|--------|-------------|
| GET | `/api/ips/stats` | | IPS stats. |
| GET | `/api/ips/blocked` | | Blocked IPs. |
| GET | `/api/ips/whitelist` | | Temp whitelist. |
| POST | `/api/ips/unblock` | `ip=<ip>` | Unblock IP. |
| POST | `/api/ips/tempblock` | `ip=<ip>&duration=<dur>&reason=<note>` | Temp block IP. |
| DELETE | `/api/ips/tempremove` | `ip=<ip>` | Remove temp rule. |

### GeoIP
| Method | Endpoint | Params | Description |
|--------|----------|--------|-------------|
| GET | `/api/geoip/check` | `ip=<ip>` | GeoIP lookup. |
| GET | `/api/geoip/vpn-check` | `ip=<ip>` | VPN/proxy check. |

### Ports
| Method | Endpoint | Params | Description |
|--------|----------|--------|-------------|
| GET | `/api/ports/list` | | List rules. |
| POST | `/api/ports/add` | `port=<p>&protocol=<tcp|udp>&direction=<in|out>&action=<allow|deny>` | Add rule. |
| DELETE | `/api/ports/remove` | `port=<p>&protocol=<tcp|udp>&direction=<in|out>` | Remove rule. |

---

## Contributing
Contributions are welcome! Open issues and PRs are encouraged.

---

## License
This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](LICENSE) file for details.
