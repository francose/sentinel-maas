# 🛡️ Sentinel MaaS

### AI-Native Monitoring-as-a-Service Agent

**Sentinel** is a local monitoring agent that gives AI assistants "Eyes" and "Hands" on your Mac. It collects deep system telemetry (thermals, network flows, security logs) and enables AI-driven remediation actions like killing runaway processes or blocking malicious IPs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Sentinel v1.3.0 - The AI's Eyes & Hands                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  👁️  EYES: CPU, Thermals, Network Flows, Security Logs, Asset Inventory │
│  🤚 HANDS: Kill Processes, Block IPs, Port Scan, Security Audit         │
│  📡 FLEET: Forward telemetry to Sentinel Server                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Features

### 🔍 Monitoring (The Eyes)

| Feature | Description |
|---------|-------------|
| **CPU & Thermal** | Real-time load, die temperature with configurable thresholds |
| **Network Flows** | Zeek-style connection tracking (Process → IP mapping) |
| **Security Logs** | Live `com.apple.securityd` event stream |
| **Firewall Status** | Monitors pf and Application Firewall state |
| **Top Processes** | CPU/memory sorted process list |
| **Asset Inventory** | Full system hardware/software inventory |
| **Network Stats** | Interface bandwidth and connection counts |

### 🛠️ Remediation (The Hands)

| Feature | Command | Description |
|---------|---------|-------------|
| **Kill Process** | `--kill <PID>` | Terminate runaway processes |
| **Block IP** | `--block-ip <IP>` | Block malicious IPs via pf |
| **Unblock IP** | `--unblock-ip <IP>` | Remove IP from blocklist |
| **Fix Firewall** | `--fix-firewall` | Enable macOS Application Firewall |
| **Restart Service** | `--restart-service <label>` | Restart launchd services |
| **Port Scanner** | `--scan-ports <target>` | Scan for open ports |
| **Security Audit** | `--security-audit` | Security posture assessment |

### 📡 Fleet Mode (Remote Reporting)

| Feature | Command | Description |
|---------|---------|-------------|
| **Forward Mode** | `--forward --server <URL>` | Send telemetry to Sentinel Server |
| **Webhook** | `--webhook <URL>` | Send telemetry to endpoint (one-shot) |
| **Daemon** | `--daemon` | Continuous reporting to configured webhook |

#### Forward Mode (New in v1.3.0)

```bash
# Start forwarding to sentinel-server
sentinel --forward --server https://sentinel-server:8443

# With custom agent ID, tags, and interval
sentinel --forward --server https://sentinel-server:8443 \
  --agent-id prod-web-01 \
  --tags production,webserver,us-east \
  --interval 60
```

| Flag | Description | Default |
|------|-------------|---------|
| `--forward` | Enable forward mode | - |
| `--server` | Sentinel server URL | Required |
| `--agent-id` | Agent identifier | Auto-generated |
| `--tags` | Comma-separated tags | - |
| `--interval` | Forward interval (seconds) | 30 |

---

## Installation

### Option A: Download Pre-built Binary (Recommended)

Download the latest release for your platform:

#### macOS

| Platform | Binary | SHA-256 |
|----------|--------|---------|
| **Apple Silicon** (M1/M2/M3) | [sentinel-darwin-arm64](dist/sentinel-darwin-arm64) | `6ba90d3a8c7f0c32dd7009a17712127d70526ab1658c083902434c8cce1eab6b` |
| **Intel Mac** | [sentinel-darwin-amd64](dist/sentinel-darwin-amd64) | `dcd6013dff84793c8567260b3290aee4d8c4b8524116319528aa86e356feda6f` |

```bash
# For Apple Silicon (M1/M2/M3)
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.3.0/sentinel-darwin-arm64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel

# For Intel Mac
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.3.0/sentinel-darwin-amd64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel
```

#### Linux (Beta)

| Platform | Binary | SHA-256 |
|----------|--------|---------|
| **Linux x86_64** | [sentinel-linux-amd64](dist/sentinel-linux-amd64) | `cc1d30ab7b82135206078b2a6ba8344fb72e1eaa12464c27e5eb1899c86a256d` |
| **Linux ARM64** | [sentinel-linux-arm64](dist/sentinel-linux-arm64) | `c306028c43470b95aa3debcca61c4caf17389759c4741cb442e1275afb3bd060` |

```bash
# For Linux x86_64
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.3.0/sentinel-linux-amd64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel

# For Linux ARM64 (Raspberry Pi, AWS Graviton, etc.)
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.3.0/sentinel-linux-arm64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel
```

> **Note:** Linux support is in beta. Core monitoring (CPU, memory, processes, network stats) works. Thermal monitoring requires `lm-sensors`. Firewall uses iptables/ufw. Service management uses systemd.

### Option B: Quick Install Script

```bash
curl -sfL https://raw.githubusercontent.com/yourusername/sentinel/main/install.sh | sudo sh
```

### Option C: Build from Source

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
go mod tidy
go build -ldflags "-s -w" -o sentinel
sudo mv sentinel /usr/local/bin/
```

### Option D: Homebrew (Coming Soon)

```bash
brew tap yourusername/sentinel
brew install sentinel
```

---

## Usage

### TUI Dashboard

```bash
sudo sentinel
```

Interactive terminal dashboard showing real-time system health. Press `q` to quit.

### JSON Telemetry (for MCP/AI Integration)

```bash
sudo sentinel --json
```

Outputs structured JSON for AI consumption:
```json
{
  "agent_id": "SENTINEL-MacBook",
  "timestamp": "2026-01-22T10:30:00Z",
  "threat_level": "LOW",
  "cpu_load": "1.25",
  "temperature": "52",
  "firewall_status": "ACTIVE",
  "flows": [...]
}
```

### Remediation Commands

```bash
# Kill a runaway process
sudo sentinel --kill 12345

# Block a suspicious IP
sudo sentinel --block-ip 192.168.1.100

# Unblock an IP
sudo sentinel --unblock-ip 192.168.1.100

# List all blocked IPs
sentinel --list-blocked

# Enable firewall
sudo sentinel --fix-firewall

# Restart a service
sudo sentinel --restart-service com.apple.example

# Scan ports on a target
sentinel --scan-ports localhost --port-range 80,443,22

# Run security audit
sentinel --security-audit
```

### System Information Commands

```bash
# Top processes by CPU/memory
sentinel --top --top-count 10

# Full asset inventory
sentinel --asset-info

# Network interface stats
sentinel --network-stats

# Check for macOS updates
sentinel --check-updates

# List launchd services
sentinel --services
```

### Fleet/Webhook Mode

```bash
# One-shot telemetry push
sudo sentinel --webhook https://your-server.com/api/telemetry

# Daemon mode (uses config file)
sudo sentinel --daemon
```

---

## Configuration

Initialize the config file:

```bash
sudo sentinel --init-config
```

This creates `/etc/sentinel/config.yaml`:

```yaml
agent_id: "SENTINEL-MacBook"

thresholds:
  thermal_warning: 75.0    # Celsius
  thermal_critical: 88.0   # Celsius
  cpu_warning: 80.0        # Percent
  cpu_critical: 95.0       # Percent
  memory_warning: 80.0     # Percent
  memory_critical: 95.0    # Percent

webhook:
  url: "https://your-server.com/api/telemetry"
  interval_seconds: 60
  enabled: true

blocked_ips: []
```

---

## MCP Integration

Sentinel is designed to work with the **Model Context Protocol (MCP)**. The `sentinel-mcp` bridge exposes these tools to AI:

| MCP Tool | Sentinel Command | Use Case |
|----------|------------------|----------|
| `get_system_health` | `--json` | "What's the system status?" |
| `terminate_process` | `--kill` | "Kill the runaway ffmpeg process" |
| `block_ip_address` | `--block-ip` | "Block this suspicious IP" |
| `enable_firewall` | `--fix-firewall` | "The firewall is disabled, fix it" |
| `get_top_processes` | `--top` | "What's using all my CPU?" |
| `restart_service` | `--restart-service` | "Restart the web server" |
| `scan_ports` | `--scan-ports` | "Check what ports are open" |
| `get_asset_info` | `--asset-info` | "What hardware is this machine?" |
| `get_network_stats` | `--network-stats` | "Show network bandwidth" |
| `security_audit` | `--security-audit` | "Is this system secure?" |
| `check_updates` | `--check-updates` | "Are there OS updates?" |

See [MCP_SPECIFICATION.md](MCP_SPECIFICATION.md) for complete MCP tool definitions.

---

## All Commands

```
Usage of sentinel:
  -asset-info           Show full system asset information
  -block-ip string      Block an IP address using pf firewall
  -check-updates        Check for available macOS updates
  -config string        Path to config file (default "/etc/sentinel/config.yaml")
  -daemon               Run as daemon, sending telemetry to configured webhook
  -fix-firewall         Enable the macOS Application Firewall
  -init-config          Create default config file
  -json                 Output JSON telemetry to stdout and exit
  -kill int             Terminate a process by PID
  -list-blocked         List all blocked IP addresses
  -network-stats        Show network interface statistics
  -port-range string    Port range to scan (default "1-1024")
  -restart-service      Restart a launchd service by label
  -scan-ports string    Scan ports on target (e.g., localhost, 192.168.1.1)
  -security-audit       Run security posture audit
  -services             List running services (LaunchDaemons/Agents)
  -top                  Show top processes by CPU/memory usage
  -top-count int        Number of processes to show (default 10)
  -unblock-ip string    Unblock a previously blocked IP address
  -version              Print version and exit
  -webhook string       Send telemetry to webhook URL (one-shot)
```

---

## Structured JSON Output

All commands return structured JSON with error codes for programmatic handling:

```json
// Success
{"success":true,"action":"block_ip","ip":"192.168.1.100"}

// Error with fix suggestion
{
  "success": false,
  "action": "kill",
  "pid": 1234,
  "error": "Permission denied",
  "error_code": "PERMISSION_DENIED",
  "fix": "Run with sudo: sudo sentinel --kill 1234"
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `PERMISSION_DENIED` | Needs sudo |
| `PROCESS_NOT_FOUND` | PID doesn't exist |
| `INVALID_IP` | Malformed IP address |
| `ALREADY_BLOCKED` | IP already in blocklist |
| `NOT_BLOCKED` | IP not in blocklist |
| `CONFIG_MISSING` | Required config not set |

---

## Requirements

### macOS
- **macOS** (Ventura+ recommended, Intel & Apple Silicon)
- **Root privileges** for thermal sensors, firewall, and process control
- **Go 1.21+** (for building from source)

### Linux (Beta)
- **Linux** (Ubuntu 20.04+, Debian 11+, RHEL 8+, or similar)
- **Root privileges** for firewall (iptables/ufw) and service management
- **lm-sensors** (optional, for temperature monitoring)
- **systemd** for service management
- **Go 1.21+** (for building from source)

---

## Platform Support Matrix

| Feature | macOS | Linux |
|---------|-------|-------|
| CPU/Memory Monitoring | ✅ | ✅ |
| Temperature Monitoring | ✅ powermetrics | ⚠️ lm-sensors |
| Process Management | ✅ | ✅ |
| Network Stats | ✅ | ✅ |
| Port Scanning | ✅ | ✅ |
| Firewall Control | ✅ pf | ✅ iptables/ufw |
| Service Management | ✅ launchd | ✅ systemd |
| Security Audit | ✅ Full | ⚠️ Partial |
| TUI Dashboard | ✅ | ✅ |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Temp: ??` | Run with `sudo` for thermal sensor access |
| `ERR: RUN AS SUDO` | Sentinel needs root for `powermetrics` |
| Permission denied on kill | Use `sudo sentinel --kill <PID>` |
| Webhook fails | Check network connectivity and URL |

---

## License

[MIT License](LICENSE)

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and development status.
