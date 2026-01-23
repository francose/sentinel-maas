# 🛡️ Sentinel MaaS

### AI-Native Monitoring-as-a-Service Agent

**Sentinel** is a local monitoring agent that gives AI assistants "Eyes" and "Hands" on your Mac. It collects deep system telemetry (thermals, network flows, security logs) and enables AI-driven remediation actions like killing runaway processes or blocking malicious IPs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Sentinel v1.1.0 - The AI's Eyes & Hands                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  👁️  EYES: CPU, Thermals, Network Flows, Security Logs, Firewall Status │
│  🤚 HANDS: Kill Processes, Block IPs, Enable Firewall, Fleet Reporting  │
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

### 🛠️ Remediation (The Hands)

| Feature | Command | Description |
|---------|---------|-------------|
| **Kill Process** | `--kill <PID>` | Terminate runaway processes |
| **Block IP** | `--block-ip <IP>` | Block malicious IPs via pf |
| **Unblock IP** | `--unblock-ip <IP>` | Remove IP from blocklist |
| **Fix Firewall** | `--fix-firewall` | Enable macOS Application Firewall |

### 📡 Fleet Mode (Remote Reporting)

| Feature | Command | Description |
|---------|---------|-------------|
| **Webhook** | `--webhook <URL>` | Send telemetry to endpoint (one-shot) |
| **Daemon** | `--daemon` | Continuous reporting to configured webhook |

---

## Installation

### Option A: Download Pre-built Binary (Recommended)

Download the latest release for your Mac:

| Platform | Binary | SHA-256 |
|----------|--------|---------|
| **Apple Silicon** (M1/M2/M3) | [sentinel-darwin-arm64](dist/sentinel-darwin-arm64) | `e0d2c65b36c36b49d633a1c857679d3a12076f73bf34f6786d3d7959a13dd58b` |
| **Intel Mac** | [sentinel-darwin-amd64](dist/sentinel-darwin-amd64) | `8d3ee0733d6ac938feb9a2dc331b1f53b510dfdc41ae7fe2b223c94592654a52` |

```bash
# For Apple Silicon (M1/M2/M3)
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.1.0/sentinel-darwin-arm64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel

# For Intel Mac
sudo curl -L https://github.com/yourusername/sentinel/releases/download/v1.1.0/sentinel-darwin-amd64 -o /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel
```

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

---

## All Commands

```
Usage of sentinel:
  -block-ip string      Block an IP address using pf firewall
  -config string        Path to config file (default "/etc/sentinel/config.yaml")
  -daemon               Run as daemon, sending telemetry to configured webhook
  -fix-firewall         Enable the macOS Application Firewall
  -init-config          Create default config file
  -json                 Output JSON telemetry to stdout and exit
  -kill int             Terminate a process by PID
  -list-blocked         List all blocked IP addresses
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

- **macOS** (Ventura+ recommended, Intel & Apple Silicon)
- **Root privileges** for thermal sensors, firewall, and process control
- **Go 1.21+** (for building from source)

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
