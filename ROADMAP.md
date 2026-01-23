# 🛡️ Sentinel Ecosystem: Project Roadmap

## Executive Summary

### The Problem
AI Assistants (Claude, Copilot, Gemini) are incredibly smart but "blind" and "paralyzed" regarding the local machine they run on. They can write code *about* system administration, but they cannot **see** your current CPU temperature, **detect** a network intrusion, or **act** to fix a disabled firewall.

### The Solution
**Sentinel** is a local **Monitoring-as-a-Service (MaaS)** agent that gives AI "Eyes" and "Hands."

* **The Eyes:** A high-performance Go collector (`sentinel`) that gathers deep kernel telemetry (thermals, "Zeek-style" network flows, security logs).
* **The Hands:** An MCP Bridge (`sentinel-mcp`) that allows the AI to securely execute remediation commands via standard prompts.

---

## Current Status: v1.1.0

### ✅ Completed Features

| Phase | Feature | Status | Version |
|-------|---------|--------|---------|
| **Core** | TUI Dashboard | ✅ Complete | v1.0.0 |
| **Core** | JSON Telemetry (`--json`) | ✅ Complete | v1.0.0 |
| **Core** | Firewall Monitoring | ✅ Complete | v1.0.0 |
| **Core** | Network Flow Tracking | ✅ Complete | v1.0.0 |
| **Core** | Security Log Streaming | ✅ Complete | v1.0.0 |
| **Phase 1A** | Process Killer (`--kill`) | ✅ Complete | v1.1.0 |
| **Phase 1A** | Firewall Fix (`--fix-firewall`) | ✅ Complete | v1.1.0 |
| **Phase 1B** | IP Blocking (`--block-ip`) | ✅ Complete | v1.1.0 |
| **Phase 1B** | IP Unblocking (`--unblock-ip`) | ✅ Complete | v1.1.0 |
| **Phase 1B** | List Blocked IPs (`--list-blocked`) | ✅ Complete | v1.1.0 |
| **Phase 2** | Config File Support | ✅ Complete | v1.1.0 |
| **Phase 2** | Configurable Thresholds | ✅ Complete | v1.1.0 |
| **Phase 2** | Homebrew Formula | ✅ Complete | v1.1.0 |
| **Phase 3** | Webhook Reporting (`--webhook`) | ✅ Complete | v1.1.0 |
| **Phase 3** | Daemon Mode (`--daemon`) | ✅ Complete | v1.1.0 |
| **Tech Debt** | Structured JSON Errors | ✅ Complete | v1.1.0 |

---

## Development Phases

### Phase 1: Expanded Remediation ✅ COMPLETE

*Goal: Transform Sentinel from a "Monitor" into an active "Administrator"*

#### Feature A: Process Killer ✅
```bash
sudo sentinel --kill 12345
```
- Terminates processes by PID using SIGKILL
- Returns structured JSON with process name
- Protected processes (PID 1) cannot be killed
- Clear error messages with fix suggestions

#### Feature B: Network Blocking ✅
```bash
sudo sentinel --block-ip 192.168.1.100
sudo sentinel --unblock-ip 192.168.1.100
sentinel --list-blocked
```
- Uses macOS `pf` firewall via anchor rules
- Blocks both inbound and outbound traffic
- Validates IP addresses before adding
- Persists blocklist in `/etc/pf.anchors/com.sentinel`

---

### Phase 2: Hardening & Distribution ✅ COMPLETE

*Goal: Make the tool easier to install and safer to use*

#### Config File Support ✅
```bash
sudo sentinel --init-config
```
- Creates `/etc/sentinel/config.yaml`
- Configurable thermal/CPU/memory thresholds
- Webhook URL and interval settings
- Agent ID customization

#### Homebrew Formula ✅
- Formula at `homebrew/sentinel.rb`
- LaunchDaemon support for background operation
- Proper config file installation

#### Signed Binaries 🔜 Planned
- Code signing for Gatekeeper compliance
- Notarization for macOS distribution

---

### Phase 3: Fleet Mode ✅ COMPLETE

*Goal: Monitor multiple machines from one AI session*

#### Webhook Reporting ✅
```bash
# One-shot
sudo sentinel --webhook https://api.example.com/telemetry

# Continuous daemon
sudo sentinel --daemon
```
- Sends full telemetry JSON to HTTP endpoint
- Configurable interval (default 60s)
- Includes hostname and version in payload

#### Central Dashboard 🔜 Planned
- Web UI to view fleet health
- Aggregated alerts across machines
- Historical telemetry storage

---

## Future Phases

### Phase 4: Advanced Network Tools (NetTools)

*Goal: Deep network diagnostics and traffic analysis capabilities*

| Feature | Command | Description | Priority |
|---------|---------|-------------|----------|
| **Port Scanner** | `--scan-ports <target>` | Scan open ports on local/remote hosts | High |
| **DNS Lookup** | `--dns <domain>` | Resolve DNS with full record details (A, AAAA, MX, TXT) | High |
| **Traceroute** | `--traceroute <host>` | Network path analysis with latency | Medium |
| **Bandwidth Monitor** | `--bandwidth` | Real-time network throughput per interface | High |
| **Connection Details** | `--conn-details <pid>` | Deep dive into process network activity | Medium |
| **Packet Capture** | `--pcap <interface>` | Lightweight tcpdump-style capture | Low |
| **Latency Monitor** | `--ping <hosts>` | Continuous ping with statistics | Medium |
| **ARP Table** | `--arp` | Show ARP cache with vendor lookup | Medium |
| **Listening Ports** | `--listeners` | All listening services with process info | High |
| **Netstat Enhanced** | `--netstat` | Enhanced connection table with geolocation | High |

#### Use Cases
- *"What ports are open on this machine?"* → `--listeners`
- *"Is there unusual outbound traffic?"* → `--bandwidth`
- *"Where is this IP located?"* → `--netstat` (with geo)
- *"Trace the route to api.example.com"* → `--traceroute api.example.com`

---

### Phase 5: Asset Metadata & Inventory

*Goal: Complete system inventory for asset management and compliance*

| Feature | Command | Description | Priority |
|---------|---------|-------------|----------|
| **System Info** | `--asset-info` | Full hardware/software inventory | High |
| **Hardware Details** | `--hardware` | CPU, RAM, disk, serial numbers | High |
| **Installed Apps** | `--apps` | List all installed applications with versions | High |
| **Running Services** | `--services` | LaunchDaemons/Agents status | Medium |
| **User Accounts** | `--users` | Local user enumeration | Medium |
| **Disk Usage** | `--disk` | Storage breakdown by volume | High |
| **Network Interfaces** | `--interfaces` | NICs with MAC, IP, status | High |
| **Security Posture** | `--security-audit` | SIP, Gatekeeper, FileVault status | High |
| **Certificates** | `--certs` | Installed certificates and expiry | Medium |
| **Startup Items** | `--startup` | Login items and launch agents | Medium |

#### Asset Metadata JSON Schema
```json
{
  "asset_id": "SENTINEL-MacBook-Pro-2023",
  "hostname": "jynx-macbook",
  "serial_number": "C02XG0...",
  "hardware": {
    "model": "MacBook Pro (14-inch, 2023)",
    "chip": "Apple M2 Pro",
    "cores": 12,
    "memory_gb": 32,
    "storage_gb": 1000
  },
  "os": {
    "name": "macOS",
    "version": "14.2.1",
    "build": "23C71"
  },
  "network": {
    "interfaces": [...],
    "public_ip": "203.0.113.42",
    "local_ip": "192.168.1.100"
  },
  "security": {
    "sip_enabled": true,
    "gatekeeper": "enabled",
    "filevault": "enabled",
    "firewall": "enabled"
  },
  "software": {
    "installed_apps": 142,
    "homebrew_packages": 67
  },
  "last_updated": "2026-01-22T10:30:00Z"
}
```

#### Use Cases
- *"What's the serial number of this Mac?"* → `--hardware`
- *"Is FileVault enabled?"* → `--security-audit`
- *"What apps are installed?"* → `--apps`
- *"Generate a full asset report"* → `--asset-info`

---

### Phase 6: Enhanced Security Monitoring

| Feature | Description | Priority |
|---------|-------------|----------|
| USB Device Tracking | Alert on new USB connections | Medium |
| Process Anomaly Detection | ML-based unusual process detection | Low |
| File Integrity Monitoring | Watch critical system files | Medium |
| Login Attempt Tracking | Failed SSH/auth monitoring | High |
| Privileged Command Audit | Track sudo usage | High |
| Network Anomaly Detection | Unusual traffic patterns | Medium |

---

### Phase 7: Cross-Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| macOS Intel | ✅ Supported | Primary platform |
| macOS Apple Silicon | ✅ Supported | Primary platform |
| Linux | 🔜 Planned | Different thermal/firewall APIs |
| Windows | ❓ Considering | Major refactor needed |

### Phase 8: MCP Bridge Enhancements

| Tool | Description | Status |
|------|-------------|--------|
| `get_system_health` | Current telemetry | ✅ Available |
| `terminate_process` | Kill by PID | ✅ Available |
| `block_ip_address` | Firewall block | ✅ Available |
| `enable_firewall` | Fix disabled FW | ✅ Available |
| `get_top_processes` | CPU/memory hogs | 🔜 Planned |
| `restart_service` | Service management | 🔜 Planned |
| `check_updates` | OS update status | 🔜 Planned |
| `scan_ports` | Port scanning | 🔜 Phase 4 |
| `get_asset_info` | Full asset metadata | 🔜 Phase 5 |
| `get_network_stats` | Bandwidth/connections | 🔜 Phase 4 |
| `security_audit` | Security posture check | 🔜 Phase 5 |

---

## Technical Debt & Maintenance

### Resolved ✅

- [x] Structured error JSON with error codes and fix suggestions
- [x] Config file for thresholds (removes hardcoded 88°C limit)
- [x] Proper exit codes for scripting

### Outstanding

- [ ] **Log Parsing:** Enhance `log stream` with Apple's NSPredicate for better filtering
- [ ] **Dependency Management:** Monitor `modelcontextprotocol/go-sdk` for official SDK migration
- [ ] **Test Coverage:** Add unit tests for remediation functions
- [ ] **Rate Limiting:** Prevent rapid-fire kill/block commands

---

## Contributing

### Quick Start for Contributors

1. **Clone the repo:**
   ```bash
   git clone https://github.com/yourusername/sentinel.git
   cd sentinel
   ```

2. **Build:**
   ```bash
   go mod tidy
   go build -o sentinel
   ```

3. **Test your changes:**
   ```bash
   ./sentinel --version
   ./sentinel --json
   ./sentinel --list-blocked
   ```

### Priority Items for Contributors

1. **Linux Port** - Adapt thermal monitoring for `/sys/class/thermal`
2. **Test Suite** - Add tests for process/IP validation
3. **Dashboard UI** - React/Vue web dashboard for fleet mode

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v1.1.0 | 2026-01-22 | Process killer, IP blocking, config file, webhook/daemon mode |
| v1.0.0 | 2026-01-15 | Initial release with TUI, JSON output, firewall monitoring |

---

## Contact

- **Issues:** [GitHub Issues](https://github.com/yourusername/sentinel/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/sentinel/discussions)

