# Sentinel Platform Wiki

> **AI-Native Security Monitoring Platform**
> 
> A complete security monitoring stack with MCP (Model Context Protocol) integration for AI-assisted operations.

---

## Table of Contents

1. [Platform Overview](#platform-overview)
2. [Architecture](#architecture)
3. [Repositories](#repositories)
4. [Sentinel Agent](#sentinel-agent)
5. [Sentinel Server](#sentinel-server)
6. [Sentinel Console](#sentinel-console)
7. [Sentinel Proto](#sentinel-proto)
8. [MCP Specifications](#mcp-specifications)
9. [Development Progress](#development-progress)

---

## Platform Overview

Sentinel is a self-contained security monitoring platform designed for:

- **Endpoint Monitoring**: Real-time metrics, process tracking, network connections
- **Fleet Management**: Centralized visibility across all endpoints
- **Threat Detection**: IOC matching, alert rules, anomaly detection
- **AI Integration**: Full MCP support for AI-assisted security operations
- **Incident Response**: Remote actions (block, isolate, kill, restart)

### Design Principles

1. **Zero External Dependencies**: No Splunk, no Elastic, no third-party SIEM required
2. **AI-Native**: Built from ground up with MCP for AI assistant integration
3. **Lightweight**: Minimal resource footprint on endpoints
4. **Cross-Platform**: macOS and Linux support (Windows planned)
5. **Open Source**: MIT licensed

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL PLATFORM                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │
│  │ SENTINEL AGENT  │    │ SENTINEL SERVER │    │   SENTINEL CONSOLE      │   │
│  │    (endpoint)   │───▶│  (aggregator)   │◀───│      (web UI)           │   │
│  ├─────────────────┤    ├─────────────────┤    └─────────────────────────┘   │
│  │   MCP Server    │    │   MCP Server    │                                  │
│  │  (local ops)    │    │  (fleet ops)    │◀─── AI Assistants (Claude, etc) │
│  └─────────────────┘    └─────────────────┘                                  │
│           │                     │                                            │
│           │                     ▼                                            │
│           │            ┌─────────────────┐                                   │
│           │            │ SENTINEL STORE  │                                   │
│           └───────────▶│  (time-series)  │                                   │
│              forward   └─────────────────┘                                   │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Agent (interval)                     Server                         Store
     │                                  │                             │
     │──── POST /api/v1/ingest ────────▶│                             │
     │     {metrics, events, flows}     │──── INSERT ────────────────▶│
     │                                  │                             │
     │◀─── GET /api/v1/config ──────────│     (indexed by time,       │
     │     {rules, iocs, commands}      │      host, event_type)      │
     │                                  │                             │
                                        │◀─── QUERY ──────────────────│
                              Console ──┤     (search, aggregate)     │
                                        │                             │
```

---

## Repositories

| Repository | Description | Status | Language |
|------------|-------------|--------|----------|
| [sentinel-agent](#sentinel-agent) | Endpoint monitoring agent | ✅ v1.2.0 | Go |
| [sentinel-server](#sentinel-server) | Central aggregator & API | 🔲 Planned | Go |
| [sentinel-console](#sentinel-console) | Web dashboard | 🔲 Planned | Go + HTMX |
| [sentinel-proto](#sentinel-proto) | Shared types & schemas | 🔲 Planned | Go |

---

## Sentinel Agent

### Overview

The Sentinel Agent runs on each monitored endpoint, collecting system metrics, tracking processes and network connections, and exposing local operations via CLI and MCP.

**Repository**: `github.com/[org]/sentinel-agent`

### Current Version: 1.5.0

### Features

#### Monitoring (Read-Only)
| Feature | CLI Flag | MCP Tool | Status |
|---------|----------|----------|--------|
| System Metrics | `--metrics` | `system_metrics` | ✅ |
| Process List | `--processes` | `process_list` | ✅ |
| Top Processes | `--top` | `top_processes` | ✅ |
| Network Connections | `--connections` | `network_connections` | ✅ |
| Disk Usage | `--disk` | `disk_usage` | ✅ |
| Temperature | `--temp` | `temperature` | ✅ |
| Uptime | `--uptime` | `uptime` | ✅ |
| Services List | `--services` | `list_services` | ✅ |
| Asset Info | `--asset-info` | `asset_info` | ✅ |
| Network Stats | `--network-stats` | `network_stats` | ✅ |
| Security Audit | `--security-audit` | `security_audit` | ✅ |
| Check Updates | `--check-updates` | `check_updates` | ✅ |
| Port Scanner | `--scan-ports` | `scan_ports` | ✅ |
| DNS Lookup | `--dns` | `dns_lookup` | ✅ |
| Traceroute | `--traceroute` | `traceroute` | ✅ |
| ARP Table | `--arp` | `arp_table` | ✅ |
| Packet Capture | `--pcap` | `packet_capture` | ✅ |
| DNS Connections | `--dns-connections` | `dns_connections` | ✅ |
| Process Tree | `--process-tree` | `process_tree` | ✅ |
| Process Hash | `--process-hash` | `process_hash` | ✅ |

#### Actions (Write)
| Feature | CLI Flag | MCP Tool | Status |
|---------|----------|----------|--------|
| Block IP | `--block-ip` | `block_ip` | ✅ |
| Unblock IP | `--unblock-ip` | `unblock_ip` | ✅ |
| Restart Service | `--restart-service` | `restart_service` | ✅ |

#### Interface Modes
| Mode | Flag | Status |
|------|------|--------|
| JSON Output | `--json` | ✅ |
| TUI Dashboard | `--tui` | ✅ |
| Watch Mode | `--watch` | ✅ |
| MCP Server | `--mcp` | ✅ |
| Forward Mode | `--forward` | ✅ |

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| macOS | amd64 | ✅ |
| macOS | arm64 | ✅ |
| Linux | amd64 | ✅ |
| Linux | arm64 | ✅ |
| Windows | amd64 | 🔲 Planned |

### Platform-Specific Implementations

| Feature | macOS | Linux |
|---------|-------|-------|
| Temperature | `powermetrics` | `/sys/class/thermal` + `lm-sensors` |
| Firewall | `pf` (pfctl) | `iptables` / `ufw` |
| Services | `launchctl` | `systemctl` |
| Security Audit | SIP, Gatekeeper, FileVault | AppArmor, SELinux |

### Roadmap (Agent)

#### Phase 1: Server Forwarding ✅ Complete (v1.3.0)
- [x] Add `--server` flag for server URL
- [x] Add `--agent-id` flag (auto-generate if not set)
- [x] Add `--tags` flag for agent metadata
- [x] Add `--interval` flag for forward frequency
- [x] Add `--forward` flag for forward mode
- [x] POST to `/api/v1/ingest` endpoint
- [ ] Pull config from `/api/v1/config` (requires server)

**Usage:**
```bash
# Start forwarding to sentinel-server
sentinel --forward --server https://sentinel-server:8443 --tags prod,webserver

# With custom interval and agent ID
sentinel --forward --server https://localhost:8443 --agent-id myhost-001 --interval 60
```

**Events sent per interval:**
- `metrics` - CPU, memory, disk, load, temperature, firewall status
- `processes` - Top 20 processes by CPU
- `connections` - Established and listening connections

#### Phase 2: Enhanced Telemetry
- [ ] Process tree tracking (parent-child relationships)
- [ ] Process hash collection (SHA256 of executables)
- [ ] File integrity monitoring (FIM)
- [ ] DNS query logging
- [ ] Login/logout event tracking

#### Phase 3: Response Actions
- [ ] Kill process by PID
- [ ] Quarantine file
- [ ] Network isolation mode
- [ ] Forensic data collection

### Configuration (Planned)

```yaml
# /etc/sentinel/agent.yaml
agent:
  id: ""                    # Auto-generated UUID if empty
  tags:
    - production
    - webserver

server:
  url: "https://sentinel-server:8443"
  token: "${SENTINEL_TOKEN}"
  interval: 30s
  buffer_size: 1000         # Events to buffer if server unreachable

monitoring:
  processes: true
  connections: true
  temperature: true
  interval: 10s

fim:                        # File Integrity Monitoring
  enabled: false
  paths:
    - /etc
    - /usr/bin
```

### Installation

```bash
# macOS (Homebrew)
brew tap [org]/sentinel
brew install sentinel-agent

# Linux (curl)
curl -fsSL https://get.sentinel.dev | bash

# From source
git clone https://github.com/[org]/sentinel-agent
cd sentinel-agent
go build -o sentinel .
sudo mv sentinel /usr/local/bin/
```

### Usage Examples

```bash
# Quick system check
sentinel --metrics --json

# Monitor with TUI
sentinel --tui

# Security audit
sentinel --security-audit

# Run as MCP server for AI assistant
sentinel --mcp

# Forward to server (planned)
sentinel --server https://sentinel.corp:8443 --interval 30s
```

---

## Sentinel Server

### Overview

Central aggregator that receives telemetry from all agents, stores events in a time-series database, and exposes fleet-wide operations via REST API and MCP.

**Repository**: `github.com/[org]/sentinel-server`

### Status: ✅ Released (v0.3.0)

### Features

#### Core (Implemented)
- [x] Agent registration and heartbeat
- [x] Event ingestion API (`POST /api/v1/ingest`)
- [x] DNS & Process Event Logging (Sprint 2)
- [x] Detection Engine & Rule Matching (Sprint 3)
- [x] IOC Management (Sprint 3)
- [x] Network Diagnostics Storage (Sprint 4)
- [x] Configuration distribution (`GET /api/v1/config`)
- [x] Time-series storage (SQLite)
- [ ] Event retention and rollup

#### Threat Detection (New in v0.2.0)
- [x] Real-time Rule Engine (Regex, Substring, IOC)
- [x] Automated Alert Generation
- [x] IOC Blocklist Management (IP, Domain, Hash)
- [x] Threat Hunting API

#### Search & Query (Planned)
- [ ] Full-text event search
- [ ] Field-based filtering
- [ ] Time-range queries
- [ ] Aggregations (avg, max, min, count)

#### Fleet Management
- [ ] Agent inventory
- [ ] Health monitoring
- [ ] Tag-based grouping
- [ ] Remote command push

#### Alerting
- [ ] Threshold-based rules
- [ ] Pattern matching
- [ ] Alert history
- [ ] Notification actions

#### Threat Intelligence
- [ ] IOC blocklists (IP, domain, hash)
- [ ] Automated matching
- [ ] Feed ingestion
- [ ] Threat hunting queries

### API Endpoints

| Method | Endpoint | Description | Status |
|--------|----------|-------------|--------|
| POST | `/api/v1/ingest` | Receive events from agents | ✅ |
| GET | `/api/v1/config` | Return agent config | ✅ |
| GET | `/api/v1/agents` | List all agents | ✅ |
| GET | `/api/v1/agents/{id}` | Get agent details | ✅ |
| GET | `/api/v1/events` | Search events | 🚧 |
| GET | `/api/v1/rules` | List detection rules | ✅ |
| POST | `/api/v1/rules` | Create detection rule | ✅ |
| GET | `/api/v1/iocs` | List IOCs | ✅ |
| POST | `/api/v1/iocs` | Add IOC | ✅ |
| GET | `/api/v1/alerts` | List triggered alerts | ✅ |
| GET | `/api/v1/diagnostics` | Query network diagnostics | ✅ |
| POST | `/api/v1/diagnostics` | Store diagnostic results | ✅ |

### MCP Tools (Planned)

| Tool | Description |
|------|-------------|
| `fleet_status` | Get all agents with health status |
| `host_lookup` | Get details for specific host |
| `search_events` | Query events across fleet |
| `search_processes` | Find process by name/hash |
| `search_connections` | Find network connections |
| `fleet_metrics` | Aggregated metrics |
| `create_alert` | Define alert rule |
| `list_alerts` | Get all alert rules |
| `get_alert_history` | Past triggered alerts |
| `isolate_host` | Network isolate endpoint |
| `unisolate_host` | Remove isolation |
| `push_command` | Send command to agent |
| `add_ioc` | Add indicator of compromise |
| `remove_ioc` | Remove IOC |
| `list_iocs` | List IOCs |
| `threat_hunt` | Search for IOC matches |

### Database Schema (Planned)

```sql
-- Events (all telemetry)
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    timestamp   DATETIME NOT NULL,
    agent_id    TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    data        JSON NOT NULL
);

-- Agents registry
CREATE TABLE agents (
    agent_id    TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT,
    arch        TEXT,
    version     TEXT,
    tags        JSON,
    first_seen  DATETIME,
    last_seen   DATETIME,
    status      TEXT
);

-- IOC blocklist
CREATE TABLE iocs (
    id          INTEGER PRIMARY KEY,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    severity    TEXT,
    source      TEXT,
    added_at    DATETIME,
    expires_at  DATETIME
);

-- Alert rules
CREATE TABLE alert_rules (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    condition   JSON NOT NULL,
    action      JSON NOT NULL,
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  DATETIME
);

-- Alert history
CREATE TABLE alert_history (
    id           INTEGER PRIMARY KEY,
    rule_id      INTEGER,
    agent_id     TEXT,
    triggered_at DATETIME,
    event_data   JSON,
    resolved     BOOLEAN DEFAULT FALSE
);
```

---

## Sentinel Console

### Overview

Web-based dashboard for fleet management, event investigation, and alert management.

**Repository**: `github.com/[org]/sentinel-console`

### Status: 🔲 Planned

### Features (Planned)

- [ ] Fleet overview (agent grid with health)
- [ ] Real-time event stream
- [ ] Event search interface
- [ ] Process explorer
- [ ] Network connection graph
- [ ] Alert management
- [ ] IOC management
- [ ] Host detail view
- [ ] User authentication

### Tech Stack Options

| Option | Pros | Cons |
|--------|------|------|
| **Go + HTMX** | Single binary, no Node, fast | Less interactive |
| **Go + React** | Rich interactions | Separate build, more deps |
| **Go + Templ + HTMX** | Type-safe templates | Newer ecosystem |

---

## Sentinel Proto

### Overview

Shared type definitions, API contracts, and event schemas used by all components.

**Repository**: `github.com/[org]/sentinel-proto`

### Status: 🔲 Planned

### Contents (Planned)

```
sentinel-proto/
├── go.mod
├── events/
│   ├── metric.go       # MetricEvent struct
│   ├── process.go      # ProcessEvent struct
│   ├── connection.go   # ConnectionEvent struct
│   └── alert.go        # AlertEvent struct
├── api/
│   ├── ingest.go       # IngestRequest/Response
│   ├── config.go       # AgentConfig
│   └── command.go      # CommandRequest/Response
└── mcp/
    ├── agent.go        # Agent MCP tool definitions
    └── server.go       # Server MCP tool definitions
```

---

## MCP Specifications

### Agent MCP Server

**Transport**: stdio (local process)

```json
{
  "name": "sentinel-agent",
  "version": "1.5.0",
  "tools": [
    {"name": "system_metrics", "description": "Get CPU, memory, disk, network stats"},
    {"name": "process_list", "description": "List all running processes"},
    {"name": "top_processes", "description": "Get top N processes by CPU/memory"},
    {"name": "network_connections", "description": "List active network connections"},
    {"name": "disk_usage", "description": "Get filesystem usage"},
    {"name": "temperature", "description": "Get thermal readings"},
    {"name": "uptime", "description": "Get system uptime"},
    {"name": "block_ip", "description": "Block IP in firewall"},
    {"name": "unblock_ip", "description": "Unblock IP from firewall"},
    {"name": "security_audit", "description": "Run security posture check"},
    {"name": "asset_info", "description": "Get hardware/software inventory"},
    {"name": "list_services", "description": "List system services"},
    {"name": "restart_service", "description": "Restart a service"},
    {"name": "scan_ports", "description": "Scan ports on target"},
    {"name": "check_updates", "description": "Check for OS updates"},
    {"name": "dns_lookup", "description": "Resolve DNS records for domain"},
    {"name": "traceroute", "description": "Trace network path to host"},
    {"name": "arp_table", "description": "Get ARP cache (local devices)"},
    {"name": "packet_capture", "description": "Capture packets on interface"},
    {"name": "dns_connections", "description": "Get DNS query connections"},
    {"name": "process_tree", "description": "Get process hierarchy"},
    {"name": "process_hash", "description": "Get SHA256 hash of process"}
  ]
}
```

### Server MCP Server

**Transport**: HTTP + SSE (remote access)

```json
{
  "name": "sentinel-server",
  "version": "1.0.0",
  "tools": [
    {"name": "fleet_status", "description": "Get all agents status"},
    {"name": "host_lookup", "description": "Get specific host details"},
    {"name": "search_events", "description": "Query events across fleet"},
    {"name": "search_processes", "description": "Find processes fleet-wide"},
    {"name": "search_connections", "description": "Find connections fleet-wide"},
    {"name": "fleet_metrics", "description": "Aggregated fleet metrics"},
    {"name": "create_alert", "description": "Create alert rule"},
    {"name": "list_alerts", "description": "List alert rules"},
    {"name": "get_alert_history", "description": "Get triggered alerts"},
    {"name": "isolate_host", "description": "Network isolate endpoint"},
    {"name": "unisolate_host", "description": "Remove isolation"},
    {"name": "push_command", "description": "Send command to agent"},
    {"name": "add_ioc", "description": "Add IOC to blocklist"},
    {"name": "remove_ioc", "description": "Remove IOC"},
    {"name": "list_iocs", "description": "List all IOCs"},
    {"name": "threat_hunt", "description": "Hunt for IOC matches"}
  ]
}
```

---

## Development Progress

### Overall Status

| Component | Version | Status | Progress |
|-----------|---------|--------|----------|
| sentinel-agent | 1.5.0 | ✅ Released | ████████████ 100% |
| sentinel-mcp | 1.3.0 | ✅ Released | ████████████ 100% |
| sentinel-server | 0.3.0 | ✅ Released | █████████░░░ 80% |
| sentinel-console | - | 🔲 Planned | ░░░░░░░░░░░░ 0% |
| sentinel-proto | - | 🔲 Planned | ░░░░░░░░░░░░ 0% |

### Changelog

#### 2026-01-28 (Sprint 4 Update)
- Released sentinel-agent v1.4.0
  - **DNS Lookup** (`--dns`): Full DNS resolution (A, AAAA, MX, TXT, NS, CNAME)
  - **Traceroute** (`--traceroute`): Network path analysis with hop latency
  - **ARP Table** (`--arp`): Local network device discovery
  - **Packet Capture** (`--pcap`): Lightweight tcpdump-style capture
- Released sentinel-mcp v1.3.0
  - Added 7 new tools: dns_lookup, traceroute, arp_table, packet_capture, get_dns_connections, get_process_tree, get_process_hash
  - Now 21 total MCP tools available
- Released sentinel-server v0.3.0
  - Added `network_diagnostics` table for storing DNS/traceroute/ARP/PCAP results
  - New endpoint: `/api/v1/diagnostics`
  - Handles diagnostic event types from agents

#### 2026-01-28 (Previous)
- Released sentinel-server v0.2.0
  - **Sprint 2 (DNS)**: Log DNS queries/responses, Process events
  - **Sprint 3 (Detection)**: Added Rule Engine and IOC Matching
  - New API Endpoints: `/api/v1/rules`, `/api/v1/iocs`
  - Database support for `dns_events`, `process_events`, `detection_rules`, `alerts`
  - Real-time threat detection based on IOCs and Regex patterns28
- Released sentinel-server v0.1.0
  - HTTP server with /api/v1/ingest endpoint
  - SQLite storage for events and agents
  - REST API for agents, events, fleet status
  - Auto agent online/offline tracking
  - Tested with sentinel-agent forward mode
- Released sentinel-agent v1.3.0
- Added server forwarding mode (`--forward`)
- Added `--server`, `--agent-id`, `--tags`, `--interval` flags
- Auto-generates agent ID from hostname + MAC
- Sends metrics, processes, connections events to server
- Created project wiki
- Defined platform architecture
- Documented MCP specifications
- Planned repository structure

#### 2026-01-23
- Released sentinel-agent v1.2.0
- Added 7 new monitoring features
- Added Linux platform support
- Verified all CLI commands working

---

## Contributing

1. Fork the relevant repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request

## License

MIT License - see LICENSE in each repository
