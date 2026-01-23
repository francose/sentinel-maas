# Sentinel MCP Server Specification

## Overview

This document specifies the **Model Context Protocol (MCP)** tools that the `sentinel-mcp` server must expose to AI assistants (Claude, Gemini, Copilot). The MCP server acts as a bridge between the AI and the `sentinel` CLI binary.

**Architecture:**
```
┌─────────────────┐     MCP Protocol      ┌─────────────────┐     Shell Exec     ┌─────────────────┐
│   AI Assistant  │ ◄──────────────────► │  sentinel-mcp   │ ◄────────────────► │    sentinel     │
│ (Claude/Gemini) │    JSON-RPC/stdio     │   (Go Server)   │   subprocess call  │   (Go Binary)   │
└─────────────────┘                       └─────────────────┘                    └─────────────────┘
```

**Supported Platforms:** macOS (primary), Linux (beta)

**Key Principle:** The MCP server should be a thin wrapper. It calls `sentinel` CLI commands and parses the JSON output. All heavy lifting is done by the `sentinel` binary.

---

## MCP Tools Specification

### 1. `get_system_health`

**Purpose:** Get real-time system telemetry (CPU, thermal, memory, firewall, network flows).

**When AI should use this:**
- User asks "How's my system doing?"
- User reports slowness, heat, or performance issues
- Periodic health checks
- Before making remediation decisions

**Implementation:**
```bash
sudo sentinel --json
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```
*No input required.*

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "agent_id": { "type": "string" },
    "timestamp": { "type": "string", "format": "date-time" },
    "threat_level": { "type": "string", "enum": ["LOW", "WARNING", "CRITICAL"] },
    "cpu_load": { "type": "string" },
    "temperature": { "type": "string" },
    "firewall_status": { "type": "string", "enum": ["ACTIVE", "DISABLED", "UNKNOWN"] },
    "flows": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "pid": { "type": "integer" },
          "process_name": { "type": "string" },
          "source": { "type": "string" },
          "destination": { "type": "string" },
          "status": { "type": "string" }
        }
      }
    },
    "hostname": { "type": "string" },
    "version": { "type": "string" }
  }
}
```

**Example Response:**
```json
{
  "agent_id": "SENTINEL-MacBook",
  "timestamp": "2026-01-23T10:30:00Z",
  "threat_level": "LOW",
  "cpu_load": "1.25",
  "temperature": "52",
  "firewall_status": "ACTIVE",
  "flows": [
    {
      "pid": 1234,
      "process_name": "Safari",
      "source": "192.168.1.100:54321",
      "destination": "142.250.80.46:443",
      "status": "ESTABLISHED"
    }
  ],
  "hostname": "jynx-macbook",
  "version": "1.1.0"
}
```

---

### 2. `terminate_process`

**Purpose:** Kill a runaway or malicious process by PID.

**When AI should use this:**
- User says "kill process X" or "stop ffmpeg"
- High CPU/memory detected and user approves termination
- Malicious process identified

**Implementation:**
```bash
sudo sentinel --kill <pid>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "pid": {
      "type": "integer",
      "description": "Process ID to terminate"
    },
    "reason": {
      "type": "string",
      "description": "Optional reason for audit logging"
    }
  },
  "required": ["pid"]
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "pid": { "type": "integer" },
    "process_name": { "type": "string" },
    "signal": { "type": "string" },
    "error": { "type": "string" },
    "error_code": { "type": "string" },
    "fix": { "type": "string" }
  }
}
```

**Example Success:**
```json
{
  "success": true,
  "pid": 12345,
  "process_name": "ffmpeg",
  "signal": "SIGKILL"
}
```

**Example Error:**
```json
{
  "success": false,
  "pid": 12345,
  "process_name": "kernel_task",
  "signal": "SIGKILL",
  "error": "Permission denied to kill process 12345 (kernel_task)",
  "error_code": "PERMISSION_DENIED",
  "fix": "Run sentinel with sudo: sudo sentinel --kill 12345"
}
```

**Error Codes:**
| Code | Meaning | AI Action |
|------|---------|-----------|
| `PERMISSION_DENIED` | Needs root | Inform user to use sudo |
| `PROCESS_NOT_FOUND` | PID doesn't exist | Process already terminated |
| `PROTECTED_PROCESS` | Cannot kill (e.g., PID 1) | Refuse and explain |
| `INVALID_PID` | Bad PID value | Ask user for correct PID |

---

### 3. `block_ip_address`

**Purpose:** Block an IP address in the macOS pf firewall.

**When AI should use this:**
- Suspicious connection detected in network flows
- User identifies malicious IP
- Intrusion detection triggered

**Implementation:**
```bash
sudo sentinel --block-ip <ip>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "ip": {
      "type": "string",
      "format": "ipv4",
      "description": "IP address to block (IPv4 or IPv6)"
    },
    "reason": {
      "type": "string",
      "description": "Why this IP is being blocked (for audit)"
    }
  },
  "required": ["ip"]
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "block_ip" },
    "ip": { "type": "string" },
    "error": { "type": "string" },
    "error_code": { "type": "string" },
    "fix": { "type": "string" }
  }
}
```

**Error Codes:**
| Code | Meaning |
|------|---------|
| `INVALID_IP` | Malformed IP address |
| `ALREADY_BLOCKED` | IP already in blocklist |
| `PERMISSION_DENIED` | Needs sudo |
| `PF_RELOAD_FAILED` | Firewall reload error |

---

### 4. `unblock_ip_address`

**Purpose:** Remove an IP from the blocklist.

**Implementation:**
```bash
sudo sentinel --unblock-ip <ip>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "ip": {
      "type": "string",
      "format": "ipv4",
      "description": "IP address to unblock"
    }
  },
  "required": ["ip"]
}
```

**Output Schema:** Same as `block_ip_address`

**Error Codes:**
| Code | Meaning |
|------|---------|
| `NOT_BLOCKED` | IP was not in blocklist |
| `INVALID_IP` | Malformed IP address |

---

### 5. `list_blocked_ips`

**Purpose:** List all currently blocked IP addresses.

**Implementation:**
```bash
sentinel --list-blocked
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "list_blocked" },
    "ips": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

**Example:**
```json
{
  "success": true,
  "action": "list_blocked",
  "ips": ["192.168.1.100", "10.0.0.50", "203.0.113.42"]
}
```

---

### 6. `enable_firewall`

**Purpose:** Enable the macOS Application Firewall if disabled.

**When AI should use this:**
- `get_system_health` shows `firewall_status: "DISABLED"`
- User asks to secure the system
- Security audit recommends it

**Implementation:**
```bash
sudo sentinel --fix-firewall
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "enable_firewall" },
    "details": { "type": "string" },
    "error": { "type": "string" },
    "error_code": { "type": "string" },
    "fix": { "type": "string" }
  }
}
```

---

### 7. `send_telemetry_webhook`

**Purpose:** Send current telemetry to a remote endpoint.

**Implementation:**
```bash
sudo sentinel --webhook <url>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "url": {
      "type": "string",
      "format": "uri",
      "description": "Webhook URL to send telemetry to"
    }
  },
  "required": ["url"]
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "webhook" },
    "target": { "type": "string" },
    "details": { "type": "string" },
    "error": { "type": "string" },
    "error_code": { "type": "string" }
  }
}
```

---

### 8. `get_top_processes`

**Purpose:** Get top CPU/memory consuming processes.

**When AI should use this:**
- User asks "What's using all my CPU?"
- System is slow and user wants to see what's running
- Before recommending which process to kill

**Implementation:**
```bash
sentinel --top --top-count <count>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "count": {
      "type": "integer",
      "description": "Number of processes to return (default: 10)",
      "default": 10
    }
  },
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "top_processes" },
    "timestamp": { "type": "string" },
    "processes": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "pid": { "type": "integer" },
          "name": { "type": "string" },
          "cpu_percent": { "type": "number" },
          "mem_percent": { "type": "number" },
          "mem_mb": { "type": "number" },
          "user": { "type": "string" },
          "status": { "type": "string" },
          "command": { "type": "string" }
        }
      }
    }
  }
}
```

---

### 9. `restart_service`

**Purpose:** Restart a system service (launchd on macOS, systemd on Linux).

**When AI should use this:**
- User asks to restart a service
- A service is misbehaving and needs a restart
- After configuration changes

**Implementation:**
```bash
# macOS
sudo sentinel --restart-service <label>

# Linux  
sudo sentinel --restart-service <unit>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "service": {
      "type": "string",
      "description": "Service label (macOS) or unit name (Linux)"
    }
  },
  "required": ["service"]
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "restart_service" },
    "label": { "type": "string" },
    "message": { "type": "string" },
    "error": { "type": "string" },
    "error_code": { "type": "string" },
    "fix": { "type": "string" }
  }
}
```

**Error Codes:**
| Code | Meaning |
|------|---------|
| `SERVICE_NOT_FOUND` | Service doesn't exist |
| `PERMISSION_DENIED` | Needs sudo |
| `RESTART_FAILED` | Service failed to restart |

---

### 10. `check_updates`

**Purpose:** Check for available OS updates.

**When AI should use this:**
- User asks about updates
- Security audit needs to verify patch status
- Periodic maintenance checks

**Implementation:**
```bash
sentinel --check-updates
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "check_updates" },
    "info": {
      "type": "object",
      "properties": {
        "updates_available": { "type": "boolean" },
        "updates": { "type": "array", "items": { "type": "string" } },
        "last_checked": { "type": "string" },
        "os_version": { "type": "string" }
      }
    }
  }
}
```

---

### 11. `scan_ports`

**Purpose:** Scan ports on a target host.

**When AI should use this:**
- User asks "What ports are open?"
- Security audit to check exposed services
- Troubleshooting connectivity issues

**Implementation:**
```bash
sentinel --scan-ports <target> --port-range <range>
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "target": {
      "type": "string",
      "description": "Target host (e.g., localhost, 192.168.1.1)"
    },
    "port_range": {
      "type": "string",
      "description": "Ports to scan (e.g., '1-1024', '80,443,8080')",
      "default": "1-1024"
    }
  },
  "required": ["target"]
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "scan_ports" },
    "target": { "type": "string" },
    "ports": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "port": { "type": "integer" },
          "state": { "type": "string" },
          "service": { "type": "string" },
          "protocol": { "type": "string" }
        }
      }
    },
    "open_count": { "type": "integer" },
    "scan_time_ms": { "type": "string" }
  }
}
```

---

### 12. `get_asset_info`

**Purpose:** Get complete system hardware/software inventory.

**When AI should use this:**
- User asks about system specs
- Asset inventory/compliance
- "What hardware is this machine?"

**Implementation:**
```bash
sentinel --asset-info
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "asset_info" },
    "asset": {
      "type": "object",
      "properties": {
        "asset_id": { "type": "string" },
        "hostname": { "type": "string" },
        "serial_number": { "type": "string" },
        "hardware": {
          "type": "object",
          "properties": {
            "model": { "type": "string" },
            "chip": { "type": "string" },
            "cores": { "type": "integer" },
            "memory_gb": { "type": "integer" },
            "memory_used_gb": { "type": "integer" }
          }
        },
        "os": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "version": { "type": "string" },
            "build": { "type": "string" },
            "kernel": { "type": "string" },
            "uptime": { "type": "string" }
          }
        },
        "network": {
          "type": "object",
          "properties": {
            "interfaces": { "type": "array" }
          }
        },
        "security": {
          "type": "object",
          "properties": {
            "sip_enabled": { "type": "boolean" },
            "gatekeeper": { "type": "string" },
            "filevault": { "type": "string" },
            "firewall": { "type": "string" }
          }
        },
        "storage": {
          "type": "object",
          "properties": {
            "volumes": { "type": "array" }
          }
        },
        "last_updated": { "type": "string" }
      }
    }
  }
}
```

---

### 13. `get_network_stats`

**Purpose:** Get network interface statistics and connection counts.

**When AI should use this:**
- User asks about network bandwidth
- Troubleshooting network issues
- Monitoring for unusual traffic

**Implementation:**
```bash
sentinel --network-stats
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "network_stats" },
    "stats": {
      "type": "object",
      "properties": {
        "interfaces": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "bytes_sent": { "type": "integer" },
              "bytes_recv": { "type": "integer" },
              "packets_sent": { "type": "integer" },
              "packets_recv": { "type": "integer" },
              "errors_in": { "type": "integer" },
              "errors_out": { "type": "integer" }
            }
          }
        },
        "connections": {
          "type": "object",
          "properties": {
            "total": { "type": "integer" },
            "established": { "type": "integer" },
            "listen": { "type": "integer" },
            "time_wait": { "type": "integer" },
            "close_wait": { "type": "integer" }
          }
        },
        "total_bytes_sent": { "type": "integer" },
        "total_bytes_recv": { "type": "integer" }
      }
    },
    "timestamp": { "type": "string" }
  }
}
```

---

### 14. `security_audit`

**Purpose:** Run a security posture assessment.

**When AI should use this:**
- User asks "Is my system secure?"
- Security compliance checks
- Initial system assessment

**Implementation:**
```bash
sentinel --security-audit
```

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Output Schema:**
```json
{
  "type": "object",
  "properties": {
    "success": { "type": "boolean" },
    "action": { "type": "string", "const": "security_audit" },
    "overall_status": { "type": "string", "enum": ["PASS", "WARNING", "FAIL"] },
    "checks": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "status": { "type": "string", "enum": ["PASS", "WARN", "FAIL"] },
          "description": { "type": "string" },
          "value": { "type": "string" },
          "fix": { "type": "string" }
        }
      }
    },
    "score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "timestamp": { "type": "string" }
  }
}
```

**Example Response:**
```json
{
  "success": true,
  "action": "security_audit",
  "overall_status": "WARNING",
  "checks": [
    {"name": "System Integrity Protection", "status": "PASS", "value": "Enabled"},
    {"name": "Gatekeeper", "status": "PASS", "value": "Enabled"},
    {"name": "FileVault Encryption", "status": "WARN", "value": "Disabled", "fix": "Enable in System Preferences > Security & Privacy > FileVault"},
    {"name": "Application Firewall", "status": "PASS", "value": "Enabled"}
  ],
  "score": 75,
  "timestamp": "2026-01-23T10:30:00Z"
}
```

---

## Future Tools (Planned)

These tools are in the roadmap and should be implemented once the sentinel CLI supports them:

### 15. `dns_lookup` (Phase 4)
```bash
sentinel --dns <domain>
```
DNS resolution with full record details.

### 16. `traceroute` (Phase 4)
```bash
sentinel --traceroute <host>
```
Network path analysis with latency.

---

## Implementation Guidelines for MCP Server

### 1. Server Setup (Go)

Use the `mark3labs/mcp-go` library:

```go
package main

import (
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)

func main() {
    s := server.NewMCPServer(
        "sentinel-mcp",
        "1.1.0",
        server.WithToolCapabilities(true),
    )
    
    // Register tools
    s.AddTool(mcp.NewTool("get_system_health", ...), handleGetSystemHealth)
    s.AddTool(mcp.NewTool("terminate_process", ...), handleTerminateProcess)
    // ... register all tools
    
    s.ServeStdio()
}
```

### 2. Executing Sentinel Commands

```go
func runSentinel(args ...string) ([]byte, error) {
    cmd := exec.Command("sudo", append([]string{"sentinel"}, args...)...)
    return cmd.Output()
}

func handleGetSystemHealth(args map[string]interface{}) (*mcp.CallToolResult, error) {
    output, err := runSentinel("--json")
    if err != nil {
        return mcp.NewToolResultError(err.Error()), nil
    }
    return mcp.NewToolResultText(string(output)), nil
}
```

### 3. Error Handling

Always parse the JSON response to check for errors:

```go
type SentinelResult struct {
    Success   bool   `json:"success"`
    Error     string `json:"error,omitempty"`
    ErrorCode string `json:"error_code,omitempty"`
    Fix       string `json:"fix,omitempty"`
}

func handleTerminateProcess(args map[string]interface{}) (*mcp.CallToolResult, error) {
    pid := int(args["pid"].(float64))
    
    output, _ := runSentinel("--kill", strconv.Itoa(pid))
    
    var result SentinelResult
    json.Unmarshal(output, &result)
    
    if !result.Success {
        // Return error with fix suggestion
        return mcp.NewToolResultText(string(output)), nil
    }
    
    return mcp.NewToolResultText(string(output)), nil
}
```

### 4. MCP Server Configuration (for Claude Desktop)

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/usr/local/bin/sentinel-mcp",
      "args": []
    }
  }
}
```

---

## Tool Descriptions (for AI Context)

These descriptions should be included in the MCP tool registration so the AI understands when to use each tool:

| Tool | Description for AI |
|------|-------------------|
| `get_system_health` | Get real-time system status including CPU load, temperature, memory, firewall status, and active network connections. Use this first to assess system state. |
| `terminate_process` | Kill a process by PID. Use SIGKILL for immediate termination. Requires sudo. Use when user wants to stop a specific process or when a runaway process is detected. |
| `block_ip_address` | Block an IP address in the firewall (pf on macOS, iptables on Linux). Blocks both inbound and outbound traffic. Use for malicious IPs or suspicious connections. |
| `unblock_ip_address` | Remove an IP from the firewall blocklist. Use when a blocked IP should be allowed again. |
| `list_blocked_ips` | List all IP addresses currently blocked by Sentinel. Use to show user what's blocked or before adding new blocks. |
| `enable_firewall` | Enable the system firewall if it's disabled. Use when security audit shows firewall is off. |
| `send_telemetry_webhook` | Send current system telemetry to a remote HTTP endpoint. Use for fleet monitoring or external logging. |
| `get_top_processes` | Get top CPU/memory consuming processes. Use when user asks what's using resources or system is slow. |
| `restart_service` | Restart a system service (launchd on macOS, systemd on Linux). Use when a service needs to be restarted. |
| `check_updates` | Check for available OS updates. Use for security compliance or when user asks about updates. |
| `scan_ports` | Scan ports on a target host. Use for security audits or troubleshooting connectivity. |
| `get_asset_info` | Get complete system hardware/software inventory. Use when user asks about specs or for asset tracking. |
| `get_network_stats` | Get network interface statistics and connection counts. Use for bandwidth monitoring or network troubleshooting. |
| `security_audit` | Run a security posture assessment. Use when user asks "Is my system secure?" or for compliance checks. |

---

## Testing the MCP Server

### Manual Testing

1. Start the MCP server:
   ```bash
   sentinel-mcp
   ```

2. Send a JSON-RPC request via stdin:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_system_health","arguments":{}}}
   ```

3. Verify JSON response on stdout.

### Integration Testing

```bash
# Test get_system_health
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_system_health","arguments":{}}}' | sentinel-mcp

# Test terminate_process
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"terminate_process","arguments":{"pid":12345}}}' | sentinel-mcp
```

---

## Summary Table

| Tool | CLI Command | Needs Sudo | Category | Platform |
|------|-------------|------------|----------|----------|
| `get_system_health` | `--json` | Yes | Monitoring | All |
| `terminate_process` | `--kill <pid>` | Yes | Remediation | All |
| `block_ip_address` | `--block-ip <ip>` | Yes | Remediation | All |
| `unblock_ip_address` | `--unblock-ip <ip>` | Yes | Remediation | All |
| `list_blocked_ips` | `--list-blocked` | No | Monitoring | All |
| `enable_firewall` | `--fix-firewall` | Yes | Remediation | All |
| `send_telemetry_webhook` | `--webhook <url>` | Yes | Fleet | All |
| `get_top_processes` | `--top --top-count <n>` | No | Monitoring | All |
| `restart_service` | `--restart-service <label>` | Yes | Remediation | All |
| `check_updates` | `--check-updates` | No | Monitoring | macOS |
| `scan_ports` | `--scan-ports <target>` | No | Security | All |
| `get_asset_info` | `--asset-info` | No | Inventory | All |
| `get_network_stats` | `--network-stats` | No | Monitoring | All |
| `security_audit` | `--security-audit` | No | Security | All |

---

## Platform Notes

| Feature | macOS | Linux |
|---------|-------|-------|
| Firewall | pf (`pfctl`) | iptables/ufw |
| Services | launchd (`launchctl`) | systemd (`systemctl`) |
| Temperature | powermetrics | /sys/class/thermal, lm-sensors |
| Updates Check | softwareupdate | Not implemented |
| Security Audit | Full (SIP, Gatekeeper, FileVault) | Partial |

---

## Questions?

This specification should provide everything needed to implement the MCP server. The key principle is: **keep the MCP server thin**—it only translates MCP calls to `sentinel` CLI invocations and returns the JSON output.
