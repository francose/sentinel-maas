//go:build linux
// +build linux

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Platform constants
const (
	PlatformName      = "linux"
	ConfigDir         = "/etc/sentinel"
	DefaultConfigPath = "/etc/sentinel/config.yaml"
	SentinelPFAnchor  = "" // Not used on Linux
	SentinelPFConf    = "" // Not used on Linux
)

// GetTemperature reads CPU temperature from /sys/class/thermal (Linux)
func GetTemperature() string {
	// Try common thermal zone paths
	paths := []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/hwmon/hwmon0/temp1_input",
		"/sys/class/hwmon/hwmon1/temp1_input",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			temp, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil {
				// Temperature is in millidegrees, convert to degrees
				return strconv.FormatFloat(float64(temp)/1000.0, 'f', 1, 64)
			}
		}
	}

	// Try lm-sensors
	out, err := exec.Command("sensors").Output()
	if err == nil {
		re := regexp.MustCompile(`(?i)(?:core 0|cpu|temp1).*?[+]?([\d.]+)°C`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			return m[1]
		}
	}

	return "??"
}

// GetFirewallStatus checks iptables/nftables status (Linux)
func GetFirewallStatus() string {
	// Check if iptables has any rules
	out, err := exec.Command("iptables", "-L", "-n").Output()
	if err == nil && len(out) > 100 { // More than just empty chains
		return "ACTIVE"
	}

	// Check nftables
	out, err = exec.Command("nft", "list", "ruleset").Output()
	if err == nil && len(out) > 10 {
		return "ACTIVE"
	}

	// Check ufw
	out, err = exec.Command("ufw", "status").Output()
	if err == nil && strings.Contains(string(out), "Status: active") {
		return "ACTIVE"
	}

	return "INACTIVE"
}

// EnableFirewall enables ufw firewall (Linux)
func EnableFirewall() ActionResult {
	// Try ufw first (most common on Ubuntu/Debian)
	cmd := exec.Command("ufw", "--force", "enable")
	if err := cmd.Run(); err != nil {
		// Try firewalld (Fedora/RHEL)
		cmd = exec.Command("systemctl", "start", "firewalld")
		if err := cmd.Run(); err != nil {
			if os.Geteuid() != 0 {
				return ActionResult{
					Success:   false,
					Action:    "fix_firewall",
					Error:     "Permission denied",
					ErrorCode: "PERMISSION_DENIED",
					Fix:       "Run with sudo: sudo sentinel --fix-firewall",
				}
			}
			return ActionResult{
				Success:   false,
				Action:    "fix_firewall",
				Error:     "Failed to enable firewall (tried ufw and firewalld)",
				ErrorCode: "FIREWALL_ERROR",
				Fix:       "Install and configure ufw or firewalld manually",
			}
		}
	}
	return ActionResult{
		Success: true,
		Action:  "fix_firewall",
		Details: "Linux firewall enabled successfully",
	}
}

// BlockIP blocks an IP using iptables (Linux)
func BlockIP(ip string) BlockResult {
	// Check if already blocked
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if checkCmd.Run() == nil {
		return BlockResult{
			Success:   false,
			Action:    "block_ip",
			IP:        ip,
			Error:     "IP already blocked",
			ErrorCode: "ALREADY_BLOCKED",
		}
	}

	// Block incoming
	inCmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := inCmd.Run(); err != nil {
		if os.Geteuid() != 0 {
			return BlockResult{
				Success:   false,
				Action:    "block_ip",
				IP:        ip,
				Error:     "Permission denied",
				ErrorCode: "PERMISSION_DENIED",
				Fix:       "Run with sudo: sudo sentinel --block-ip " + ip,
			}
		}
		return BlockResult{
			Success:   false,
			Action:    "block_ip",
			IP:        ip,
			Error:     err.Error(),
			ErrorCode: "IPTABLES_ERROR",
		}
	}

	// Block outgoing
	outCmd := exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP")
	outCmd.Run() // Best effort

	return BlockResult{
		Success: true,
		Action:  "block_ip",
		IP:      ip,
	}
}

// UnblockIP removes an IP from iptables (Linux)
func UnblockIP(ip string) BlockResult {
	// Check if blocked
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if checkCmd.Run() != nil {
		return BlockResult{
			Success:   false,
			Action:    "unblock_ip",
			IP:        ip,
			Error:     "IP not in blocklist",
			ErrorCode: "NOT_BLOCKED",
		}
	}

	// Remove from INPUT
	inCmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := inCmd.Run(); err != nil {
		return BlockResult{
			Success:   false,
			Action:    "unblock_ip",
			IP:        ip,
			Error:     err.Error(),
			ErrorCode: "IPTABLES_ERROR",
		}
	}

	// Remove from OUTPUT
	outCmd := exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP")
	outCmd.Run() // Best effort

	return BlockResult{
		Success: true,
		Action:  "unblock_ip",
		IP:      ip,
	}
}

// ListBlockedIPs returns all blocked IPs from iptables (Linux)
func ListBlockedIPs() BlockResult {
	out, err := exec.Command("iptables", "-L", "INPUT", "-n").Output()
	if err != nil {
		return BlockResult{
			Success: true,
			Action:  "list_blocked",
			IPs:     []string{},
		}
	}

	re := regexp.MustCompile(`DROP\s+all\s+--\s+([\d.]+)\s+`)
	matches := re.FindAllStringSubmatch(string(out), -1)

	var ips []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			ips = append(ips, m[1])
			seen[m[1]] = true
		}
	}

	return BlockResult{
		Success: true,
		Action:  "list_blocked",
		IPs:     ips,
	}
}

// RestartService restarts a systemd service (Linux)
func RestartService(label string) ServiceResult {
	result := ServiceResult{
		Action: "restart_service",
		Label:  label,
	}

	// Check if service exists
	checkCmd := exec.Command("systemctl", "status", label)
	if err := checkCmd.Run(); err != nil {
		// Check if it's an exit code 3 (inactive but exists) vs 4 (not found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 4 {
				result.Success = false
				result.Error = "Service not found: " + label
				result.ErrorCode = "SERVICE_NOT_FOUND"
				result.Fix = "Check if service exists: systemctl list-units | grep " + label
				return result
			}
		}
	}

	// Restart the service
	restartCmd := exec.Command("systemctl", "restart", label)
	if err := restartCmd.Run(); err != nil {
		if os.Geteuid() != 0 {
			result.Success = false
			result.Error = "Permission denied"
			result.ErrorCode = "PERMISSION_DENIED"
			result.Fix = "Run with sudo: sudo sentinel --restart-service " + label
			return result
		}
		result.Success = false
		result.Error = "Failed to restart service: " + err.Error()
		result.ErrorCode = "RESTART_FAILED"
		return result
	}

	result.Success = true
	result.Message = "Service restarted successfully"
	return result
}

// GetAppFirewallStatus returns firewall status for Linux
func GetAppFirewallStatus() string {
	// Check ufw
	out, err := exec.Command("ufw", "status").Output()
	if err == nil {
		if strings.Contains(string(out), "Status: active") {
			return "enabled"
		}
		return "disabled"
	}

	// Check firewalld
	out, err = exec.Command("firewall-cmd", "--state").Output()
	if err == nil {
		if strings.Contains(string(out), "running") {
			return "enabled"
		}
		return "disabled"
	}

	return "unknown"
}

// CheckMacOSUpdates - stub for Linux (not applicable)
func CheckMacOSUpdates() (bool, string) {
	return false, "macOS updates check not available on Linux"
}

// GetServiceManager returns the service manager name for this platform
func GetServiceManager() string {
	return "systemd"
}

// GetServiceListCommand returns the command to list services
func GetServiceListCommand() string {
	return "systemctl list-units --type=service"
}
