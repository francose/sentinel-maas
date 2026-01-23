//go:build darwin
// +build darwin

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Platform constants
const (
	PlatformName      = "darwin"
	ConfigDir         = "/etc/sentinel"
	DefaultConfigPath = "/etc/sentinel/config.yaml"
	SentinelPFAnchor  = "com.sentinel"
	SentinelPFConf    = "/etc/pf.anchors/com.sentinel"
)

// GetTemperature reads CPU temperature using powermetrics (macOS)
func GetTemperature() string {
	out, err := exec.Command("powermetrics", "-n", "1", "--samplers", "smc,thermal").Output()
	if err != nil {
		return "??"
	}
	re := regexp.MustCompile(`CPU die temperature:\s*([\d.]+)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		return m[1]
	}
	return "??"
}

// GetFirewallStatus checks pf firewall status (macOS)
func GetFirewallStatus() string {
	fwCmd := exec.Command("pfctl", "-s", "info")
	fwOut, _ := fwCmd.CombinedOutput()
	if strings.Contains(string(fwOut), "Status: Enabled") {
		return "ACTIVE"
	}
	return "INACTIVE"
}

// EnableFirewall enables the macOS Application Firewall
func EnableFirewall() ActionResult {
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on")
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
			Error:     err.Error(),
			ErrorCode: "FIREWALL_ERROR",
		}
	}
	return ActionResult{
		Success: true,
		Action:  "fix_firewall",
		Details: "macOS Application Firewall enabled successfully",
	}
}

// BlockIP blocks an IP using pf firewall (macOS)
func BlockIP(ip string) BlockResult {
	// Read existing rules
	existingRules := ""
	if data, err := os.ReadFile(SentinelPFConf); err == nil {
		existingRules = string(data)
		// Check if already blocked
		if strings.Contains(existingRules, ip) {
			return BlockResult{
				Success:   false,
				Action:    "block_ip",
				IP:        ip,
				Error:     "IP already blocked",
				ErrorCode: "ALREADY_BLOCKED",
			}
		}
	}

	// Create anchor directory
	os.MkdirAll("/etc/pf.anchors", 0755)

	// Add block rule
	newRules := existingRules
	if newRules != "" && !strings.HasSuffix(newRules, "\n") {
		newRules += "\n"
	}
	newRules += "block drop quick from " + ip + " to any\n"
	newRules += "block drop quick from any to " + ip + "\n"

	if err := os.WriteFile(SentinelPFConf, []byte(newRules), 0644); err != nil {
		if os.Geteuid() != 0 {
			return BlockResult{
				Success:   false,
				Action:    "block_ip",
				IP:        ip,
				Error:     "Permission denied writing firewall rules",
				ErrorCode: "PERMISSION_DENIED",
				Fix:       "Run with sudo: sudo sentinel --block-ip " + ip,
			}
		}
		return BlockResult{
			Success:   false,
			Action:    "block_ip",
			IP:        ip,
			Error:     err.Error(),
			ErrorCode: "WRITE_ERROR",
		}
	}

	// Load the anchor rules
	cmd := exec.Command("pfctl", "-a", SentinelPFAnchor, "-f", SentinelPFConf)
	if err := cmd.Run(); err != nil {
		return BlockResult{
			Success:   false,
			Action:    "block_ip",
			IP:        ip,
			Error:     "Failed to load firewall rules: " + err.Error(),
			ErrorCode: "PFCTL_ERROR",
		}
	}

	// Enable pf if not already enabled
	exec.Command("pfctl", "-e").Run()

	return BlockResult{
		Success: true,
		Action:  "block_ip",
		IP:      ip,
	}
}

// UnblockIP removes an IP from the pf blocklist (macOS)
func UnblockIP(ip string) BlockResult {
	data, err := os.ReadFile(SentinelPFConf)
	if err != nil {
		return BlockResult{
			Success:   false,
			Action:    "unblock_ip",
			IP:        ip,
			Error:     "No blocklist file found",
			ErrorCode: "NOT_BLOCKED",
		}
	}

	rules := string(data)
	if !strings.Contains(rules, ip) {
		return BlockResult{
			Success:   false,
			Action:    "unblock_ip",
			IP:        ip,
			Error:     "IP not in blocklist",
			ErrorCode: "NOT_BLOCKED",
		}
	}

	// Remove rules for this IP
	lines := strings.Split(rules, "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, ip) {
			newLines = append(newLines, line)
		}
	}

	newRules := strings.Join(newLines, "\n")
	if err := os.WriteFile(SentinelPFConf, []byte(newRules), 0644); err != nil {
		return BlockResult{
			Success:   false,
			Action:    "unblock_ip",
			IP:        ip,
			Error:     err.Error(),
			ErrorCode: "WRITE_ERROR",
		}
	}

	// Reload rules
	exec.Command("pfctl", "-a", SentinelPFAnchor, "-f", SentinelPFConf).Run()

	return BlockResult{
		Success: true,
		Action:  "unblock_ip",
		IP:      ip,
	}
}

// ListBlockedIPs returns all blocked IPs from pf anchor (macOS)
func ListBlockedIPs() BlockResult {
	data, err := os.ReadFile(SentinelPFConf)
	if err != nil {
		return BlockResult{
			Success: true,
			Action:  "list_blocked",
			IPs:     []string{},
		}
	}

	re := regexp.MustCompile(`block drop quick from ([\d.]+) to any`)
	matches := re.FindAllStringSubmatch(string(data), -1)

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

// RestartService restarts a launchd service (macOS)
func RestartService(label string) ServiceResult {
	result := ServiceResult{
		Action: "restart_service",
		Label:  label,
	}

	// Check if service exists
	checkCmd := exec.Command("launchctl", "list", label)
	if _, err := checkCmd.Output(); err != nil {
		result.Success = false
		result.Error = "Service not found: " + label
		result.ErrorCode = "SERVICE_NOT_FOUND"
		result.Fix = "Check if service exists: launchctl list | grep " + label
		return result
	}

	// Stop the service
	stopCmd := exec.Command("launchctl", "stop", label)
	if err := stopCmd.Run(); err != nil {
		result.Success = false
		result.Error = "Failed to stop service: " + err.Error()
		result.ErrorCode = "STOP_FAILED"
		return result
	}

	// Start the service
	startCmd := exec.Command("launchctl", "start", label)
	if err := startCmd.Run(); err != nil {
		result.Success = false
		result.Error = "Stopped but failed to start: " + err.Error()
		result.ErrorCode = "START_FAILED"
		result.Fix = "Check if service exists: launchctl list | grep " + label
		return result
	}

	result.Success = true
	result.Message = "Service restarted successfully"
	return result
}

// GetAppFirewallStatus checks the macOS Application Firewall status
func GetAppFirewallStatus() string {
	out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
	if err != nil {
		return "unknown"
	}
	if strings.Contains(strings.ToLower(string(out)), "enabled") {
		return "enabled"
	}
	return "disabled"
}

// CheckMacOSUpdates checks for available macOS updates
func CheckMacOSUpdates() (bool, string) {
	cmd := exec.Command("softwareupdate", "-l")
	out, _ := cmd.CombinedOutput()
	output := string(out)
	hasUpdates := strings.Contains(output, "Software Update found") ||
		strings.Contains(output, "Title:") ||
		strings.Contains(output, "Label:")
	return hasUpdates, output
}

// GetServiceManager returns the service manager name for this platform
func GetServiceManager() string {
	return "launchd"
}

// GetServiceListCommand returns the command to list services
func GetServiceListCommand() string {
	return "launchctl list"
}
