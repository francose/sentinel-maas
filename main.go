package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"gopkg.in/yaml.v3"
)

// --- DATA STRUCTURES ---
type MaaSUpdate struct {
	AgentID      string       `json:"agent_id"`
	Timestamp    string       `json:"timestamp"`
	ThreatLevel  string       `json:"threat_level"`
	CPULoad      string       `json:"cpu_load"`
	Temperature  string       `json:"temperature"`
	Firewall     string       `json:"firewall_status"`
	NetworkFlows []FlowRecord `json:"flows"`
	SecurityLogs []string     `json:"recent_logs"`
	Hostname     string       `json:"hostname,omitempty"`
	Version      string       `json:"version,omitempty"`
}

type FlowRecord struct {
	PID     int32  `json:"pid"`
	Process string `json:"process_name"`
	Src     string `json:"source"`
	Dst     string `json:"destination"`
	Status  string `json:"status"`
}

// --- PHASE 2: CONFIG FILE SUPPORT ---
type Config struct {
	AgentID    string `yaml:"agent_id"`
	Thresholds struct {
		ThermalWarning  float64 `yaml:"thermal_warning"`
		ThermalCritical float64 `yaml:"thermal_critical"`
		CPUWarning      float64 `yaml:"cpu_warning"`
		CPUCritical     float64 `yaml:"cpu_critical"`
		MemoryWarning   float64 `yaml:"memory_warning"`
		MemoryCritical  float64 `yaml:"memory_critical"`
	} `yaml:"thresholds"`
	Webhook struct {
		URL      string `yaml:"url"`
		Interval int    `yaml:"interval_seconds"`
		Enabled  bool   `yaml:"enabled"`
	} `yaml:"webhook"`
	BlockedIPs []string `yaml:"blocked_ips"`
}

// --- STRUCTURED ERROR/RESULT RESPONSES ---
type ActionResult struct {
	Success   bool   `json:"success"`
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Fix       string `json:"fix,omitempty"`
	Details   string `json:"details,omitempty"`
}

type KillResult struct {
	Success     bool   `json:"success"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name,omitempty"`
	Signal      string `json:"signal"`
	Error       string `json:"error,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

type BlockResult struct {
	Success   bool     `json:"success"`
	Action    string   `json:"action"`
	IP        string   `json:"ip,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Error     string   `json:"error,omitempty"`
	ErrorCode string   `json:"error_code,omitempty"`
	Fix       string   `json:"fix,omitempty"`
}

// --- PHASE 4/5: NEW DATA STRUCTURES ---

// TopProcess represents a process in the top list
type TopProcess struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float32 `json:"mem_percent"`
	MemMB      float64 `json:"mem_mb"`
	User       string  `json:"user"`
	Status     string  `json:"status"`
	Command    string  `json:"command,omitempty"`
}

// TopProcessResult for --top command
type TopProcessResult struct {
	Success   bool         `json:"success"`
	Action    string       `json:"action"`
	Timestamp string       `json:"timestamp"`
	Processes []TopProcess `json:"processes"`
	Error     string       `json:"error,omitempty"`
	ErrorCode string       `json:"error_code,omitempty"`
}

// ServiceInfo for --services command
type ServiceInfo struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"`
	PID    int    `json:"pid,omitempty"`
	Type   string `json:"type"` // LaunchDaemon, LaunchAgent
	Path   string `json:"path,omitempty"`
}

// ServiceResult for service operations
type ServiceResult struct {
	Success   bool          `json:"success"`
	Action    string        `json:"action"`
	Service   string        `json:"service,omitempty"`
	Label     string        `json:"label,omitempty"`
	Message   string        `json:"message,omitempty"`
	Services  []ServiceInfo `json:"services,omitempty"`
	Error     string        `json:"error,omitempty"`
	ErrorCode string        `json:"error_code,omitempty"`
	Fix       string        `json:"fix,omitempty"`
}

// UpdateInfo for --check-updates
type UpdateInfo struct {
	Available   bool     `json:"updates_available"`
	Updates     []string `json:"updates,omitempty"`
	LastChecked string   `json:"last_checked"`
	OSVersion   string   `json:"os_version"`
	Error       string   `json:"error,omitempty"`
}

// UpdateResult for update check
type UpdateResult struct {
	Success   bool       `json:"success"`
	Action    string     `json:"action"`
	Info      UpdateInfo `json:"info"`
	Error     string     `json:"error,omitempty"`
	ErrorCode string     `json:"error_code,omitempty"`
}

// PortInfo for --scan-ports
type PortInfo struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Protocol string `json:"protocol"`
}

// PortScanResult for port scanning
type PortScanResult struct {
	Success   bool       `json:"success"`
	Action    string     `json:"action"`
	Target    string     `json:"target"`
	Ports     []PortInfo `json:"ports"`
	OpenCount int        `json:"open_count"`
	ScanTime  string     `json:"scan_time_ms"`
	Error     string     `json:"error,omitempty"`
	ErrorCode string     `json:"error_code,omitempty"`
}

// AssetInfo for --asset-info
type AssetInfo struct {
	AssetID      string       `json:"asset_id"`
	Hostname     string       `json:"hostname"`
	SerialNumber string       `json:"serial_number"`
	Hardware     HardwareInfo `json:"hardware"`
	OS           OSInfo       `json:"os"`
	Network      NetworkInfo  `json:"network"`
	Security     SecurityInfo `json:"security"`
	Storage      StorageInfo  `json:"storage"`
	LastUpdated  string       `json:"last_updated"`
}

type HardwareInfo struct {
	Model      string `json:"model"`
	Chip       string `json:"chip"`
	Cores      int    `json:"cores"`
	MemoryGB   uint64 `json:"memory_gb"`
	MemoryUsed uint64 `json:"memory_used_gb"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
	Kernel  string `json:"kernel"`
	Uptime  string `json:"uptime"`
}

type NetworkInfo struct {
	Interfaces []InterfaceInfo `json:"interfaces"`
	PublicIP   string          `json:"public_ip,omitempty"`
}

type InterfaceInfo struct {
	Name   string   `json:"name"`
	MAC    string   `json:"mac"`
	IPs    []string `json:"ips"`
	Status string   `json:"status"`
}

type SecurityInfo struct {
	SIPEnabled bool   `json:"sip_enabled"`
	Gatekeeper string `json:"gatekeeper"`
	FileVault  string `json:"filevault"`
	Firewall   string `json:"firewall"`
	XProtect   string `json:"xprotect,omitempty"`
}

type StorageInfo struct {
	Volumes []VolumeInfo `json:"volumes"`
}

type VolumeInfo struct {
	Name       string  `json:"name"`
	MountPoint string  `json:"mount_point"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	FreeGB     float64 `json:"free_gb"`
	UsedPct    float64 `json:"used_percent"`
}

// AssetResult for asset info
type AssetResult struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	Asset     AssetInfo `json:"asset"`
	Error     string    `json:"error,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// NetworkStats for --network-stats
type NetworkStats struct {
	Interfaces     []InterfaceStats `json:"interfaces"`
	Connections    ConnectionStats  `json:"connections"`
	TotalBytesSent uint64           `json:"total_bytes_sent"`
	TotalBytesRecv uint64           `json:"total_bytes_recv"`
}

type InterfaceStats struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	Errin       uint64 `json:"errors_in"`
	Errout      uint64 `json:"errors_out"`
}

type ConnectionStats struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	Listen      int `json:"listen"`
	TimeWait    int `json:"time_wait"`
	CloseWait   int `json:"close_wait"`
}

// NetworkStatsResult for network stats
type NetworkStatsResult struct {
	Success   bool         `json:"success"`
	Action    string       `json:"action"`
	Stats     NetworkStats `json:"stats"`
	Timestamp string       `json:"timestamp"`
	Error     string       `json:"error,omitempty"`
	ErrorCode string       `json:"error_code,omitempty"`
}

// SecurityAuditResult for --security-audit
type SecurityAuditResult struct {
	Success       bool         `json:"success"`
	Action        string       `json:"action"`
	OverallStatus string       `json:"overall_status"` // SECURE, WARNING, CRITICAL
	Checks        []AuditCheck `json:"checks"`
	Score         int          `json:"score"` // 0-100
	Timestamp     string       `json:"timestamp"`
	Error         string       `json:"error,omitempty"`
	ErrorCode     string       `json:"error_code,omitempty"`
}

type AuditCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // PASS, WARN, FAIL
	Description string `json:"description"`
	Value       string `json:"value,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

const (
	Version = "1.3.0"
)

// Platform-specific constants are defined in platform_darwin.go and platform_linux.go:
// - ConfigDir, DefaultConfigPath
// - SentinelPFAnchor, SentinelPFConf (macOS only)

// --- FORWARDING DATA STRUCTURES ---

// ForwardConfig holds server forwarding configuration
type ForwardConfig struct {
	ServerURL    string
	AgentID      string
	Tags         []string
	Interval     time.Duration
	BufferSize   int
	Timeout      time.Duration
}

// ForwardEvent is the envelope sent to sentinel-server
type ForwardEvent struct {
	AgentID    string                 `json:"agent_id"`
	Hostname   string                 `json:"hostname"`
	OS         string                 `json:"os"`
	Arch       string                 `json:"arch"`
	Version    string                 `json:"version"`
	Tags       []string               `json:"tags,omitempty"`
	Timestamp  string                 `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	Data       map[string]interface{} `json:"data"`
}

// ForwardBatch is a batch of events sent to server
type ForwardBatch struct {
	AgentID   string         `json:"agent_id"`
	Hostname  string         `json:"hostname"`
	Timestamp string         `json:"timestamp"`
	Events    []ForwardEvent `json:"events"`
}

// ServerResponse from sentinel-server ingest endpoint
type ServerResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	EventsRecv int    `json:"events_received,omitempty"`
}

// --- GLOBAL STATE ---
var (
	globalFlows    []FlowRecord
	globalLogs     []string
	globalTemp     string
	globalLoad     float64
	globalFirewall string
	globalThreat   string = "LOW"
	coreCount      int
	globalConfig   Config
)

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// --- FLAGS ---
	jsonMode := flag.Bool("json", false, "Output JSON telemetry to stdout and exit")
	fixFirewall := flag.Bool("fix-firewall", false, "Enable the macOS Application Firewall")
	killPID := flag.Int("kill", 0, "Terminate a process by PID")

	// PHASE 1B: Network Blocking flags
	blockIP := flag.String("block-ip", "", "Block an IP address using pf firewall")
	unblockIP := flag.String("unblock-ip", "", "Unblock a previously blocked IP address")
	listBlocked := flag.Bool("list-blocked", false, "List all blocked IP addresses")

	// PHASE 2: Config file
	configPath := flag.String("config", DefaultConfigPath, "Path to config file")
	initConfig := flag.Bool("init-config", false, "Create default config file")

	// PHASE 3: Webhook/Fleet mode
	webhookURL := flag.String("webhook", "", "Send telemetry to webhook URL (one-shot)")
	daemonMode := flag.Bool("daemon", false, "Run as daemon, sending telemetry to configured webhook")

	// PHASE 4: Advanced Network Tools
	topProcs := flag.Bool("top", false, "Show top processes by CPU/memory usage")
	topCount := flag.Int("top-count", 10, "Number of processes to show (default 10)")
	scanPorts := flag.String("scan-ports", "", "Scan ports on target (e.g., localhost, 192.168.1.1)")
	portRange := flag.String("port-range", "1-1024", "Port range to scan (e.g., 1-1024, 80,443,8080)")
	networkStats := flag.Bool("network-stats", false, "Show network interface statistics")

	// PHASE 5: Asset Metadata & Inventory
	assetInfo := flag.Bool("asset-info", false, "Show full system asset information")
	securityAudit := flag.Bool("security-audit", false, "Run security posture audit")
	listServices := flag.Bool("services", false, "List running services (LaunchDaemons/Agents)")
	restartSvc := flag.String("restart-service", "", "Restart a launchd service by label")
	checkUpdates := flag.Bool("check-updates", false, "Check for available macOS updates")

	// PHASE 6: Server Forwarding
	serverURL := flag.String("server", "", "Sentinel server URL (e.g., https://sentinel-server:8443)")
	forwardMode := flag.Bool("forward", false, "Run in forward mode, sending telemetry to sentinel-server")
	agentID := flag.String("agent-id", "", "Agent ID (auto-generated if not set)")
	agentTags := flag.String("tags", "", "Comma-separated agent tags (e.g., prod,webserver)")
	forwardInterval := flag.Int("interval", 30, "Forward interval in seconds (default 30)")

	// Info flags
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	// Version
	if *versionFlag {
		fmt.Printf("Sentinel v%s\n", Version)
		return
	}

	// Load config
	globalConfig = loadConfig(*configPath)

	// Init config file
	if *initConfig {
		initConfigFile()
		return
	}

	// Fix Firewall
	if *fixFirewall {
		enableFirewall()
		return
	}

	// Process Killer
	if *killPID > 0 {
		killProcess(*killPID)
		return
	}

	// PHASE 1B: Network blocking operations
	if *blockIP != "" {
		blockIPAddress(*blockIP)
		return
	}

	if *unblockIP != "" {
		unblockIPAddress(*unblockIP)
		return
	}

	if *listBlocked {
		listBlockedIPs()
		return
	}

	// PHASE 3: Webhook one-shot
	if *webhookURL != "" {
		sendWebhook(*webhookURL)
		return
	}

	// PHASE 3: Daemon mode
	if *daemonMode {
		runDaemon()
		return
	}

	// PHASE 6: Forward mode (to sentinel-server)
	if *forwardMode {
		// Parse tags
		var tags []string
		if *agentTags != "" {
			tags = strings.Split(*agentTags, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		// Build forward config
		fwdConfig := ForwardConfig{
			ServerURL:  *serverURL,
			AgentID:    *agentID,
			Tags:       tags,
			Interval:   time.Duration(*forwardInterval) * time.Second,
			BufferSize: 100,
			Timeout:    10 * time.Second,
		}
		runForwardMode(fwdConfig)
		return
	}

	// PHASE 4: Top processes
	if *topProcs {
		getTopProcesses(*topCount)
		return
	}

	// PHASE 4: Port scanning
	if *scanPorts != "" {
		scanPortsOnTarget(*scanPorts, *portRange)
		return
	}

	// PHASE 4: Network stats
	if *networkStats {
		getNetworkStats()
		return
	}

	// PHASE 5: Asset info
	if *assetInfo {
		getAssetInfo()
		return
	}

	// PHASE 5: Security audit
	if *securityAudit {
		runSecurityAudit()
		return
	}

	// PHASE 5: Services
	if *listServices {
		getServices()
		return
	}

	// PHASE 5: Restart service
	if *restartSvc != "" {
		restartService(*restartSvc)
		return
	}

	// PHASE 5: Check updates
	if *checkUpdates {
		checkForUpdates()
		return
	}

	// Detect Cores
	counts, _ := cpu.Counts(true)
	if counts == 0 {
		counts = 2
	}
	coreCount = counts

	// --- HEADLESS JSON MODE ---
	if *jsonMode {
		runHeadlessCollection()
		return
	}

	// --- TUI MODE ---
	runTUI()
}

// ============================================================================
// PHASE 2: CONFIG FILE
// ============================================================================

func loadConfig(path string) Config {
	cfg := Config{
		AgentID: "SENTINEL-" + getHostname(),
	}
	// Set defaults
	cfg.Thresholds.ThermalWarning = 75.0
	cfg.Thresholds.ThermalCritical = 88.0
	cfg.Thresholds.CPUWarning = 80.0
	cfg.Thresholds.CPUCritical = 95.0
	cfg.Thresholds.MemoryWarning = 80.0
	cfg.Thresholds.MemoryCritical = 95.0
	cfg.Webhook.Interval = 60

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}

	yaml.Unmarshal(data, &cfg)
	return cfg
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "UNKNOWN"
	}
	return h
}

func initConfigFile() {
	result := ActionResult{Action: "init_config", Target: DefaultConfigPath}

	// Create directory
	dir := filepath.Dir(DefaultConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		result.Error = fmt.Sprintf("Cannot create directory %s: %v", dir, err)
		result.ErrorCode = "PERMISSION_DENIED"
		result.Fix = "Run with sudo: sudo sentinel --init-config"
		outputJSON(result)
		os.Exit(1)
	}

	defaultConfig := `# Sentinel Configuration File
# /etc/sentinel/config.yaml

agent_id: "SENTINEL-DEFAULT"

thresholds:
  thermal_warning: 75.0    # Celsius - triggers warning
  thermal_critical: 88.0   # Celsius - triggers critical alert
  cpu_warning: 80.0        # Percent
  cpu_critical: 95.0       # Percent
  memory_warning: 80.0     # Percent
  memory_critical: 95.0    # Percent

webhook:
  url: ""                  # e.g., "https://your-server.com/api/telemetry"
  interval_seconds: 60     # How often to send telemetry in daemon mode
  enabled: false

# IPs to block (managed by --block-ip/--unblock-ip)
blocked_ips: []
`

	if err := os.WriteFile(DefaultConfigPath, []byte(defaultConfig), 0644); err != nil {
		result.Error = fmt.Sprintf("Cannot write config: %v", err)
		result.ErrorCode = "WRITE_FAILED"
		result.Fix = "Run with sudo: sudo sentinel --init-config"
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	result.Details = "Config file created at " + DefaultConfigPath
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Config file created at %s\n", DefaultConfigPath)
}

// ============================================================================
// PHASE 1: FIREWALL CONTROL
// ============================================================================

func enableFirewall() {
	result := ActionResult{Action: "enable_firewall"}

	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on")
	out, err := cmd.CombinedOutput()

	if err != nil {
		result.Error = fmt.Sprintf("Failed to enable firewall: %v", err)
		result.ErrorCode = "PERMISSION_DENIED"
		result.Fix = "Run with sudo: sudo sentinel --fix-firewall"
		result.Details = string(out)
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	result.Details = "macOS Application Firewall enabled"
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Firewall enabled\n")
}

// ============================================================================
// PHASE 1A: PROCESS KILLER
// ============================================================================

func killProcess(pid int) {
	result := KillResult{PID: pid, Signal: "SIGKILL"}

	if pid <= 0 {
		result.Error = "Invalid PID: must be a positive integer"
		result.ErrorCode = "INVALID_PID"
		outputJSON(result)
		os.Exit(1)
	}

	if pid == 1 {
		result.Error = "Cannot kill PID 1 (launchd/init)"
		result.ErrorCode = "PROTECTED_PROCESS"
		outputJSON(result)
		os.Exit(1)
	}

	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		result.Error = fmt.Sprintf("Process %d not found", pid)
		result.ErrorCode = "PROCESS_NOT_FOUND"
		outputJSON(result)
		os.Exit(1)
	}

	procName, _ := proc.Name()
	result.ProcessName = procName

	osProc, err := os.FindProcess(pid)
	if err != nil {
		result.Error = fmt.Sprintf("Cannot find process: %v", err)
		result.ErrorCode = "PROCESS_NOT_FOUND"
		outputJSON(result)
		os.Exit(1)
	}

	err = osProc.Signal(syscall.SIGKILL)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") ||
			strings.Contains(err.Error(), "permission denied") {
			result.Error = fmt.Sprintf("Permission denied to kill process %d (%s)", pid, procName)
			result.ErrorCode = "PERMISSION_DENIED"
			result.Fix = "Run with sudo: sudo sentinel --kill " + strconv.Itoa(pid)
		} else if strings.Contains(err.Error(), "no such process") {
			result.Error = fmt.Sprintf("Process %d no longer exists", pid)
			result.ErrorCode = "PROCESS_NOT_FOUND"
		} else {
			result.Error = fmt.Sprintf("Failed to kill process: %v", err)
			result.ErrorCode = "KILL_FAILED"
		}
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Terminated process %d (%s)\n", pid, procName)
}

// ============================================================================
// PHASE 1B: NETWORK BLOCKING (using pf)
// ============================================================================

func blockIPAddress(ip string) {
	result := BlockResult{Action: "block_ip", IP: ip}

	// Validate IP
	if net.ParseIP(ip) == nil {
		result.Error = fmt.Sprintf("Invalid IP address: %s", ip)
		result.ErrorCode = "INVALID_IP"
		outputJSON(result)
		os.Exit(1)
	}

	// Check if pf anchor file exists, create if not
	ensurePFAnchor()

	// Read current blocked IPs
	blockedIPs := readBlockedIPs()

	// Check if already blocked
	for _, blocked := range blockedIPs {
		if blocked == ip {
			result.Error = fmt.Sprintf("IP %s is already blocked", ip)
			result.ErrorCode = "ALREADY_BLOCKED"
			outputJSON(result)
			os.Exit(1)
		}
	}

	// Add to blocked list
	blockedIPs = append(blockedIPs, ip)
	if err := writeBlockedIPs(blockedIPs); err != nil {
		result.Error = fmt.Sprintf("Failed to update block list: %v", err)
		result.ErrorCode = "WRITE_FAILED"
		result.Fix = "Run with sudo: sudo sentinel --block-ip " + ip
		outputJSON(result)
		os.Exit(1)
	}

	// Reload pf rules
	if err := reloadPFRules(); err != nil {
		result.Error = fmt.Sprintf("Failed to reload firewall: %v", err)
		result.ErrorCode = "PF_RELOAD_FAILED"
		result.Fix = "Run with sudo: sudo sentinel --block-ip " + ip
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Blocked IP: %s\n", ip)
}

func unblockIPAddress(ip string) {
	result := BlockResult{Action: "unblock_ip", IP: ip}

	if net.ParseIP(ip) == nil {
		result.Error = fmt.Sprintf("Invalid IP address: %s", ip)
		result.ErrorCode = "INVALID_IP"
		outputJSON(result)
		os.Exit(1)
	}

	blockedIPs := readBlockedIPs()
	found := false
	newList := []string{}

	for _, blocked := range blockedIPs {
		if blocked == ip {
			found = true
		} else {
			newList = append(newList, blocked)
		}
	}

	if !found {
		result.Error = fmt.Sprintf("IP %s is not in the block list", ip)
		result.ErrorCode = "NOT_BLOCKED"
		outputJSON(result)
		os.Exit(1)
	}

	if err := writeBlockedIPs(newList); err != nil {
		result.Error = fmt.Sprintf("Failed to update block list: %v", err)
		result.ErrorCode = "WRITE_FAILED"
		result.Fix = "Run with sudo: sudo sentinel --unblock-ip " + ip
		outputJSON(result)
		os.Exit(1)
	}

	if err := reloadPFRules(); err != nil {
		result.Error = fmt.Sprintf("Failed to reload firewall: %v", err)
		result.ErrorCode = "PF_RELOAD_FAILED"
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Unblocked IP: %s\n", ip)
}

func listBlockedIPs() {
	result := BlockResult{Action: "list_blocked"}
	blockedIPs := readBlockedIPs()
	result.Success = true
	result.IPs = blockedIPs
	outputJSON(result)
}

func ensurePFAnchor() {
	// Create the anchor directory if needed
	os.MkdirAll("/etc/pf.anchors", 0755)

	// Check if anchor file exists
	if _, err := os.Stat(SentinelPFConf); os.IsNotExist(err) {
		os.WriteFile(SentinelPFConf, []byte("# Sentinel Blocked IPs\n"), 0644)
	}
}

func readBlockedIPs() []string {
	data, err := os.ReadFile(SentinelPFConf)
	if err != nil {
		return []string{}
	}

	var ips []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "block") {
			// Extract IP from "block drop from X to any" or just the IP
			if strings.Contains(line, "block") {
				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "from" && i+1 < len(parts) {
						ip := parts[i+1]
						if net.ParseIP(ip) != nil {
							ips = append(ips, ip)
						}
					}
				}
			} else if net.ParseIP(line) != nil {
				ips = append(ips, line)
			}
		}
	}
	return ips
}

func writeBlockedIPs(ips []string) error {
	var rules strings.Builder
	rules.WriteString("# Sentinel Blocked IPs - Managed by sentinel --block-ip/--unblock-ip\n")
	rules.WriteString("# Do not edit manually\n\n")

	for _, ip := range ips {
		rules.WriteString(fmt.Sprintf("block drop from %s to any\n", ip))
		rules.WriteString(fmt.Sprintf("block drop from any to %s\n", ip))
	}

	return os.WriteFile(SentinelPFConf, []byte(rules.String()), 0644)
}

func reloadPFRules() error {
	// Load the anchor into pf
	cmd := exec.Command("pfctl", "-a", SentinelPFAnchor, "-f", SentinelPFConf)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}

	// Ensure pf is enabled
	exec.Command("pfctl", "-e").Run()
	return nil
}

// ============================================================================
// PHASE 3: WEBHOOK & DAEMON MODE
// ============================================================================

func sendWebhook(url string) {
	result := ActionResult{Action: "webhook", Target: url}

	telemetry := collectTelemetry()
	telemetry.Version = Version
	telemetry.Hostname = getHostname()

	jsonData, _ := json.Marshal(telemetry)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		result.Error = fmt.Sprintf("Failed to send webhook: %v", err)
		result.ErrorCode = "NETWORK_ERROR"
		outputJSON(result)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		result.Error = fmt.Sprintf("Webhook returned status %d", resp.StatusCode)
		result.ErrorCode = "HTTP_ERROR"
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	result.Details = fmt.Sprintf("Telemetry sent, status: %d", resp.StatusCode)
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Telemetry sent to %s\n", url)
}

func runDaemon() {
	if globalConfig.Webhook.URL == "" {
		result := ActionResult{
			Action:    "daemon",
			Error:     "No webhook URL configured",
			ErrorCode: "CONFIG_MISSING",
			Fix:       "Set webhook.url in " + DefaultConfigPath + " or use --webhook flag",
		}
		outputJSON(result)
		os.Exit(1)
	}

	interval := globalConfig.Webhook.Interval
	if interval < 10 {
		interval = 60
	}

	fmt.Fprintf(os.Stderr, "🛡️ Sentinel Daemon started\n")
	fmt.Fprintf(os.Stderr, "   Agent ID: %s\n", globalConfig.AgentID)
	fmt.Fprintf(os.Stderr, "   Webhook: %s\n", globalConfig.Webhook.URL)
	fmt.Fprintf(os.Stderr, "   Interval: %ds\n", interval)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Send immediately on start
	sendTelemetryQuiet(globalConfig.Webhook.URL)

	for range ticker.C {
		sendTelemetryQuiet(globalConfig.Webhook.URL)
	}
}

func sendTelemetryQuiet(url string) {
	telemetry := collectTelemetry()
	telemetry.AgentID = globalConfig.AgentID
	telemetry.Version = Version
	telemetry.Hostname = getHostname()

	jsonData, _ := json.Marshal(telemetry)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Webhook failed: %v\n", err)
		return
	}
	resp.Body.Close()
	fmt.Fprintf(os.Stderr, "📡 Telemetry sent [%s]\n", time.Now().Format("15:04:05"))
}

func collectTelemetry() MaaSUpdate {
	l, _ := load.Avg()

	temp := "??"
	out, _ := exec.Command("powermetrics", "-n", "1", "--samplers", "smc,thermal").Output()
	reTemp := regexp.MustCompile(`(?i)(?:CPU\s+die\s+temperature|SOC\s+M1|Die\s+temp).*?:\s+(\d+\.?\d*)`)
	if m := reTemp.FindStringSubmatch(string(out)); len(m) > 1 {
		temp = m[1]
	}

	fwStatus := "UNKNOWN"
	fwCmd := exec.Command("pfctl", "-s", "info")
	fwOut, _ := fwCmd.CombinedOutput()
	if strings.Contains(string(fwOut), "Status: Enabled") {
		fwStatus = "ACTIVE"
	} else {
		fwStatus = "DISABLED"
	}

	conns, _ := psnet.Connections("inet")
	var flows []FlowRecord
	for _, c := range conns {
		if c.Status == "ESTABLISHED" {
			procName := "?"
			if c.Pid > 0 {
				if p, err := process.NewProcess(c.Pid); err == nil {
					n, _ := p.Name()
					if n != "" {
						procName = n
					}
				}
			}
			flows = append(flows, FlowRecord{
				PID: c.Pid, Process: procName, Status: c.Status,
				Src: fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
				Dst: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
			})
		}
	}

	// Calculate threat level based on thresholds
	threat := "LOW"
	if tempVal, err := strconv.ParseFloat(temp, 64); err == nil {
		if tempVal >= globalConfig.Thresholds.ThermalCritical {
			threat = "CRITICAL"
		} else if tempVal >= globalConfig.Thresholds.ThermalWarning {
			threat = "WARNING"
		}
	}
	if fwStatus == "DISABLED" && threat == "LOW" {
		threat = "WARNING"
	}

	return MaaSUpdate{
		AgentID:      globalConfig.AgentID,
		Timestamp:    time.Now().Format(time.RFC3339),
		ThreatLevel:  threat,
		CPULoad:      fmt.Sprintf("%.2f", l.Load1),
		Temperature:  temp,
		Firewall:     fwStatus,
		NetworkFlows: flows,
	}
}

// ============================================================================
// HEADLESS JSON MODE
// ============================================================================

func runHeadlessCollection() {
	telemetry := collectTelemetry()
	b, _ := json.Marshal(telemetry)
	fmt.Println(string(b))
}

// ============================================================================
// PHASE 6: FORWARD MODE (SENTINEL-SERVER)
// ============================================================================

// generateAgentID creates a unique agent ID based on hostname and MAC address
func generateAgentID() string {
	hostname := getHostname()

	// Try to get a MAC address for uniqueness
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if len(iface.HardwareAddr) > 0 && iface.Flags&net.FlagLoopback == 0 {
				// Use first 6 chars of MAC as suffix
				mac := strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
				if len(mac) >= 6 {
					return fmt.Sprintf("sentinel-%s-%s", strings.ToLower(hostname), mac[:6])
				}
			}
		}
	}

	// Fallback: hostname + random suffix
	return fmt.Sprintf("sentinel-%s-%d", strings.ToLower(hostname), time.Now().UnixNano()%100000)
}

// runForwardMode runs the agent in forward mode, sending telemetry to sentinel-server
func runForwardMode(cfg ForwardConfig) {
	// Validate server URL
	if cfg.ServerURL == "" {
		result := ActionResult{
			Action:    "forward",
			Error:     "No server URL specified",
			ErrorCode: "CONFIG_MISSING",
			Fix:       "Use --server https://your-sentinel-server:8443",
		}
		outputJSON(result)
		os.Exit(1)
	}

	// Generate agent ID if not provided
	if cfg.AgentID == "" {
		cfg.AgentID = generateAgentID()
	}

	// Minimum interval
	if cfg.Interval < 10*time.Second {
		cfg.Interval = 30 * time.Second
	}

	// Print startup info
	fmt.Fprintf(os.Stderr, "🛡️  Sentinel Forward Mode\n")
	fmt.Fprintf(os.Stderr, "   Agent ID:  %s\n", cfg.AgentID)
	fmt.Fprintf(os.Stderr, "   Server:    %s\n", cfg.ServerURL)
	fmt.Fprintf(os.Stderr, "   Interval:  %s\n", cfg.Interval)
	if len(cfg.Tags) > 0 {
		fmt.Fprintf(os.Stderr, "   Tags:      %s\n", strings.Join(cfg.Tags, ", "))
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	// Build ingest URL
	ingestURL := strings.TrimSuffix(cfg.ServerURL, "/") + "/api/v1/ingest"

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Send immediately on start
	sendForwardBatch(client, ingestURL, cfg)

	// Then on interval
	for range ticker.C {
		sendForwardBatch(client, ingestURL, cfg)
	}
}

// collectForwardEvents gathers all telemetry and returns as ForwardEvents
func collectForwardEvents(cfg ForwardConfig) []ForwardEvent {
	var events []ForwardEvent
	timestamp := time.Now().Format(time.RFC3339)
	hostname := getHostname()

	// Base event fields
	baseEvent := ForwardEvent{
		AgentID:   cfg.AgentID,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   Version,
		Tags:      cfg.Tags,
		Timestamp: timestamp,
	}

	// 1. System Metrics Event
	metricsEvent := baseEvent
	metricsEvent.EventType = "metrics"
	metricsEvent.Data = collectMetricsData()
	events = append(events, metricsEvent)

	// 2. Process Event (top processes)
	processEvent := baseEvent
	processEvent.EventType = "processes"
	processEvent.Data = collectProcessData()
	events = append(events, processEvent)

	// 3. Connections Event
	connEvent := baseEvent
	connEvent.EventType = "connections"
	connEvent.Data = collectConnectionData()
	events = append(events, connEvent)

	return events
}

// collectMetricsData gathers CPU, memory, disk, network stats
func collectMetricsData() map[string]interface{} {
	data := make(map[string]interface{})

	// CPU
	cpuPercent, _ := cpu.Percent(0, false)
	if len(cpuPercent) > 0 {
		data["cpu_percent"] = cpuPercent[0]
	}

	// Load
	l, _ := load.Avg()
	if l != nil {
		data["load_1"] = l.Load1
		data["load_5"] = l.Load5
		data["load_15"] = l.Load15
	}

	// Memory
	m, _ := mem.VirtualMemory()
	if m != nil {
		data["memory_total"] = m.Total
		data["memory_used"] = m.Used
		data["memory_percent"] = m.UsedPercent
	}

	// Disk
	d, _ := disk.Usage("/")
	if d != nil {
		data["disk_total"] = d.Total
		data["disk_used"] = d.Used
		data["disk_percent"] = d.UsedPercent
	}

	// Temperature (platform-specific)
	temp := GetTemperature()
	data["temperature"] = temp

	// Firewall status
	fwCmd := exec.Command("pfctl", "-s", "info")
	fwOut, _ := fwCmd.CombinedOutput()
	if strings.Contains(string(fwOut), "Status: Enabled") {
		data["firewall"] = "enabled"
	} else {
		data["firewall"] = "disabled"
	}

	return data
}

// collectProcessData gathers top processes by CPU
func collectProcessData() map[string]interface{} {
	data := make(map[string]interface{})

	procs, err := process.Processes()
	if err != nil {
		data["error"] = err.Error()
		return data
	}

	type procInfo struct {
		PID        int32   `json:"pid"`
		Name       string  `json:"name"`
		CPUPercent float64 `json:"cpu_percent"`
		MemPercent float32 `json:"mem_percent"`
		User       string  `json:"user"`
	}

	var procList []procInfo
	for _, p := range procs {
		cpu, _ := p.CPUPercent()
		mem, _ := p.MemoryPercent()
		name, _ := p.Name()
		user, _ := p.Username()

		procList = append(procList, procInfo{
			PID:        p.Pid,
			Name:       name,
			CPUPercent: cpu,
			MemPercent: mem,
			User:       user,
		})
	}

	// Sort by CPU and take top 20
	sort.Slice(procList, func(i, j int) bool {
		return procList[i].CPUPercent > procList[j].CPUPercent
	})
	if len(procList) > 20 {
		procList = procList[:20]
	}

	data["processes"] = procList
	data["total_count"] = len(procs)

	return data
}

// collectConnectionData gathers active network connections
func collectConnectionData() map[string]interface{} {
	data := make(map[string]interface{})

	conns, err := psnet.Connections("inet")
	if err != nil {
		data["error"] = err.Error()
		return data
	}

	type connInfo struct {
		PID      int32  `json:"pid"`
		Process  string `json:"process"`
		Protocol string `json:"protocol"`
		LocalIP  string `json:"local_ip"`
		LocalPort uint32 `json:"local_port"`
		RemoteIP string `json:"remote_ip"`
		RemotePort uint32 `json:"remote_port"`
		Status   string `json:"status"`
	}

	var connList []connInfo
	established := 0
	listening := 0

	for _, c := range conns {
		if c.Status == "ESTABLISHED" {
			established++
		} else if c.Status == "LISTEN" {
			listening++
		}

		// Only include established and listening for the list
		if c.Status == "ESTABLISHED" || c.Status == "LISTEN" {
			procName := ""
			if c.Pid > 0 {
				if p, err := process.NewProcess(c.Pid); err == nil {
					procName, _ = p.Name()
				}
			}

			proto := "tcp"
			if c.Type == syscall.SOCK_DGRAM {
				proto = "udp"
			}

			connList = append(connList, connInfo{
				PID:        c.Pid,
				Process:    procName,
				Protocol:   proto,
				LocalIP:    c.Laddr.IP,
				LocalPort:  c.Laddr.Port,
				RemoteIP:   c.Raddr.IP,
				RemotePort: c.Raddr.Port,
				Status:     c.Status,
			})
		}
	}

	data["connections"] = connList
	data["total"] = len(conns)
	data["established"] = established
	data["listening"] = listening

	return data
}

// sendForwardBatch collects and sends events to sentinel-server
func sendForwardBatch(client *http.Client, url string, cfg ForwardConfig) {
	events := collectForwardEvents(cfg)

	batch := ForwardBatch{
		AgentID:   cfg.AgentID,
		Hostname:  getHostname(),
		Timestamp: time.Now().Format(time.RFC3339),
		Events:    events,
	}

	jsonData, err := json.Marshal(batch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  JSON marshal error: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Request error: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", cfg.AgentID)
	req.Header.Set("X-Agent-Version", Version)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Server unreachable: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Fprintf(os.Stderr, "📡 Forwarded %d events [%s]\n", len(events), time.Now().Format("15:04:05"))
	} else {
		fmt.Fprintf(os.Stderr, "⚠️  Server returned %d\n", resp.StatusCode)
	}
}

// ============================================================================
// TUI MODE
// ============================================================================

func runTUI() {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to init termui: %v", err)
	}
	defer ui.Close()

	slCPU := widgets.NewSparkline()
	slCPU.LineColor = ui.ColorGreen
	slCPU.Title = fmt.Sprintf("CPU Activity (%d Cores)", coreCount)
	slCPUGroup := widgets.NewSparklineGroup(slCPU)
	slCPUGroup.Title = "Load Pressure"
	slCPUGroup.SetRect(0, 0, 50, 10)

	pHardware := widgets.NewParagraph()
	pHardware.Title = "Thermal Status (Root)"
	pHardware.Text = "Sensor: Initializing..."
	pHardware.SetRect(50, 0, 75, 10)

	pMaaS := widgets.NewParagraph()
	pMaaS.Title = "MaaS Agent"
	pMaaS.Text = fmt.Sprintf("Mode: ACTIVE\nVersion: %s", Version)
	pMaaS.SetRect(75, 0, 100, 10)
	pMaaS.TextStyle = ui.NewStyle(ui.ColorGreen)

	gMem := widgets.NewGauge()
	gMem.Title = "RAM Usage"
	gMem.SetRect(0, 10, 50, 13)
	gMem.BarColor = ui.ColorCyan

	pSec := widgets.NewParagraph()
	pSec.Title = "Firewall Status"
	pSec.Text = "Checking Packet Filter..."
	pSec.SetRect(50, 10, 100, 13)

	lNet := widgets.NewList()
	lNet.Title = "Network Flows"
	lNet.Rows = []string{"Scanning socket table..."}
	lNet.SetRect(0, 13, 50, 25)

	lLogs := widgets.NewList()
	lLogs.Title = "Security Events"
	lLogs.Rows = []string{"Watching com.apple.securityd..."}
	lLogs.SetRect(50, 13, 100, 25)

	// --- UI WORKERS ---
	// 1. Security Monitor
	go func() {
		cmd := exec.Command("log", "stream", "--style", "syslog", "--predicate", "subsystem == \"com.apple.securityd\"", "--info")
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			globalLogs = append(globalLogs, line)
			if len(globalLogs) > 20 {
				globalLogs = globalLogs[1:]
			}
			if len(line) > 55 {
				line = line[:55] + ".."
			}
			lLogs.Rows = append(lLogs.Rows, line)
			if len(lLogs.Rows) > 12 {
				lLogs.Rows = lLogs.Rows[1:]
			}
			ui.Render(lLogs)
		}
	}()

	// 2. Hardware Monitor
	go func() {
		reTemp := regexp.MustCompile(`(?i)(?:CPU\s+die\s+temperature|SOC\s+M1|Die\s+temp).*?:\s+(\d+\.?\d*)`)
		for {
			out, err := exec.Command("powermetrics", "-n", "1", "--samplers", "smc,thermal").Output()
			if err != nil {
				pHardware.Text = "ERR: RUN AS SUDO"
				pHardware.TextStyle = ui.NewStyle(ui.ColorRed, ui.ModifierBold)
			} else {
				output := string(out)
				tempStr := "??"
				if m := reTemp.FindStringSubmatch(output); len(m) > 1 {
					tempStr = m[1]
				}
				globalTemp = tempStr

				// Apply threshold coloring
				tempVal, _ := strconv.ParseFloat(tempStr, 64)
				if tempVal >= globalConfig.Thresholds.ThermalCritical {
					pHardware.TextStyle = ui.NewStyle(ui.ColorRed, ui.ModifierBold)
				} else if tempVal >= globalConfig.Thresholds.ThermalWarning {
					pHardware.TextStyle = ui.NewStyle(ui.ColorYellow)
				} else {
					pHardware.TextStyle = ui.NewStyle(ui.ColorGreen)
				}
				pHardware.Text = fmt.Sprintf("Cooling: PASSIVE\nTemp:    %s C", tempStr)
			}

			fwStatus := "UNKNOWN"
			fwCmd := exec.Command("pfctl", "-s", "info")
			fwOut, _ := fwCmd.CombinedOutput()
			if strings.Contains(string(fwOut), "Status: Enabled") {
				fwStatus = "ACTIVE (Blocking)"
				pSec.TextStyle = ui.NewStyle(ui.ColorGreen)
			} else {
				fwStatus = "DISABLED (RISK!)"
				pSec.TextStyle = ui.NewStyle(ui.ColorRed, ui.ModifierBold)
			}
			globalFirewall = fwStatus
			pSec.Text = fmt.Sprintf("Firewall: %s", fwStatus)

			ui.Render(pHardware, pSec)
			time.Sleep(2 * time.Second)
		}
	}()

	// 3. Network Flows
	go func() {
		for {
			conns, _ := psnet.Connections("inet")
			var flows []FlowRecord
			var uiRows []string
			count := 0
			for _, c := range conns {
				if count > 12 {
					break
				}
				if c.Status == "ESTABLISHED" || c.Status == "LISTEN" {
					procName := "?"
					if c.Pid > 0 {
						if p, err := process.NewProcess(c.Pid); err == nil {
							n, _ := p.Name()
							if n != "" {
								procName = n
							}
						}
					}
					if len(procName) > 10 {
						procName = procName[:10]
					}

					flows = append(flows, FlowRecord{
						PID: c.Pid, Process: procName, Status: c.Status,
						Src: fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
						Dst: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
					})
					row := fmt.Sprintf("[%d] %s: %s->%s", c.Pid, procName, c.Laddr.IP, c.Raddr.IP)
					uiRows = append(uiRows, row)
					count++
				}
			}
			globalFlows = flows
			lNet.Rows = uiRows
			ui.Render(lNet)
			time.Sleep(2 * time.Second)
		}
	}()

	// MAIN EVENT LOOP
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(1 * time.Second).C
	for {
		select {
		case e := <-uiEvents:
			if e.ID == "q" || e.ID == "<C-c>" {
				return
			}
		case <-ticker:
			c, _ := cpu.Percent(0, false)
			if len(c) > 0 {
				slCPU.Data = append(slCPU.Data, float64(c[0]))
				if len(slCPU.Data) > 50 {
					slCPU.Data = slCPU.Data[1:]
				}
			}
			l, _ := load.Avg()
			globalLoad = l.Load1
			v, _ := mem.VirtualMemory()
			gMem.Percent = int(v.UsedPercent)
			gMem.Label = fmt.Sprintf("%d%%", int(v.UsedPercent))
			ui.Render(slCPUGroup, gMem)
		}
	}
}

// ============================================================================
// UTILITY
// ============================================================================

func outputJSON(v interface{}) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

// ============================================================================
// PHASE 4: TOP PROCESSES
// ============================================================================

func getTopProcesses(count int) {
	result := TopProcessResult{
		Action:    "top_processes",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	procs, err := process.Processes()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to get processes: %v", err)
		result.ErrorCode = "PROCESS_ERROR"
		outputJSON(result)
		os.Exit(1)
	}

	var topProcs []TopProcess
	for _, p := range procs {
		name, _ := p.Name()
		cpuPct, _ := p.CPUPercent()
		memPct, _ := p.MemoryPercent()
		memInfo, _ := p.MemoryInfo()
		user, _ := p.Username()
		status, _ := p.Status()
		cmdline, _ := p.Cmdline()

		memMB := float64(0)
		if memInfo != nil {
			memMB = float64(memInfo.RSS) / 1024 / 1024
		}

		// Truncate command line
		if len(cmdline) > 100 {
			cmdline = cmdline[:100] + "..."
		}

		topProcs = append(topProcs, TopProcess{
			PID:        p.Pid,
			Name:       name,
			CPUPercent: cpuPct,
			MemPercent: memPct,
			MemMB:      memMB,
			User:       user,
			Status:     strings.Join(status, ","),
			Command:    cmdline,
		})
	}

	// Sort by CPU usage (descending)
	sort.Slice(topProcs, func(i, j int) bool {
		return topProcs[i].CPUPercent > topProcs[j].CPUPercent
	})

	// Limit to count
	if len(topProcs) > count {
		topProcs = topProcs[:count]
	}

	result.Success = true
	result.Processes = topProcs
	outputJSON(result)
}

// ============================================================================
// PHASE 4: PORT SCANNING
// ============================================================================

func scanPortsOnTarget(target string, portRange string) {
	result := PortScanResult{
		Action: "scan_ports",
		Target: target,
	}

	startTime := time.Now()

	// Parse port range
	ports := parsePortRange(portRange)
	if len(ports) == 0 {
		result.Error = "Invalid port range format. Use: 1-1024 or 80,443,8080"
		result.ErrorCode = "INVALID_PORT_RANGE"
		outputJSON(result)
		os.Exit(1)
	}

	// Common port services
	portServices := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
		5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
		8443: "HTTPS-Alt", 27017: "MongoDB",
	}

	var openPorts []PortInfo
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			service := portServices[port]
			if service == "" {
				service = "unknown"
			}
			openPorts = append(openPorts, PortInfo{
				Port:     port,
				State:    "open",
				Service:  service,
				Protocol: "tcp",
			})
		}
	}

	elapsed := time.Since(startTime)
	result.Success = true
	result.Ports = openPorts
	result.OpenCount = len(openPorts)
	result.ScanTime = fmt.Sprintf("%d", elapsed.Milliseconds())
	outputJSON(result)
}

func parsePortRange(rangeStr string) []int {
	var ports []int

	// Handle comma-separated list
	if strings.Contains(rangeStr, ",") {
		parts := strings.Split(rangeStr, ",")
		for _, p := range parts {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
		return ports
	}

	// Handle range (e.g., 1-1024)
	if strings.Contains(rangeStr, "-") {
		parts := strings.Split(rangeStr, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		}
		return ports
	}

	// Single port
	port, err := strconv.Atoi(strings.TrimSpace(rangeStr))
	if err == nil && port > 0 && port <= 65535 {
		ports = append(ports, port)
	}

	return ports
}

// ============================================================================
// PHASE 4: NETWORK STATS
// ============================================================================

func getNetworkStats() {
	result := NetworkStatsResult{
		Action:    "network_stats",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Get interface stats
	ioCounters, err := psnet.IOCounters(true)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to get network stats: %v", err)
		result.ErrorCode = "NETWORK_ERROR"
		outputJSON(result)
		os.Exit(1)
	}

	var totalSent, totalRecv uint64
	var ifaceStats []InterfaceStats
	for _, io := range ioCounters {
		ifaceStats = append(ifaceStats, InterfaceStats{
			Name:        io.Name,
			BytesSent:   io.BytesSent,
			BytesRecv:   io.BytesRecv,
			PacketsSent: io.PacketsSent,
			PacketsRecv: io.PacketsRecv,
			Errin:       io.Errin,
			Errout:      io.Errout,
		})
		totalSent += io.BytesSent
		totalRecv += io.BytesRecv
	}

	// Get connection stats
	conns, _ := psnet.Connections("all")
	connStats := ConnectionStats{Total: len(conns)}
	for _, c := range conns {
		switch c.Status {
		case "ESTABLISHED":
			connStats.Established++
		case "LISTEN":
			connStats.Listen++
		case "TIME_WAIT":
			connStats.TimeWait++
		case "CLOSE_WAIT":
			connStats.CloseWait++
		}
	}

	result.Success = true
	result.Stats = NetworkStats{
		Interfaces:     ifaceStats,
		Connections:    connStats,
		TotalBytesSent: totalSent,
		TotalBytesRecv: totalRecv,
	}
	outputJSON(result)
}

// ============================================================================
// PHASE 5: ASSET INFO
// ============================================================================

func getAssetInfo() {
	result := AssetResult{
		Action: "asset_info",
	}

	// Hardware info
	hostInfo, _ := host.Info()
	cpuInfo, _ := cpu.Info()
	memInfo, _ := mem.VirtualMemory()

	chipName := runtime.GOARCH
	if len(cpuInfo) > 0 {
		chipName = cpuInfo[0].ModelName
	}

	cores, _ := cpu.Counts(true)

	// Get serial number (macOS specific)
	serialNumber := "Unknown"
	if out, err := exec.Command("system_profiler", "SPHardwareDataType").Output(); err == nil {
		re := regexp.MustCompile(`Serial Number.*:\s*(\S+)`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			serialNumber = m[1]
		}
	}

	// Get model
	model := "Unknown"
	if out, err := exec.Command("system_profiler", "SPHardwareDataType").Output(); err == nil {
		re := regexp.MustCompile(`Model Name:\s*(.+)`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			model = strings.TrimSpace(m[1])
		}
	}

	// Network interfaces
	interfaces, _ := psnet.Interfaces()
	var netInterfaces []InterfaceInfo
	for _, iface := range interfaces {
		var ips []string
		for _, addr := range iface.Addrs {
			ips = append(ips, addr.Addr)
		}
		status := "down"
		for _, f := range iface.Flags {
			if f == "up" {
				status = "up"
				break
			}
		}
		netInterfaces = append(netInterfaces, InterfaceInfo{
			Name:   iface.Name,
			MAC:    iface.HardwareAddr,
			IPs:    ips,
			Status: status,
		})
	}

	// Storage info
	partitions, _ := disk.Partitions(false)
	var volumes []VolumeInfo
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err == nil {
			volumes = append(volumes, VolumeInfo{
				Name:       p.Device,
				MountPoint: p.Mountpoint,
				TotalGB:    float64(usage.Total) / 1024 / 1024 / 1024,
				UsedGB:     float64(usage.Used) / 1024 / 1024 / 1024,
				FreeGB:     float64(usage.Free) / 1024 / 1024 / 1024,
				UsedPct:    usage.UsedPercent,
			})
		}
	}

	// Security info
	secInfo := getSecurityInfo()

	// Uptime
	uptime := time.Duration(hostInfo.Uptime) * time.Second
	uptimeStr := fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60)

	result.Success = true
	result.Asset = AssetInfo{
		AssetID:      globalConfig.AgentID,
		Hostname:     hostInfo.Hostname,
		SerialNumber: serialNumber,
		Hardware: HardwareInfo{
			Model:      model,
			Chip:       chipName,
			Cores:      cores,
			MemoryGB:   memInfo.Total / 1024 / 1024 / 1024,
			MemoryUsed: memInfo.Used / 1024 / 1024 / 1024,
		},
		OS: OSInfo{
			Name:    hostInfo.Platform,
			Version: hostInfo.PlatformVersion,
			Build:   hostInfo.KernelVersion,
			Kernel:  hostInfo.KernelArch,
			Uptime:  uptimeStr,
		},
		Network: NetworkInfo{
			Interfaces: netInterfaces,
		},
		Security: secInfo,
		Storage: StorageInfo{
			Volumes: volumes,
		},
		LastUpdated: time.Now().Format(time.RFC3339),
	}
	outputJSON(result)
}

func getSecurityInfo() SecurityInfo {
	info := SecurityInfo{}

	// SIP Status
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		info.SIPEnabled = strings.Contains(string(out), "enabled")
	}

	// Gatekeeper
	if out, err := exec.Command("spctl", "--status").Output(); err == nil {
		if strings.Contains(string(out), "enabled") {
			info.Gatekeeper = "enabled"
		} else {
			info.Gatekeeper = "disabled"
		}
	}

	// FileVault
	if out, err := exec.Command("fdesetup", "status").Output(); err == nil {
		if strings.Contains(string(out), "FileVault is On") {
			info.FileVault = "enabled"
		} else {
			info.FileVault = "disabled"
		}
	}

	// Firewall
	if out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output(); err == nil {
		if strings.Contains(string(out), "enabled") {
			info.Firewall = "enabled"
		} else {
			info.Firewall = "disabled"
		}
	}

	return info
}

// ============================================================================
// PHASE 5: SECURITY AUDIT
// ============================================================================

func runSecurityAudit() {
	result := SecurityAuditResult{
		Action:    "security_audit",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	var checks []AuditCheck
	score := 0
	maxScore := 0

	// Check 1: SIP
	maxScore += 20
	sipCheck := AuditCheck{Name: "System Integrity Protection", Description: "Prevents unauthorized code modifications"}
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		if strings.Contains(string(out), "enabled") {
			sipCheck.Status = "PASS"
			sipCheck.Value = "Enabled"
			score += 20
		} else {
			sipCheck.Status = "FAIL"
			sipCheck.Value = "Disabled"
			sipCheck.Fix = "Boot to Recovery Mode and run: csrutil enable"
		}
	} else {
		sipCheck.Status = "WARN"
		sipCheck.Value = "Unable to check"
	}
	checks = append(checks, sipCheck)

	// Check 2: Gatekeeper
	maxScore += 15
	gkCheck := AuditCheck{Name: "Gatekeeper", Description: "Verifies downloaded applications"}
	if out, err := exec.Command("spctl", "--status").Output(); err == nil {
		if strings.Contains(string(out), "enabled") {
			gkCheck.Status = "PASS"
			gkCheck.Value = "Enabled"
			score += 15
		} else {
			gkCheck.Status = "FAIL"
			gkCheck.Value = "Disabled"
			gkCheck.Fix = "sudo spctl --master-enable"
		}
	}
	checks = append(checks, gkCheck)

	// Check 3: FileVault
	maxScore += 20
	fvCheck := AuditCheck{Name: "FileVault Encryption", Description: "Full disk encryption"}
	if out, err := exec.Command("fdesetup", "status").Output(); err == nil {
		if strings.Contains(string(out), "FileVault is On") {
			fvCheck.Status = "PASS"
			fvCheck.Value = "Enabled"
			score += 20
		} else {
			fvCheck.Status = "WARN"
			fvCheck.Value = "Disabled"
			fvCheck.Fix = "Enable in System Preferences > Security & Privacy > FileVault"
		}
	}
	checks = append(checks, fvCheck)

	// Check 4: Firewall
	maxScore += 15
	fwCheck := AuditCheck{Name: "Application Firewall", Description: "Blocks unwanted incoming connections"}
	if out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output(); err == nil {
		if strings.Contains(string(out), "enabled") {
			fwCheck.Status = "PASS"
			fwCheck.Value = "Enabled"
			score += 15
		} else {
			fwCheck.Status = "FAIL"
			fwCheck.Value = "Disabled"
			fwCheck.Fix = "sudo sentinel --fix-firewall"
		}
	}
	checks = append(checks, fwCheck)

	// Check 5: Automatic Updates
	maxScore += 10
	auCheck := AuditCheck{Name: "Automatic Updates", Description: "Keeps system patched"}
	if out, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "1" {
			auCheck.Status = "PASS"
			auCheck.Value = "Enabled"
			score += 10
		} else {
			auCheck.Status = "WARN"
			auCheck.Value = "Disabled"
			auCheck.Fix = "Enable in System Preferences > Software Update"
		}
	} else {
		auCheck.Status = "WARN"
		auCheck.Value = "Unable to check"
	}
	checks = append(checks, auCheck)

	// Check 6: Remote Login (SSH)
	maxScore += 10
	sshCheck := AuditCheck{Name: "Remote Login (SSH)", Description: "SSH access to this machine"}
	if out, err := exec.Command("systemsetup", "-getremotelogin").Output(); err == nil {
		if strings.Contains(string(out), "Off") {
			sshCheck.Status = "PASS"
			sshCheck.Value = "Disabled"
			score += 10
		} else {
			sshCheck.Status = "WARN"
			sshCheck.Value = "Enabled (potential risk)"
			sshCheck.Fix = "Disable if not needed: sudo systemsetup -setremotelogin off"
		}
	}
	checks = append(checks, sshCheck)

	// Check 7: Screen Lock
	maxScore += 10
	slCheck := AuditCheck{Name: "Screen Lock on Sleep", Description: "Requires password after sleep"}
	if out, err := exec.Command("defaults", "read", "com.apple.screensaver", "askForPassword").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "1" {
			slCheck.Status = "PASS"
			slCheck.Value = "Enabled"
			score += 10
		} else {
			slCheck.Status = "WARN"
			slCheck.Value = "Disabled"
			slCheck.Fix = "Enable in System Preferences > Security & Privacy"
		}
	} else {
		slCheck.Status = "WARN"
		slCheck.Value = "Unable to check"
	}
	checks = append(checks, slCheck)

	// Calculate overall status
	pct := (score * 100) / maxScore
	status := "SECURE"
	if pct < 60 {
		status = "CRITICAL"
	} else if pct < 80 {
		status = "WARNING"
	}

	result.Success = true
	result.Checks = checks
	result.Score = pct
	result.OverallStatus = status
	outputJSON(result)
}

// ============================================================================
// PHASE 5: SERVICES
// ============================================================================

func getServices() {
	result := ServiceResult{
		Action: "list_services",
	}

	var services []ServiceInfo

	// Get LaunchDaemons
	daemonDirs := []string{
		"/Library/LaunchDaemons",
		"/System/Library/LaunchDaemons",
	}

	for _, dir := range daemonDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".plist") {
				label := strings.TrimSuffix(f.Name(), ".plist")
				status := "unknown"
				pid := 0

				// Check if running
				out, err := exec.Command("launchctl", "list", label).Output()
				if err == nil {
					status = "loaded"
					// Try to parse PID
					lines := strings.Split(string(out), "\n")
					for _, line := range lines {
						if strings.Contains(line, "PID") {
							parts := strings.Fields(line)
							if len(parts) >= 3 {
								pid, _ = strconv.Atoi(parts[2])
							}
						}
					}
				} else {
					status = "not loaded"
				}

				services = append(services, ServiceInfo{
					Name:   f.Name(),
					Label:  label,
					Status: status,
					PID:    pid,
					Type:   "LaunchDaemon",
					Path:   filepath.Join(dir, f.Name()),
				})
			}
		}
	}

	result.Success = true
	result.Services = services
	outputJSON(result)
}

func restartService(label string) {
	result := ServiceResult{
		Action:  "restart_service",
		Service: label,
	}

	// Stop the service
	stopCmd := exec.Command("launchctl", "stop", label)
	if out, err := stopCmd.CombinedOutput(); err != nil {
		// Service might not be running, that's ok
		_ = out
	}

	// Start the service
	startCmd := exec.Command("launchctl", "start", label)
	if out, err := startCmd.CombinedOutput(); err != nil {
		result.Error = fmt.Sprintf("Failed to start service: %v - %s", err, string(out))
		result.ErrorCode = "SERVICE_START_FAILED"
		result.Fix = "Check if service exists: launchctl list | grep " + label
		outputJSON(result)
		os.Exit(1)
	}

	result.Success = true
	outputJSON(result)
	fmt.Fprintf(os.Stderr, "✅ Service %s restarted\n", label)
}

// ============================================================================
// PHASE 5: CHECK UPDATES
// ============================================================================

func checkForUpdates() {
	result := UpdateResult{
		Action: "check_updates",
	}

	// Get OS version
	hostInfo, _ := host.Info()

	result.Info.OSVersion = hostInfo.PlatformVersion
	result.Info.LastChecked = time.Now().Format(time.RFC3339)

	// Run softwareupdate to check for updates
	cmd := exec.Command("softwareupdate", "--list")
	out, err := cmd.CombinedOutput()

	if err != nil {
		// softwareupdate returns exit code 0 even when no updates,
		// but might fail for other reasons
		if !strings.Contains(string(out), "No new software available") {
			result.Error = fmt.Sprintf("Failed to check updates: %v", err)
			result.ErrorCode = "UPDATE_CHECK_FAILED"
			outputJSON(result)
			os.Exit(1)
		}
	}

	output := string(out)

	// Parse updates
	var updates []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "* Label:") || strings.HasPrefix(line, "* ") {
			update := strings.TrimPrefix(line, "* Label:")
			update = strings.TrimPrefix(update, "* ")
			update = strings.TrimSpace(update)
			if update != "" {
				updates = append(updates, update)
			}
		}
	}

	result.Success = true
	result.Info.Available = len(updates) > 0
	result.Info.Updates = updates
	outputJSON(result)
}
