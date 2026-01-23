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
	"strconv"
	"strings"
	"syscall"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/shirou/gopsutil/v4/cpu"
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

const (
	Version           = "1.1.0"
	DefaultConfigPath = "/etc/sentinel/config.yaml"
	SentinelPFAnchor  = "com.sentinel"
	SentinelPFConf    = "/etc/pf.anchors/com.sentinel"
)

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
