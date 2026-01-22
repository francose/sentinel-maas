package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// --- MaaS DATA STRUCTURES ---
type MaaSUpdate struct {
	AgentID      string       `json:"agent_id"`
	Timestamp    string       `json:"timestamp"`
	ThreatLevel  string       `json:"threat_level"`
	CPULoad      string       `json:"cpu_load"`
	Temperature  string       `json:"temperature"`
	Firewall     string       `json:"firewall_status"`
	NetworkFlows []FlowRecord `json:"flows"`
	SecurityLogs []string     `json:"recent_logs"`
}

type FlowRecord struct {
	PID      int32  `json:"pid"`
	Process  string `json:"process_name"`
	Src      string `json:"source"`
	Dst      string `json:"destination"`
	Status   string `json:"status"`
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
)

func main() {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to init termui: %v", err)
	}
	defer ui.Close()

	// Detect Cores (Dynamic Load Logic)
	counts, _ := cpu.Counts(true)
	if counts == 0 { counts = 2 }
	coreCount = counts

	// --- LAYOUT SETUP ---

	// 1. CPU Sparkline (Top Left)
	slCPU := widgets.NewSparkline()
	slCPU.LineColor = ui.ColorGreen
	slCPU.Title = fmt.Sprintf("CPU Activity (%d Cores)", coreCount)
	slCPUGroup := widgets.NewSparklineGroup(slCPU)
	slCPUGroup.Title = "CPU Load | Init..."
	slCPUGroup.SetRect(0, 0, 50, 10)

	// 2. Hardware Thermal Monitor (Top Right)
	pHardware := widgets.NewParagraph()
	pHardware.Title = "Thermal Status (Fanless)"
	pHardware.Text = "Sensor: Initializing..."
	pHardware.SetRect(50, 0, 75, 10)
	pHardware.TextStyle = ui.NewStyle(ui.ColorWhite)

	// 3. MaaS Status (Top Far Right)
	pMaaS := widgets.NewParagraph()
	pMaaS.Title = "MaaS Agent"
	pMaaS.Text = "Uplink: Starting..."
	pMaaS.SetRect(75, 0, 100, 10)
	pMaaS.TextStyle = ui.NewStyle(ui.ColorGreen)

	// 4. Memory Gauge (Middle Left)
	gMem := widgets.NewGauge()
	gMem.Title = "RAM Usage"
	gMem.SetRect(0, 10, 50, 13)
	gMem.BarColor = ui.ColorCyan

	// 5. Network Stats (Middle Right)
	pNetRate := widgets.NewParagraph()
	pNetRate.Title = "Bandwidth"
	pNetRate.Text = "Rx: ... Tx: ..."
	pNetRate.SetRect(50, 10, 100, 13)

	// 6. Active Network Flows (Bottom Left - The "Zeek" View)
	lNet := widgets.NewList()
	lNet.Title = "Live Network Flows"
	lNet.Rows = []string{"Scanning socket table..."}
	lNet.TextStyle = ui.NewStyle(ui.ColorCyan)
	lNet.SetRect(0, 13, 50, 25)

	// 7. Security Logs (Bottom Right)
	lLogs := widgets.NewList()
	lLogs.Title = "Security Events (Auth)"
	lLogs.Rows = []string{"Watching com.apple.securityd..."}
	lLogs.TextStyle = ui.NewStyle(ui.ColorYellow)
	lLogs.SetRect(50, 13, 100, 25)

	// 8. DOCTOR OVERLAY (Hidden by default)
	pDoctor := widgets.NewParagraph()
	pDoctor.Title = "SENTINEL DOCTOR (Press 'd' to Close)"
	pDoctor.SetRect(10, 4, 90, 22)
	pDoctor.TextStyle = ui.NewStyle(ui.ColorWhite)
	pDoctor.BorderStyle = ui.NewStyle(ui.ColorRed, ui.ColorClear, ui.ModifierBold)
	showDoctor := false

	// --- WORKER GOROUTINES ---

	// A. Security Monitor (Log Stream)
	go func() {
		cmd := exec.Command("log", "stream", "--style", "syslog", "--predicate", "subsystem == \"com.apple.securityd\"", "--info")
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			globalLogs = append(globalLogs, line)
			if len(globalLogs) > 20 { globalLogs = globalLogs[1:] }

			if len(line) > 55 { line = line[:55] + ".." }
			lLogs.Rows = append(lLogs.Rows, line)
			if len(lLogs.Rows) > 12 { lLogs.Rows = lLogs.Rows[1:] }
			
			if !showDoctor { ui.Render(lLogs) }
		}
	}()

	// B. Hardware Monitor (Fanless Specific)
	go func() {
		reTemp := regexp.MustCompile(`(?i)(?:CPU\s+die\s+temperature|SOC\s+M1|Die\s+temp).*?:\s+(\d+\.?\d*)`)

		for {
			out, err := exec.Command("powermetrics", "-n", "1", "--samplers", "smc,thermal").Output()
			if err != nil {
				pHardware.Text = "ERR: Need Sudo"
				if !showDoctor { ui.Render(pHardware) }
				time.Sleep(5 * time.Second)
				continue
			}

			output := string(out)
			tempStr := "??"
			if m := reTemp.FindStringSubmatch(output); len(m) > 1 {
				tempStr = m[1]
			}
			globalTemp = tempStr

			infoText := fmt.Sprintf("Cooling: PASSIVE\nTemp:    %s C", tempStr)
			
			if val, err := strconv.ParseFloat(tempStr, 64); err == nil {
				if val > 88.0 {
					pHardware.TextStyle = ui.NewStyle(ui.ColorRed, ui.ColorClear, ui.ModifierBold)
					infoText += " (HOT!)"
				} else if val > 75.0 {
					pHardware.TextStyle = ui.NewStyle(ui.ColorYellow)
				} else {
					pHardware.TextStyle = ui.NewStyle(ui.ColorGreen)
				}
			}

			pHardware.Text = infoText
			if !showDoctor { ui.Render(pHardware) }
			time.Sleep(2 * time.Second)
		}
	}()

	// C. Network Flow Monitor (Zeek-Lite)
	go func() {
		for {
			conns, err := net.Connections("inet")
			if err != nil { time.Sleep(2 * time.Second); continue }

			var flows []FlowRecord
			var uiRows []string
			
			count := 0
			for _, c := range conns {
				if count > 12 { break } // Limit UI lines
				if c.Status == "ESTABLISHED" || c.Status == "LISTEN" {
					
					procName := "?"
					if c.Pid > 0 {
						if p, err := process.NewProcess(c.Pid); err == nil {
							n, _ := p.Name()
							if n != "" { procName = n }
						}
					}

					if len(procName) > 10 { procName = procName[:10] }

					rec := FlowRecord{
						PID:      c.Pid,
						Process:  procName,
						Src:      fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
						Dst:      fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
						Status:   c.Status,
					}
					flows = append(flows, rec)
					
					row := fmt.Sprintf("[%d] %s: %s->%s", c.Pid, procName, rec.Src, rec.Dst)
					uiRows = append(uiRows, row)
					count++
				}
			}
			globalFlows = flows
			lNet.Rows = uiRows
			if !showDoctor { ui.Render(lNet) }
			time.Sleep(2 * time.Second)
		}
	}()

	// D. MaaS Transmitter
	go func() {
		payloadCount := 0
		for {
			time.Sleep(10 * time.Second)
			
			payload := MaaSUpdate{
				AgentID:      "SENTINEL-MAC-01",
				Timestamp:    time.Now().Format(time.RFC3339),
				ThreatLevel:  globalThreat,
				CPULoad:      fmt.Sprintf("%.2f", globalLoad),
				Temperature:  globalTemp,
				Firewall:     globalFirewall,
				NetworkFlows: globalFlows,
				SecurityLogs: globalLogs,
			}

			jsonData, _ := json.Marshal(payload)
			payloadCount++
			
			pMaaS.Text = fmt.Sprintf("Status: ACTIVE\nSent:   %d\nSize:   %d B", 
				payloadCount, len(jsonData))
			if !showDoctor { ui.Render(pMaaS) }
		}
	}()

	// --- MAIN LOOP ---
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(1 * time.Second).C
	var lastRx, lastTx uint64

	for {
		select {
		case e := <-uiEvents:
			if e.ID == "q" || e.ID == "<C-c>" { return }

			// DOCTOR KEY ('d')
			if e.ID == "d" {
				if showDoctor {
					showDoctor = false
					// Force full redraw
					ui.Render(slCPUGroup, pHardware, pMaaS, gMem, pNetRate, lNet, lLogs)
				} else {
					showDoctor = true
					
					report := fmt.Sprintf("SENTINEL DIAGNOSIS [%s]\n", time.Now().Format("15:04:05"))
					report += strings.Repeat("-", 50) + "\n"
					
					report += fmt.Sprintf("LOAD AVG: %.2f (Cores: %d)\n", globalLoad, coreCount)
					if globalLoad > float64(coreCount) {
						report += "  [!] SYSTEM LAG DETECTED\n"
					} else {
						report += "  [OK] System is responsive\n"
					}

					tVal, _ := strconv.ParseFloat(globalTemp, 64)
					report += fmt.Sprintf("THERMAL:  %s C\n", globalTemp)
					if tVal > 88.0 {
						report += "  [!] THROTTLING ACTIVE\n"
					}

					snap := MaaSUpdate{
						AgentID: "SENTINEL-DOCTOR",
						Timestamp: time.Now().Format(time.RFC3339),
						CPULoad: fmt.Sprintf("%.2f", globalLoad),
						Temperature: globalTemp,
						SecurityLogs: globalLogs,
					}
					f, _ := json.MarshalIndent(snap, "", " ")
					_ = os.WriteFile("sentinel_dump.json", f, 0644)
					report += "\n[JSON Snapshot saved for AI Analysis]"
					
					pDoctor.Text = report
					ui.Render(pDoctor)
				}
			}

		case <-ticker:
			if showDoctor { continue }

			c, _ := cpu.Percent(0, false)
			if len(c) > 0 {
				slCPU.Data = append(slCPU.Data, float64(c[0]))
				if len(slCPU.Data) > 50 { slCPU.Data = slCPU.Data[1:] }
			}
			l, _ := load.Avg()
			globalLoad = l.Load1
			slCPUGroup.Title = fmt.Sprintf("CPU Load | Avg: %.2f", globalLoad)

			v, _ := mem.VirtualMemory()
			s, _ := mem.SwapMemory()
			gMem.Percent = int(v.UsedPercent)
			if s.Used > 0 {
				gMem.Label = fmt.Sprintf("%d%% (Swap: %.1fG)", int(v.UsedPercent), float64(s.Used)/1024/1024/1024)
				gMem.BarColor = ui.ColorYellow
			} else {
				gMem.Label = fmt.Sprintf("%d%%", int(v.UsedPercent))
				gMem.BarColor = ui.ColorCyan
			}

			n, _ := net.IOCounters(false)
			if len(n) > 0 {
				rx := n[0].BytesRecv
				tx := n[0].BytesSent
				if lastRx != 0 {
					pNetRate.Text = fmt.Sprintf("Dn: %d KB/s  Up: %d KB/s", (rx-lastRx)/1024, (tx-lastTx)/1024)
				}
				lastRx = rx
				lastTx = tx
			}

			ui.Render(slCPUGroup, pHardware, pMaaS, gMem, pNetRate, lNet, lLogs)
		}
	}
}