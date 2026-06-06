package enforcer

import (
	"encoding/json"
	"log"
	"os/exec"
	"runtime"
	"strings"
)

type TelemetryPayload struct {
	FirewallRules []FirewallRule `json:"firewall_rules"`
	InstalledApps []string       `json:"installed_apps"`
}

func CollectTelemetry() *TelemetryPayload {
	return &TelemetryPayload{
		FirewallRules: collectFirewallRules(),
		InstalledApps: collectInstalledApps(),
	}
}

func collectFirewallRules() []FirewallRule {
	if runtime.GOOS != "windows" {
		// Mock firewall rules for development on Linux/macOS
		return []FirewallRule{
			{Name: "Allow_SSH", Direction: "in", Action: "allow", Protocol: "TCP", LocalPort: "22", RemoteIP: "any"},
			{Name: "Allow_HTTP", Direction: "in", Action: "allow", Protocol: "TCP", LocalPort: "80", RemoteIP: "any"},
			{Name: "Block_SMB", Direction: "in", Action: "block", Protocol: "TCP", LocalPort: "445", RemoteIP: "any"},
		}
	}

	// Windows PowerShell Query
	cmd := exec.Command("powershell", "-Command", "Get-NetFirewallRule | Select-Object Name, Direction, Action | ConvertTo-Json")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("[TELEMETRY] Failed to fetch Windows firewall rules: %v", err)
		return []FirewallRule{}
	}

	var rawRules []struct {
		Name      string `json:"Name"`
		Direction int    `json:"Direction"` // 1 = Inbound, 2 = Outbound
		Action    int    `json:"Action"`    // 2 = Allow, 4 = Block
	}

	var rules []FirewallRule
	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		return []FirewallRule{}
	}
	if !strings.HasPrefix(outStr, "[") {
		outStr = "[" + outStr + "]"
	}

	err = json.Unmarshal([]byte(outStr), &rawRules)
	if err == nil {
		for _, r := range rawRules {
			dir := "in"
			if r.Direction == 2 {
				dir = "out"
			}
			act := "allow"
			if r.Action == 4 {
				act = "block"
			}
			rules = append(rules, FirewallRule{
				Name:      r.Name,
				Direction: dir,
				Action:    act,
				Protocol:  "any",
				LocalPort: "any",
				RemoteIP:  "any",
			})
		}
		return rules
	}

	return []FirewallRule{}
}

func collectInstalledApps() []string {
	if runtime.GOOS != "windows" {
		// Mock installed applications list for development on Linux/macOS
		return []string{
			"Google Chrome",
			"Visual Studio Code",
			"Git v2.43.0",
			"Go Compiler v1.21.8",
			"Docker Desktop",
			"Node.js Runtime v20.11",
		}
	}

	// Query Windows registry for installed applications list
	cmd := exec.Command("powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json")
	out, err := cmd.Output()
	if err != nil {
		return []string{}
	}

	var rawApps []struct {
		DisplayName string `json:"DisplayName"`
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		return []string{}
	}
	if !strings.HasPrefix(outStr, "[") {
		outStr = "[" + outStr + "]"
	}

	var apps []string
	err = json.Unmarshal([]byte(outStr), &rawApps)
	if err == nil {
		for _, app := range rawApps {
			trimmedName := strings.TrimSpace(app.DisplayName)
			if trimmedName != "" {
				apps = append(apps, trimmedName)
			}
		}
		return apps
	}

	return []string{}
}
