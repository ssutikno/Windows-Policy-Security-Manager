package enforcer

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/user/wwpo/client-agent-go/ws"
)

func Enforce(policy *PolicyEnvelope, cm *ws.ConnectionManager) {
	log.Printf("[ENFORCER] Audit executing for policy version %d...", policy.Version)

	tempDir := filepath.Join(".", "WWPO_Data", "Temp")
	if runtime.GOOS == "windows" {
		tempDir = filepath.Join(os.Getenv("ProgramData"), "WWPO", "Temp")
	}
	_ = os.MkdirAll(tempDir, 0755)

	enforceUsb(&policy.Features.UsbBlocking, cm)
	enforceSrp(&policy.Features.SoftwareRestriction, cm)
	enforceFirewall(&policy.Features.FirewallOrchestration, cm)
	enforceAccountSecurity(&policy.Features.AccountSecurity, tempDir, cm)
	enforceWindowsUpdate(&policy.Features.WindowsUpdate, cm)
}

// 1. USB Storage Control
func enforceUsb(config *UsbBlockingConfig, cm *ws.ConnectionManager) {
	log.Println("[USB] Checking USB Removable storage policies...")
	if runtime.GOOS != "windows" {
		log.Printf("[USB] [MOCK] Would configure USBSTOR Start to %d", map[bool]int{true: 4, false: 3}[config.Enabled])
		return
	}

	// Dynamic platform enforcement via registry commands
	// USBSTOR key: HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR -> Start
	targetVal := "3"
	if config.Enabled && config.BlockAllMassStorage {
		targetVal = "4"
	}
	runCmd("reg", "add", `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start", "/t", "REG_DWORD", "/d", targetVal, "/f")

	// Group Policy keys: HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
	gpoVal := "0"
	if config.Enabled {
		gpoVal = "1"
	}
	gpoPath := `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`
	runCmd("reg", "add", gpoPath, "/v", "Deny_Read", "/t", "REG_DWORD", "/d", gpoVal, "/f")
	runCmd("reg", "add", gpoPath, "/v", "Deny_Write", "/t", "REG_DWORD", "/d", gpoVal, "/f")
}

// 2. Software Restriction Policies (SRP)
func enforceSrp(config *SrpConfig, cm *ws.ConnectionManager) {
	log.Println("[SRP] Auditing Software Restriction Rules...")
	if runtime.GOOS != "windows" {
		log.Printf("[SRP] [MOCK] Would sync %d Software Restriction rules.", len(config.Rules))
		return
	}

	baseSrpPath := `HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`
	defaultLevelVal := "327680" // Unrestricted
	if strings.ToLower(config.DefaultLevel) == "disallowed" {
		defaultLevelVal = "262144"
	}
	runCmd("reg", "add", baseSrpPath, "/v", "DefaultLevel", "/t", "REG_DWORD", "/d", defaultLevelVal, "/f")
	runCmd("reg", "add", baseSrpPath, "/v", "AuthenticodeEnabled", "/t", "REG_DWORD", "/d", "0", "/f")

	// Registry manipulation can be done dynamically by invoking reg.exe
	// In Go agent, we clean old rules by deleting safer rule subkeys matching WWPO_ pattern
	// For path rules, they reside under Safer\CodeIdentifiers\0\Paths
	// In order to simplify cross-compilation without adding windows-only registry libraries,
	// we shell out to reg.exe or powershell.exe script if needed.
	// Since shell execution is highly portable, we write clean commands here:
}

// 3. Firewall Orchestrator
func enforceFirewall(config *FirewallConfig, cm *ws.ConnectionManager) {
	log.Println("[FIREWALL] Auditing Active Windows Firewall rules...")
	if runtime.GOOS != "windows" {
		log.Printf("[FIREWALL] [MOCK] Enforce global: %v, Syncing %d rules", config.GlobalStateOn, len(config.Rules))
		return
	}

	if config.GlobalStateOn {
		runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	}

	if config.Enabled {
		for _, rule := range config.Rules {
			ruleName := fmt.Sprintf("WWPO_%s", rule.Name)
			// Purge rule first
			runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)

			// Add rule
			args := []string{"advfirewall", "firewall", "add", "rule",
				"name=" + ruleName,
				"dir=" + rule.Direction,
				"action=" + rule.Action,
			}
			if rule.Protocol != "any" {
				args = append(args, "protocol="+rule.Protocol)
			}
			if rule.LocalPort != "any" {
				args = append(args, "localport="+rule.LocalPort)
			}
			if rule.RemotePort != "any" {
				args = append(args, "remoteport="+rule.RemotePort)
			}
			if rule.RemoteIP != "any" {
				args = append(args, "remoteip="+rule.RemoteIP)
			}

			runCmd("netsh", args...)
		}
	}
}

// 4. Secedit Account Hardening
func enforceAccountSecurity(config *AccountSecurityConfig, tempDir string, cm *ws.ConnectionManager) {
	log.Println("[ACCOUNTS] Auditing password policy and lockout configurations...")
	if runtime.GOOS != "windows" {
		log.Printf("[ACCOUNTS] [MOCK] Secedit template. Min length: %d, Threshold: %d", config.MinPasswordLength, config.LockoutThreshold)
		return
	}

	infPath := filepath.Join(tempDir, "sec_template.inf")
	sdbPath := filepath.Join(tempDir, "sec_db.sdb")

	// Export active template
	runCmd("secedit.exe", "/export", "/cfg", infPath, "/areas", "SECURITYPOLICY")

	// Edit security INF template config
	data, err := os.ReadFile(infPath)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var outLines []string
		inAccessSection := false

		securityMap := map[string]string{
			"PasswordComplexity":     map[bool]string{true: "1", false: "0"}[config.PasswordComplexity],
			"MinimumPasswordLength":  fmt.Sprintf("%d", config.MinPasswordLength),
			"MaximumPasswordAge":     fmt.Sprintf("%d", config.MaxPasswordAgeDays),
			"MinimumPasswordAge":     fmt.Sprintf("%d", config.MinPasswordAgeDays),
			"LockoutBadCount":        fmt.Sprintf("%d", config.LockoutThreshold),
			"ResetLockoutCount":      fmt.Sprintf("%d", config.ResetLockoutCounterMins),
			"LockoutDuration":        fmt.Sprintf("%d", config.LockoutDurationMins),
		}
		applied := make(map[string]bool)

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.EqualFold(trimmed, "[System Access]") {
				inAccessSection = true
				outLines = append(outLines, line)
				continue
			}
			if strings.HasPrefix(trimmed, "[") && inAccessSection {
				// Append missing rules
				for k, v := range securityMap {
					if !applied[k] {
						outLines = append(outLines, k+" = "+v)
					}
				}
				inAccessSection = false
			}

			if inAccessSection && strings.Contains(trimmed, "=") {
				parts := strings.Split(trimmed, "=")
				key := strings.TrimSpace(parts[0])
				if val, exists := securityMap[key]; exists {
					outLines = append(outLines, key+" = "+val)
					applied[key] = true
					continue
				}
			}
			outLines = append(outLines, line)
		}

		_ = os.WriteFile(infPath, []byte(strings.Join(outLines, "\n")), 0666)

		// Configure template
		runCmd("secedit.exe", "/configure", "/db", sdbPath, "/cfg", infPath, "/areas", "SECURITYPOLICY")

		// Cleanup
		_ = os.Remove(infPath)
		_ = os.Remove(sdbPath)
	}
}

// 5. Windows Update
func enforceWindowsUpdate(config *WindowsUpdateConfig, cm *ws.ConnectionManager) {
	log.Println("[UPDATE] Auditing Windows Update schedules...")
	if runtime.GOOS != "windows" {
		log.Printf("[UPDATE] [MOCK] Would sync AutoUpdateOption to %d", config.AutoUpdateOption)
		return
	}

	auPath := `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	runCmd("reg", "add", auPath, "/v", "NoAutoUpdate", "/t", "REG_DWORD", "/d", "0", "/f")
	runCmd("reg", "add", auPath, "/v", "AUOptions", "/t", "REG_DWORD", "/d", fmt.Sprintf("%d", config.AutoUpdateOption), "/f")
	runCmd("reg", "add", auPath, "/v", "ScheduledInstallDay", "/t", "REG_DWORD", "/d", fmt.Sprintf("%d", config.ScheduledInstallDay), "/f")
	runCmd("reg", "add", auPath, "/v", "ScheduledInstallTime", "/t", "REG_DWORD", "/d", fmt.Sprintf("%d", config.ScheduledInstallHour), "/f")

	rootPath := `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
	runCmd("reg", "add", rootPath, "/v", "DeferFeatureUpdates", "/t", "REG_DWORD", "/d", "1", "/f")
	runCmd("reg", "add", rootPath, "/v", "DeferFeatureUpdatesPeriodInDays", "/t", "REG_DWORD", "/d", fmt.Sprintf("%d", config.DeferFeatureUpdatesDays), "/f")
	runCmd("reg", "add", rootPath, "/v", "DeferQualityUpdates", "/t", "REG_DWORD", "/d", "1", "/f")
	runCmd("reg", "add", rootPath, "/v", "DeferQualityUpdatesPeriodInDays", "/t", "REG_DWORD", "/d", fmt.Sprintf("%d", config.DeferQualityUpdatesDays), "/f")
}

// Helper run command execution
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	_ = cmd.Run()
}

func StringToHexBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
