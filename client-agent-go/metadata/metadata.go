package metadata

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "UNKNOWN-HOST"
	}
	return name
}

func GetOSVersion() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/c", "ver").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return "Windows (Unknown Version)"
	}

	// Linux fallback OS version
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				return val + " (" + runtime.GOARCH + ")"
			}
		}
	}
	return runtime.GOOS + " (" + runtime.GOARCH + ")"
}

func GetMachineUUID() string {
	if runtime.GOOS == "windows" {
		// Exec query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err == nil {
			lines := strings.Split(string(out), "\r\n")
			for _, line := range lines {
				if strings.Contains(line, "MachineGuid") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						return parts[2]
					}
				}
			}
		}
	} else if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			return strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	// Dynamic MAC address backup UUID
	return getFallbackMACUUID()
}

func getFallbackMACUUID() string {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
				macStr := iface.HardwareAddr.String()
				hash := sha256.Sum256([]byte(macStr))
				return hex.EncodeToString(hash[:16])
			}
		}
	}
	return "00000000-0000-0000-0000-000000000000"
}
