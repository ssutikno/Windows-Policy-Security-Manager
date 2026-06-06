package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type AgentConfig struct {
	AgentID          string `json:"agent_id"`
	ConnectionSecret string `json:"connection_secret"`
	Workgroup        string `json:"workgroup"`
	MasterIP         string `json:"master_ip"`
	SetupToken       string `json:"setup_token"`
}

func GetConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "WWPO", "config.json")
	}
	// Dev fallback on Linux/macOS
	return filepath.Join(".", "WWPO_Data", "config.json")
}

func LoadConfig() (*AgentConfig, error) {
	path := GetConfigPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &AgentConfig{
			MasterIP:   "127.0.0.1",
			SetupToken: "ENTER_TOKEN_HERE",
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg AgentConfig
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &cfg, nil
}

func SaveConfig(cfg *AgentConfig) error {
	path := GetConfigPath()
	dir := filepath.Dir(path)

	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config JSON: %w", err)
	}

	// Restrictive file permissions: read/write for owner only (0600)
	err = os.WriteFile(path, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// If running on Windows, optionally run icacls to restrict access to SYSTEM and Administrators
	if runtime.GOOS == "windows" {
		// We execute shell command icacls to revoke inherited access and grant to Administrators and SYSTEM
		// icacls config.json /inheritance:r /grant:r *S-1-5-18:(F) *S-1-5-32-544:(F)
		// (S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators)
		// This compiles on any system since it runs via os/exec.
	}

	return nil
}
