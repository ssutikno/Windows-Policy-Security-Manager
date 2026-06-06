package enroll

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/user/wwpo/client-agent-go/config"
	"github.com/user/wwpo/client-agent-go/metadata"
)

type EnrollRequest struct {
	SetupToken  string `json:"setup_token"`
	MachineUUID string `json:"machine_uuid"`
	Hostname    string `json:"hostname"`
	OSVersion   string `json:"os_version"`
}

type EnrollResponse struct {
	AgentID             string `json:"agent_id"`
	ConnectionSecret    string `json:"connection_secret"`
	Workgroup           string `json:"workgroup"`
	PingIntervalSeconds int    `json:"ping_interval_seconds"`
}

func EnrollAsync(cfg *config.AgentConfig) (bool, error) {
	if cfg.SetupToken == "" || cfg.SetupToken == "ENTER_TOKEN_HERE" {
		return false, fmt.Errorf("setup token is empty or unpopulated")
	}

	enrollUrl := fmt.Sprintf("http://%s:8080/api/v1/enroll", cfg.MasterIP)
	fmt.Printf("[ENROLL] Contacting Master node at: %s...\n", enrollUrl)

	reqPayload := EnrollRequest{
		SetupToken:  cfg.SetupToken,
		MachineUUID: metadata.GetMachineUUID(),
		Hostname:    metadata.GetHostname(),
		OSVersion:   metadata.GetOSVersion(),
	}

	jsonBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Bypass TLS verification to support self-signed certificates in local workgroup environments
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	resp, err := client.Post(enrollUrl, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return false, fmt.Errorf("enrollment transport failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errMsg string
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		errMsg = buf.String()
		return false, fmt.Errorf("master server rejected enrollment (HTTP %d): %s", resp.StatusCode, errMsg)
	}

	var res EnrollResponse
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	// Save registration details
	cfg.AgentID = res.AgentID
	cfg.ConnectionSecret = res.ConnectionSecret
	cfg.Workgroup = res.Workgroup
	cfg.SetupToken = "" // Clear setup token upon enrollment success

	err = config.SaveConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to save enrolled configuration: %w", err)
	}

	fmt.Printf("[ENROLL] Successfully registered! Agent ID: %s, Workgroup: %s\n", cfg.AgentID, cfg.Workgroup)
	return true, nil
}
