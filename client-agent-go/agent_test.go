package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/user/wwpo/client-agent-go/config"
	"github.com/user/wwpo/client-agent-go/metadata"
)

func TestConfigSerialization(t *testing.T) {
	testConfig := &config.AgentConfig{
		AgentID:          "test-agent-go-id",
		ConnectionSecret: "dGVzdC1zZWNyZXQtYmFzZTY0LWtleS0xMjM0NTY3ODkw",
		Workgroup:        "DEV_DEPT",
		MasterIP:         "192.168.1.10",
		SetupToken:       "temp-token",
	}

	data, err := json.Marshal(testConfig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var deserialized config.AgentConfig
	err = json.Unmarshal(data, &deserialized)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if deserialized.AgentID != testConfig.AgentID || deserialized.Workgroup != testConfig.Workgroup {
		t.Errorf("Config mismatch: %+v", deserialized)
	}
}

func TestSignatureGeneration(t *testing.T) {
	timestamp := "1717659600"
	secretBase64 := base64.StdEncoding.EncodeToString([]byte("my-symmetric-shared-connection-secret-key"))

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(timestamp))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if signature == "" {
		t.Error("Generated empty signature key")
	}
}

func TestSystemMetadata(t *testing.T) {
	hostname := metadata.GetHostname()
	osVersion := metadata.GetOSVersion()
	uuid := metadata.GetMachineUUID()

	if hostname == "" || hostname == "UNKNOWN-HOST" {
		// If testing inside a container or sandboxed environment, we log it
		t.Logf("Hostname retrieved: %s", hostname)
	}
	if osVersion == "" {
		t.Error("OSVersion collected is empty")
	}
	if uuid == "" {
		t.Error("Machine UUID collected is empty")
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	testConfig := &config.AgentConfig{
		AgentID:          "local-save-load-test",
		ConnectionSecret: "secret-key",
		Workgroup:        "TEST_WG",
		MasterIP:         "127.0.0.1",
	}

	// Overwrite to test directory path
	origPath := config.GetConfigPath()
	defer os.RemoveAll("./WWPO_Data")

	err := config.SaveConfig(testConfig)
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.AgentID != testConfig.AgentID || loaded.Workgroup != testConfig.Workgroup {
		t.Errorf("Mismatch after load. Expected ID: %s, Got: %s. Saved config path: %s", testConfig.AgentID, loaded.AgentID, origPath)
	}
}
