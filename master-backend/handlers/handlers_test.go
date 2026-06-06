package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/user/wwpo/master-backend/db"
)

func TestEnrollAgentHandler(t *testing.T) {
	dbPath := "./test_handlers_wwpo.db"
	err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test DB: %v", err)
	}
	defer os.Remove(dbPath)

	// 1. Generate a valid token
	token, err := db.GenerateSetupToken("HR_DEPT", 30)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 2. Prepare mock enrollment POST request
	enrollReq := EnrollRequest{
		SetupToken:  token.Value,
		MachineUUID: "mock-machine-uuid-99999",
		Hostname:    "HR-DESKTOP-1",
		OSVersion:   "Windows 11 Enterprise",
	}
	reqBytes, _ := json.Marshal(enrollReq)

	req, err := http.NewRequest("POST", "/api/v1/enroll", bytes.NewBuffer(reqBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(EnrollAgentHandler)

	// 3. Serve HTTP
	handler.ServeHTTP(rr, req)

	// Check response status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v, expected %v", status, http.StatusOK)
	}

	// Check response properties
	var resp EnrollResponse
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.AgentID == "" || resp.ConnectionSecret == "" {
		t.Errorf("Invalid credentials returned: %+v", resp)
	}

	if resp.Workgroup != "HR_DEPT" {
		t.Errorf("Workgroup mismatch: expected HR_DEPT, got %s", resp.Workgroup)
	}

	// 4. Test re-enrollment using the same token (should fail 403 Forbidden)
	rr2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/api/v1/enroll", bytes.NewBuffer(reqBytes))
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusForbidden {
		t.Errorf("Expected reused token to fail with 403 Forbidden, but got %d", rr2.Code)
	}
}

func TestWebSocketTelemetry(t *testing.T) {
	dbPath := "./test_ws_telemetry.db"
	err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test DB: %v", err)
	}
	defer os.Remove(dbPath)

	// Register a mock agent
	secret := base64.StdEncoding.EncodeToString([]byte("testsecretkey"))
	agent := &db.Agent{
		AgentID:          "mock-agent-111",
		Workgroup:        "TEST_WG",
		MachineUUID:      "uuid-111",
		Hostname:         "TelemetryHost",
		IPAddress:        "127.0.0.1",
		OSVersion:        "Win 11",
		ConnectionSecret: secret,
	}
	err = db.RegisterOrUpdateAgent(agent)
	if err != nil {
		t.Fatalf("Failed to register agent: %v", err)
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(ConnectWebSocketHandler))
	defer server.Close()

	// Calculate auth params
	nowStr := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte("testsecretkey"))
	mac.Write([]byte(nowStr))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Dial WS
	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/connect?agent_id=mock-agent-111&timestamp=" + nowStr + "&signature=" + url.QueryEscape(sig)
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("Failed to connect via WS: %v", err)
	}
	defer conn.Close()

	// Send telemetry payload
	telemetryMsg := map[string]interface{}{
		"type": "telemetry",
		"payload": map[string]interface{}{
			"firewall_rules": []map[string]string{
				{"name": "Allow_Port_8080", "direction": "in", "action": "allow"},
			},
			"installed_apps": []string{"Firefox", "Docker"},
		},
	}
	msgBytes, _ := json.Marshal(telemetryMsg)
	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Wait briefly for server process to process the message in the websocket loop
	time.Sleep(100 * time.Millisecond)

	// Assert database values
	updatedAgent, err := db.GetAgent("mock-agent-111")
	if err != nil {
		t.Fatalf("Failed to fetch agent: %v", err)
	}

	if !strings.Contains(updatedAgent.InstalledApps, "Firefox") {
		t.Errorf("Expected installed apps to contain Firefox, got %s", updatedAgent.InstalledApps)
	}
	if !strings.Contains(updatedAgent.FirewallRules, "Allow_Port_8080") {
		t.Errorf("Expected firewall rules to contain Allow_Port_8080, got %s", updatedAgent.FirewallRules)
	}
}
