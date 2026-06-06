package db

import (
	"os"
	"testing"
	"time"
)

func TestDBLifecycle(t *testing.T) {
	dbPath := "./test_wwpo.db"
	defer os.Remove(dbPath)

	// 1. Test database initialization
	err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// 2. Test generating setup token
	token, err := GenerateSetupToken("FINANCE_DEPT", 10)
	if err != nil {
		t.Fatalf("GenerateSetupToken failed: %v", err)
	}
	if token.Value == "" || token.Workgroup != "FINANCE_DEPT" {
		t.Errorf("Generated token properties mismatch: %+v", token)
	}

	// 3. Test validating setup token
	wg, err := ValidateSetupToken(token.Value)
	if err != nil {
		t.Fatalf("ValidateSetupToken failed: %v", err)
	}
	if wg != "FINANCE_DEPT" {
		t.Errorf("ValidateSetupToken returned wrong workgroup: %s, expected FINANCE_DEPT", wg)
	}

	// 4. Test validating token again (should fail because it's marked used)
	_, err = ValidateSetupToken(token.Value)
	if err == nil {
		t.Error("Expected validation error for already used token, but got nil")
	}

	// 5. Test agent registration
	agent := &Agent{
		Workgroup:        "FINANCE_DEPT",
		MachineUUID:      "test-uuid-123456",
		Hostname:         "TEST-DESKTOP",
		IPAddress:        "192.168.10.5",
		OSVersion:        "Windows 11 Pro",
		ConnectionSecret: "super-secret-key-123",
	}
	err = RegisterOrUpdateAgent(agent)
	if err != nil {
		t.Fatalf("RegisterOrUpdateAgent failed: %v", err)
	}
	if agent.AgentID == "" {
		t.Error("Expected registered agent to have an ID assigned, got empty string")
	}

	// 6. Test listing agents
	agents, err := ListAgents()
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("Expected 1 registered agent, got %d", len(agents))
	}
	if agents[0].Hostname != "TEST-DESKTOP" {
		t.Errorf("Agent hostname mismatch: expected TEST-DESKTOP, got %s", agents[0].Hostname)
	}

	// 7. Test log security events
	event := &SecurityEvent{
		AgentID:   agent.AgentID,
		EventType: "HEAL_ACTION",
		Message:   "Corrected USB registry drift",
		Timestamp: time.Now(),
	}
	err = LogEvent(event)
	if err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	events, err := ListEvents()
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("Expected 1 logged event, got %d", len(events))
	}
	if events[0].EventType != "HEAL_ACTION" || events[0].AgentID != agent.AgentID {
		t.Errorf("Event properties mismatch: %+v", events[0])
	}
}
