package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/user/wwpo/master-backend/db"
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

type TokenGenRequest struct {
	Workgroup       string `json:"workgroup"`
	DurationMinutes int    `json:"duration_minutes"`
}

// GenerateSecret creates a cryptographically strong, 32-byte connection secret.
func GenerateSecret() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// EnrollAgentHandler manages HTTPS POST agent enrollment.
func EnrollAgentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EnrollRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.SetupToken == "" || req.MachineUUID == "" || req.Hostname == "" {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// 1. Validate setup token and resolve target Workgroup
	workgroup, err := db.ValidateSetupToken(req.SetupToken)
	if err != nil {
		log.Printf("Enrollment failed for host %s: %v", req.Hostname, err)
		http.Error(w, "Unauthorized setup token: "+err.Error(), http.StatusForbidden)
		return
	}

	// 2. Extract agent source IP address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	// Check for standard proxy headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		ip = strings.TrimSpace(ips[0])
	}

	// 3. Generate high-entropy Connection Secret
	secret, err := GenerateSecret()
	if err != nil {
		log.Printf("Internal error generating secret: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Register agent in SQLite DB
	agent := &db.Agent{
		Workgroup:        workgroup,
		MachineUUID:      req.MachineUUID,
		Hostname:         req.Hostname,
		IPAddress:        ip,
		OSVersion:        req.OSVersion,
		ConnectionSecret: secret,
	}

	err = db.RegisterOrUpdateAgent(agent)
	if err != nil {
		log.Printf("Failed to register agent in DB: %v", err)
		http.Error(w, "Internal database error", http.StatusInternalServerError)
		return
	}

	// 5. Log security event
	event := &db.SecurityEvent{
		AgentID:   agent.AgentID,
		EventType: "INFO",
		Message:   "Successfully enrolled agent in Workgroup: " + workgroup,
	}
	_ = db.LogEvent(event)

	// 6. Return connection keys to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(EnrollResponse{
		AgentID:             agent.AgentID,
		ConnectionSecret:    secret,
		Workgroup:           workgroup,
		PingIntervalSeconds: 30,
	})
}

// GenerateTokenHandler exposes a protected endpoint to create setup tokens.
func GenerateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenGenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Workgroup == "" {
		http.Error(w, "Invalid token config payload", http.StatusBadRequest)
		return
	}

	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 120 // Default to 2 hours
	}

	token, err := db.GenerateSetupToken(req.Workgroup, req.DurationMinutes)
	if err != nil {
		log.Printf("Failed to generate setup token: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(token)
}

// ListAgentsHandler returns the list of all registered endpoints
func ListAgentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents, err := db.ListAgents()
	if err != nil {
		log.Printf("Failed to query agents: %v", err)
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(agents)
}

// ListEventsHandler returns recent compliance events logged by agents
func ListEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	events, err := db.ListEvents()
	if err != nil {
		log.Printf("Failed to query events: %v", err)
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(events)
}

// DeployPolicyHandler saves policy config and broadcasts to online agents
func DeployPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	workgroup, ok := reqBody["workgroup"].(string)
	if !ok || workgroup == "" {
		http.Error(w, "Missing workgroup string", http.StatusBadRequest)
		return
	}

	versionFloat, ok := reqBody["version"].(float64)
	if !ok {
		http.Error(w, "Missing or invalid policy version", http.StatusBadRequest)
		return
	}
	version := int(versionFloat)

	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		http.Error(w, "Failed to serialize policy", http.StatusInternalServerError)
		return
	}
	payloadStr := string(payloadBytes)

	// Save policy to database
	policy := &db.Policy{
		Workgroup:     workgroup,
		Version:       version,
		PolicyPayload: payloadStr,
		CreatedBy:     "admin",
	}

	err = db.SavePolicy(policy)
	if err != nil {
		log.Printf("Failed to save policy: %v", err)
		http.Error(w, "Database error saving policy", http.StatusInternalServerError)
		return
	}

	// Broadcast policy via active WebSockets
	// Note: ConnectWebSocketHandler manages ActiveConnections. We reference it by importing or calling local functions
	activeCount := BroadcastPolicyToWorkgroup(workgroup, payloadStr)

	log.Printf("Deployed policy version %d to workgroup %s. Broadcasted to %d active agent(s).", version, workgroup, activeCount)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"success","broadcast_count":%d,"message":"Policy deployed successfully."}`, activeCount)))
}

// GetPolicyHandler retrieves the latest policy configuration for a workgroup
func GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workgroup := r.URL.Query().Get("workgroup")
	if workgroup == "" {
		http.Error(w, "Missing workgroup query parameter", http.StatusBadRequest)
		return
	}

	policy, err := db.GetLatestPolicyForWorkgroup(workgroup)
	if err != nil {
		// Return empty policy configuration if none exists
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(policy.PolicyPayload))
}
