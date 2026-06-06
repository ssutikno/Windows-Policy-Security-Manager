package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/user/wwpo/master-backend/db"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow cross-origin connections for development
	},
}

// ActiveConnections maps AgentID -> *websocket.Conn
var ActiveConnections sync.Map

// AuthWebSocket checks URL query parameters to authenticate the connection
func AuthWebSocket(w http.ResponseWriter, r *http.Request) (*db.Agent, error) {
	agentID := r.URL.Query().Get("agent_id")
	timestampStr := r.URL.Query().Get("timestamp")
	clientSignature := r.URL.Query().Get("signature")

	if agentID == "" || timestampStr == "" || clientSignature == "" {
		return nil, fmt.Errorf("missing authentication parameters")
	}

	// 1. Validate replay attacks (allow +/- 5 minute skew)
	timestampUnix, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format")
	}
	clientTime := time.Unix(timestampUnix, 0)
	timeDiff := time.Since(clientTime)
	if timeDiff < -5*time.Minute || timeDiff > 5*time.Minute {
		return nil, fmt.Errorf("timestamp out of validation range (potential replay attack)")
	}

	// 2. Query agent secret from database
	agent, err := db.GetAgent(agentID)
	if err != nil {
		return nil, fmt.Errorf("unregistered agent id")
	}

	// 3. Re-calculate HMAC signature
	secretBytes, err := base64.StdEncoding.DecodeString(agent.ConnectionSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding of stored connection secret")
	}

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(timestampStr))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(clientSignature), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid cryptographic signature")
	}

	return agent, nil
}

// ConnectWebSocketHandler upgrades request to WS and routes message flows
func ConnectWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate connection
	agent, err := AuthWebSocket(w, r)
	if err != nil {
		log.Printf("WS Authentication failed: %v", err)
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 2. Upgrade HTTP connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	// 3. Register active socket in concurrent Map
	ActiveConnections.Store(agent.AgentID, conn)
	log.Printf("Agent %s (%s) connected from %s", agent.Hostname, agent.AgentID, conn.RemoteAddr().String())

	// Update agent status in DB
	agent.Status = "online"
	_ = db.RegisterOrUpdateAgent(agent)

	// Clean up registration on disconnect
	defer func() {
		ActiveConnections.Delete(agent.AgentID)
		agent.Status = "offline"
		_ = db.RegisterOrUpdateAgent(agent)
		log.Printf("Agent %s (%s) disconnected", agent.Hostname, agent.AgentID)
	}()

	// 4. Inbound listener loop (keeping connection open & processing pings/events)
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Connection read error for agent %s: %v", agent.AgentID, err)
			break
		}

		if messageType == websocket.TextMessage {
			msgStr := string(payload)
			if msgStr == "ping" {
				// Heartbeat maintenance
				_ = conn.WriteMessage(websocket.TextMessage, []byte("pong"))
			} else {
				// Process inbound alert/compliance data or telemetry
				var msg struct {
					Type    string          `json:"type"`
					Payload json.RawMessage `json:"payload"`
				}
				err := json.Unmarshal(payload, &msg)
				if err == nil && msg.Type != "" {
					switch msg.Type {
					case "telemetry":
						var tel struct {
							FirewallRules json.RawMessage `json:"firewall_rules"`
							InstalledApps json.RawMessage `json:"installed_apps"`
						}
						if err := json.Unmarshal(msg.Payload, &tel); err == nil {
							_ = db.UpdateAgentTelemetry(agent.AgentID, string(tel.FirewallRules), string(tel.InstalledApps))
							log.Printf("Received system telemetry from agent %s", agent.Hostname)
						} else {
							log.Printf("Failed to decode telemetry payload: %v", err)
						}
					case "event":
						var event db.SecurityEvent
						if err := json.Unmarshal(msg.Payload, &event); err == nil {
							event.AgentID = agent.AgentID
							_ = db.LogEvent(&event)
							log.Printf("Received event from agent %s: [%s] %s", agent.Hostname, event.EventType, event.Message)
						}
					}
				} else {
					var event db.SecurityEvent
					err := json.Unmarshal(payload, &event)
					if err == nil {
						event.AgentID = agent.AgentID
						_ = db.LogEvent(&event)
						log.Printf("Received legacy event from agent %s: [%s] %s", agent.Hostname, event.EventType, event.Message)
					}
				}
			}
		}
	}
}

// BroadcastPolicyToWorkgroup pushes a JSON policy to all active agents belonging to a workgroup
func BroadcastPolicyToWorkgroup(workgroup string, policyPayload string) int {
	count := 0
	ActiveConnections.Range(func(key, value interface{}) bool {
		agentID := key.(string)
		conn := value.(*websocket.Conn)

		agent, err := db.GetAgent(agentID)
		if err == nil && agent.Workgroup == workgroup {
			err = conn.WriteMessage(websocket.TextMessage, []byte(policyPayload))
			if err == nil {
				count++
			} else {
				log.Printf("Failed to push policy to agent %s: %v", agentID, err)
			}
		}
		return true
	})
	return count
}
