package ws

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/user/wwpo/client-agent-go/config"
)

type SecurityEvent struct {
	EventType string    `json:"event_type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type ConnectionManager struct {
	Config           *config.AgentConfig
	conn             *websocket.Conn
	mu               sync.Mutex
	lastPong         time.Time
	OnPolicyReceived func(payload string)
	OnConnected      func()
	backoffIntervals []time.Duration
	backoffIndex     int
}

func NewConnectionManager(cfg *config.AgentConfig, onPolicy func(string)) *ConnectionManager {
	return &ConnectionManager{
		Config:           cfg,
		OnPolicyReceived: onPolicy,
		backoffIntervals: []time.Duration{
			5 * time.Second,
			10 * time.Second,
			30 * time.Second,
			60 * time.Second,
			300 * time.Second,
		},
		backoffIndex: 0,
	}
}

func (cm *ConnectionManager) Start() {
	for {
		err := cm.connectWithRetry()
		if err != nil {
			log.Printf("[WS] Connection retry loops ended: %v", err)
			return
		}

		cm.backoffIndex = 0
		cm.lastPong = time.Now()

		stopChan := make(chan struct{})
		var wg sync.WaitGroup

		wg.Add(2)
		go cm.receiveLoop(stopChan, &wg)
		go cm.pingLoop(stopChan, &wg)

		wg.Wait()
		cm.closeConnection()

		log.Println("[WS] Disconnected. Reconnecting in 3 seconds...")
		time.Sleep(3 * time.Second)
	}
}

func (cm *ConnectionManager) connectWithRetry() error {
	for {
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := cm.generateSignature(timestamp, cm.Config.ConnectionSecret)

		u := url.URL{
			Scheme: "ws",
			Host:   fmt.Sprintf("%s:8080", cm.Config.MasterIP),
			Path:   "/api/v1/connect",
		}
		q := u.Query()
		q.Set("agent_id", cm.Config.AgentID)
		q.Set("timestamp", timestamp)
		q.Set("signature", signature)
		u.RawQuery = q.Encode()

		log.Printf("[WS] Dialing master socket: %s", u.String())
		c, _, err := dialer.Dial(u.String(), nil)
		if err == nil {
			cm.mu.Lock()
			cm.conn = c
			cm.mu.Unlock()
			log.Println("[WS] Socket connected successfully!")
			if cm.OnConnected != nil {
				go cm.OnConnected()
			}
			return nil
		}

		interval := cm.backoffIntervals[cm.backoffIndex]
		log.Printf("[WS] Connection failed: %v. Retrying in %v...", err, interval)

		if cm.backoffIndex < len(cm.backoffIntervals)-1 {
			cm.backoffIndex++
		}

		time.Sleep(interval)
	}
}

func (cm *ConnectionManager) generateSignature(timestamp, secretBase64 string) string {
	secretBytes, _ := base64.StdEncoding.DecodeString(secretBase64)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(timestamp))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (cm *ConnectionManager) receiveLoop(stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(stop)

	for {
		cm.mu.Lock()
		c := cm.conn
		cm.mu.Unlock()
		if c == nil {
			break
		}

		messageType, payload, err := c.ReadMessage()
		if err != nil {
			log.Printf("[WS] Read message error: %v", err)
			break
		}

		if messageType == websocket.TextMessage {
			msgStr := string(payload)
			if msgStr == "pong" {
				cm.lastPong = time.Now()
			} else {
				cm.processInboundPolicy(msgStr)
			}
		}
	}
}

func (cm *ConnectionManager) pingLoop(stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cm.mu.Lock()
			c := cm.conn
			cm.mu.Unlock()
			if c == nil {
				return
			}

			// Check for ping timeout (40s)
			if time.Since(cm.lastPong) > 40*time.Second {
				log.Println("[WS] Heartbeat timeout. Closing connection.")
				cm.closeConnection()
				return
			}

			err := cm.writeMessage(websocket.TextMessage, []byte("ping"))
			if err != nil {
				log.Printf("[WS] Failed to send ping: %v", err)
				return
			}
		}
	}
}

func (cm *ConnectionManager) processInboundPolicy(payload string) {
	var temp struct {
		Workgroup string `json:"workgroup"`
	}
	err := json.Unmarshal([]byte(payload), &temp)
	if err != nil {
		log.Printf("[WS] Failed to parse payload envelope: %v", err)
		return
	}

	if temp.Workgroup != cm.Config.Workgroup {
		log.Printf("[SECURITY] Discarded payload: workgroup mismatch. Target: %s, Local: %s", temp.Workgroup, cm.Config.Workgroup)
		return
	}

	log.Println("[WS] Received matching policy update configuration.")
	if cm.OnPolicyReceived != nil {
		cm.OnPolicyReceived(payload)
	}
}

type OutboundMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func (cm *ConnectionManager) SendCustomMessage(msgType string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal inner payload: %w", err)
	}

	outer := OutboundMessage{
		Type:    msgType,
		Payload: json.RawMessage(payloadBytes),
	}

	outerBytes, err := json.Marshal(outer)
	if err != nil {
		return fmt.Errorf("failed to marshal outer message: %w", err)
	}

	return cm.writeMessage(websocket.TextMessage, outerBytes)
}

func (cm *ConnectionManager) SendEvent(eventType, message string) {
	event := SecurityEvent{
		EventType: eventType,
		Message:   message,
		Timestamp: time.Now(),
	}

	err := cm.SendCustomMessage("event", event)
	if err != nil {
		log.Printf("[WS] Failed to send security event: %v", err)
	}
}

func (cm *ConnectionManager) writeMessage(messageType int, data []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.conn == nil {
		return fmt.Errorf("connection is nil")
	}
	return cm.conn.WriteMessage(messageType, data)
}

func (cm *ConnectionManager) closeConnection() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.conn != nil {
		_ = cm.conn.Close()
		cm.conn = nil
	}
}
