package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/user/wwpo/client-agent-go/config"
	"github.com/user/wwpo/client-agent-go/enforcer"
	"github.com/user/wwpo/client-agent-go/enroll"
	"github.com/user/wwpo/client-agent-go/ws"
)

func main() {
	log.Println("Starting WWPO Go Client Agent service initialization...")

	// Enforce Admin privileges
	if !checkAdminPrivileges() {
		if os.Getenv("WWPO_DEV_MODE") == "true" {
			log.Println("[WARNING] Running without Administrator privileges in development mode.")
		} else {
			log.Fatalln("CRITICAL ERROR: WWPO Client Agent must be run as Administrator (Elevated / root). Set WWPO_DEV_MODE=true to override in development.")
		}
	}

	startService()
}

func runAgent(stopChan chan struct{}) {
	log.Println("WWPO Go Client Agent background service active.")

	// 1. Load configuration settings
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config manager: %v", err)
	}

	// 2. Perform secure enrollment if credentials are not yet populated
	for cfg.AgentID == "" || cfg.ConnectionSecret == "" {
		log.Println("Agent not enrolled. Initiating registration handshake...")
		enrolled, err := enroll.EnrollAsync(cfg)
		if err != nil {
			log.Printf("Enrollment failed: %v. Retrying in 15 seconds...", err)
			
			// Wait for 15 seconds or stop signal
			select {
			case <-stopChan:
				return
			case <-time.After(15 * time.Second):
			}

			// Reload configuration to pick up manual modifications if any
			cfg, _ = config.LoadConfig()
			continue
		}
		if enrolled {
			break
		}
	}

	// Local offline policy caching path
	policyCachePath := filepath.Join(filepath.Dir(config.GetConfigPath()), "policy_cache.json")

	// 3. Setup WebSocket Connection Manager
	var cm *ws.ConnectionManager

	onPolicyReceived := func(payload string) {
		log.Println("[AGENT] Received policy push from Master. Parsing configuration...")

		var policy enforcer.PolicyEnvelope
		err := json.Unmarshal([]byte(payload), &policy)
		if err != nil {
			log.Printf("[AGENT] Failed to parse pushed policy JSON: %v", err)
			return
		}

		// Save to local offline cache
		err = os.WriteFile(policyCachePath, []byte(payload), 0600)
		if err != nil {
			log.Printf("[AGENT] Failed to write policy cache: %v", err)
		} else {
			log.Println("[AGENT] Policy successfully written to local offline cache.")
		}

		// Enforce immediately
		enforcer.Enforce(&policy, cm)
		cm.SendEvent("HEAL_ACTION", fmt.Sprintf("Applied policy version %d successfully", policy.Version))
	}

	cm = ws.NewConnectionManager(cfg, onPolicyReceived)

	cm.OnConnected = func() {
		log.Println("[AGENT] Connected to Master. Gathering and transmitting system telemetry...")
		tel := enforcer.CollectTelemetry()
		err := cm.SendCustomMessage("telemetry", tel)
		if err != nil {
			log.Printf("[AGENT] Failed to send telemetry: %v", err)
		} else {
			log.Println("[AGENT] Telemetry successfully sent to Master.")
		}
	}

	// 4. Load & enforce offline policy cache if it exists on boot
	if _, err := os.Stat(policyCachePath); err == nil {
		log.Println("[AGENT] Local offline policy cache detected. Applying settings prior to server synchronization...")
		data, err := os.ReadFile(policyCachePath)
		if err == nil {
			var policy enforcer.PolicyEnvelope
			err = json.Unmarshal(data, &policy)
			if err == nil {
				go enforcer.Enforce(&policy, cm)
			}
		}
	}

	// 5. Start WebSocket connection manager
	go cm.Start()

	// 6. Active Self-Healing Loop (Audits settings every 60 seconds)
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-stopChan:
				ticker.Stop()
				return
			case <-ticker.C:
				if _, err := os.Stat(policyCachePath); err == nil {
					data, err := os.ReadFile(policyCachePath)
					if err == nil {
						var policy enforcer.PolicyEnvelope
						err = json.Unmarshal(data, &policy)
						if err == nil {
							log.Println("[AGENT] Running 60-second scheduled self-healing audit...")
							enforcer.Enforce(&policy, cm)
						}
					}
				}
			}
		}
	}()

	// Wait for stop signal
	<-stopChan
	ticker.Stop()
	log.Println("Agent background tasks stopped.")
}

func waitForConsoleSignal(stopChan chan struct{}) {
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	<-shutdownChan
	close(stopChan)
	log.Println("WWPO Client Agent background service stopping...")
}
