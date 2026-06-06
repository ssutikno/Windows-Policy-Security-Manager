package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

type Agent struct {
	AgentID          string    `json:"agent_id"`
	Workgroup        string    `json:"workgroup"`
	MachineUUID      string    `json:"machine_uuid"`
	Hostname         string    `json:"hostname"`
	IPAddress        string    `json:"ip_address"`
	OSVersion        string    `json:"os_version"`
	ConnectionSecret string    `json:"connection_secret"`
	CreatedAt        time.Time `json:"created_at"`
	LastSeen         time.Time `json:"last_seen"`
	Status           string    `json:"status"` // 'online', 'offline', 'compromised'
	FirewallRules    string    `json:"firewall_rules"`
	InstalledApps    string    `json:"installed_apps"`
}

type SetupToken struct {
	TokenID   string    `json:"token_id"`
	Value     string    `json:"token_value"`
	Workgroup string    `json:"workgroup"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
}

type Policy struct {
	PolicyID      string    `json:"policy_id"`
	Workgroup     string    `json:"workgroup"`
	Version       int       `json:"version"`
	PolicyPayload string    `json:"policy_payload"` // JSON string representation
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
}

type SecurityEvent struct {
	EventID   string    `json:"event_id"`
	AgentID   string    `json:"agent_id"`
	EventType string    `json:"event_type"` // INFO, WARNING, HEAL_ACTION, ALERT
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// InitDB initializes the SQLite database and runs migrations.
func InitDB(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Optimize SQLite for concurrent reading and write safety (WAL mode)
	_, err = DB.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		return fmt.Errorf("failed to set WAL mode: %w", err)
	}

	if err := createTables(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func createTables() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS setup_tokens (
			token_id TEXT PRIMARY KEY,
			token_value TEXT UNIQUE NOT NULL,
			workgroup TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			is_used INTEGER DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS agents (
			agent_id TEXT PRIMARY KEY,
			workgroup TEXT NOT NULL,
			machine_uuid TEXT UNIQUE NOT NULL,
			hostname TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			os_version TEXT NOT NULL,
			connection_secret TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			status TEXT DEFAULT 'offline',
			firewall_rules TEXT DEFAULT '[]',
			installed_apps TEXT DEFAULT '[]'
		);`,
		`CREATE TABLE IF NOT EXISTS policies (
			policy_id TEXT PRIMARY KEY,
			workgroup TEXT NOT NULL,
			version INTEGER NOT NULL,
			policy_payload TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS security_events (
			event_id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			message TEXT NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_agents_workgroup ON agents(workgroup);`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_value ON setup_tokens(token_value);`,
	}

	for _, query := range schema {
		if _, err := DB.Exec(query); err != nil {
			return err
		}
	}

	// Dynamically run migration updates for existing tables
	_, _ = DB.Exec("ALTER TABLE agents ADD COLUMN firewall_rules TEXT DEFAULT '[]';")
	_, _ = DB.Exec("ALTER TABLE agents ADD COLUMN installed_apps TEXT DEFAULT '[]';")

	return nil
}

// GenerateSetupToken creates a cryptographically random, ephemeral setup token bound to a workgroup.
func GenerateSetupToken(workgroup string, durationMinutes int) (*SetupToken, error) {
	tokenVal := uuid.New().String() // High entropy UUID
	tokenID := uuid.New().String()
	now := time.Now()
	expires := now.Add(time.Duration(durationMinutes) * time.Minute)

	query := `INSERT INTO setup_tokens (token_id, token_value, workgroup, expires_at) VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, tokenID, tokenVal, workgroup, expires)
	if err != nil {
		return nil, fmt.Errorf("db error generating token: %w", err)
	}

	return &SetupToken{
		TokenID:   tokenID,
		Value:     tokenVal,
		Workgroup: workgroup,
		CreatedAt: now,
		ExpiresAt: expires,
		IsUsed:    false,
	}, nil
}

// ValidateSetupToken checks if a token is valid, unexpired, and unused, returning the workgroup.
// It marks the token as used upon validation.
func ValidateSetupToken(tokenValue string) (string, error) {
	var workgroup string
	var expiresAt time.Time
	var isUsed int

	query := `SELECT workgroup, expires_at, is_used FROM setup_tokens WHERE token_value = ? LIMIT 1`
	err := DB.QueryRow(query, tokenValue).Scan(&workgroup, &expiresAt, &isUsed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("token does not exist")
		}
		return "", err
	}

	if isUsed == 1 {
		return "", errors.New("token has already been used")
	}

	if time.Now().After(expiresAt) {
		return "", errors.New("token has expired")
	}

	// Mark token as used
	updateQuery := `UPDATE setup_tokens SET is_used = 1 WHERE token_value = ?`
	_, err = DB.Exec(updateQuery, tokenValue)
	if err != nil {
		return "", fmt.Errorf("failed to mark token as used: %w", err)
	}

	return workgroup, nil
}

// RegisterOrUpdateAgent inserts a newly enrolled agent or updates an existing agent's details.
func RegisterOrUpdateAgent(agent *Agent) error {
	// Check if agent already registered by machine UUID
	var existingID string
	checkQuery := `SELECT agent_id FROM agents WHERE machine_uuid = ? LIMIT 1`
	err := DB.QueryRow(checkQuery, agent.MachineUUID).Scan(&existingID)

	if err == nil {
		// Update existing agent metadata and secret
		agent.AgentID = existingID
		updateQuery := `UPDATE agents SET hostname = ?, ip_address = ?, os_version = ?, connection_secret = ?, status = ?, last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`
		_, err = DB.Exec(updateQuery, agent.Hostname, agent.IPAddress, agent.OSVersion, agent.ConnectionSecret, agent.Status, agent.AgentID)
		if err != nil {
			return fmt.Errorf("failed to update existing agent: %w", err)
		}
		return nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	// Create new registration
	if agent.AgentID == "" {
		agent.AgentID = uuid.New().String()
	}
	insertQuery := `INSERT INTO agents (agent_id, workgroup, machine_uuid, hostname, ip_address, os_version, connection_secret, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = DB.Exec(insertQuery, agent.AgentID, agent.Workgroup, agent.MachineUUID, agent.Hostname, agent.IPAddress, agent.OSVersion, agent.ConnectionSecret, agent.Status)
	if err != nil {
		return fmt.Errorf("failed to insert new agent: %w", err)
	}

	return nil
}

// GetAgent retrieves agent details by ID.
func GetAgent(agentID string) (*Agent, error) {
	var agent Agent
	query := `SELECT agent_id, workgroup, machine_uuid, hostname, ip_address, os_version, connection_secret, status, last_seen, firewall_rules, installed_apps FROM agents WHERE agent_id = ?`
	var lastSeenStr string
	err := DB.QueryRow(query, agentID).Scan(
		&agent.AgentID, &agent.Workgroup, &agent.MachineUUID,
		&agent.Hostname, &agent.IPAddress, &agent.OSVersion,
		&agent.ConnectionSecret, &agent.Status, &lastSeenStr,
		&agent.FirewallRules, &agent.InstalledApps,
	)
	if err != nil {
		return nil, err
	}
	agent.LastSeen, _ = time.Parse(time.RFC3339, lastSeenStr)
	return &agent, nil
}

// SavePolicy inserts a new policy revision for a workgroup.
func SavePolicy(policy *Policy) error {
	if policy.PolicyID == "" {
		policy.PolicyID = uuid.New().String()
	}
	query := `INSERT INTO policies (policy_id, workgroup, version, policy_payload, created_by) VALUES (?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, policy.PolicyID, policy.Workgroup, policy.Version, policy.PolicyPayload, policy.CreatedBy)
	if err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}
	return nil
}

// GetLatestPolicyForWorkgroup gets the latest policy version for a specific workgroup.
func GetLatestPolicyForWorkgroup(workgroup string) (*Policy, error) {
	var policy Policy
	query := `SELECT policy_id, workgroup, version, policy_payload, created_at, created_by FROM policies WHERE workgroup = ? ORDER BY version DESC LIMIT 1`
	err := DB.QueryRow(query, workgroup).Scan(
		&policy.PolicyID, &policy.Workgroup, &policy.Version, &policy.PolicyPayload, &policy.CreatedAt, &policy.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// LogEvent writes a security/administrative alert to the database.
func LogEvent(event *SecurityEvent) error {
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	query := `INSERT INTO security_events (event_id, agent_id, event_type, message) VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, event.EventID, event.AgentID, event.EventType, event.Message)
	if err != nil {
		return fmt.Errorf("failed to log event: %w", err)
	}
	return nil
}

// ListAgents returns all registered agents in the SQLite database.
func ListAgents() ([]Agent, error) {
	query := `SELECT agent_id, workgroup, machine_uuid, hostname, ip_address, os_version, status, last_seen, firewall_rules, installed_apps FROM agents`
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var agent Agent
		var lastSeenStr string
		err := rows.Scan(
			&agent.AgentID, &agent.Workgroup, &agent.MachineUUID,
			&agent.Hostname, &agent.IPAddress, &agent.OSVersion,
			&agent.Status, &lastSeenStr,
			&agent.FirewallRules, &agent.InstalledApps,
		)
		if err != nil {
			return nil, err
		}
		agent.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeenStr)
		if agent.LastSeen.IsZero() {
			agent.LastSeen, _ = time.Parse(time.RFC3339, lastSeenStr)
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

// UpdateAgentTelemetry updates the firewall rules and installed apps of an agent.
func UpdateAgentTelemetry(agentID string, firewallRules string, installedApps string) error {
	query := `UPDATE agents SET firewall_rules = ?, installed_apps = ?, last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`
	_, err := DB.Exec(query, firewallRules, installedApps, agentID)
	return err
}

// ListEvents returns recent security events.
func ListEvents() ([]SecurityEvent, error) {
	query := `SELECT event_id, agent_id, event_type, message, timestamp FROM security_events ORDER BY timestamp DESC LIMIT 100`
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		var timestampStr string
		err := rows.Scan(&event.EventID, &event.AgentID, &event.EventType, &event.Message, &timestampStr)
		if err != nil {
			return nil, err
		}
		event.Timestamp, _ = time.Parse("2006-01-02 15:04:05", timestampStr)
		if event.Timestamp.IsZero() {
			event.Timestamp, _ = time.Parse(time.RFC3339, timestampStr)
		}
		events = append(events, event)
	}
	return events, nil
}
