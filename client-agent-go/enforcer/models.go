package enforcer

import "time"

type PolicyEnvelope struct {
	PolicyID  string         `json:"policy_id"`
	Version   int            `json:"version"`
	Workgroup string         `json:"workgroup"`
	Timestamp time.Time      `json:"timestamp"`
	Features  FeaturesConfig `json:"features"`
}

type FeaturesConfig struct {
	UsbBlocking          UsbBlockingConfig   `json:"usb_blocking"`
	SoftwareRestriction  SrpConfig           `json:"software_restriction"`
	FirewallOrchestration FirewallConfig      `json:"firewall_orchestration"`
	AccountSecurity      AccountSecurityConfig `json:"account_security"`
	WindowsUpdate        WindowsUpdateConfig `json:"windows_update"`
}

type UsbBlockingConfig struct {
	Enabled                 bool `json:"enabled"`
	BlockAllMassStorage     bool `json:"block_all_mass_storage"`
	AllowReadOnlyExceptions bool `json:"allow_read_only_exceptions"`
}

type SrpConfig struct {
	Enabled      bool      `json:"enabled"`
	DefaultLevel string    `json:"default_level"`
	Rules        []SrpRule `json:"rules"`
}

type SrpRule struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	HashAlg        string `json:"hash_alg"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	Action         string `json:"action"`
	Description    string `json:"description"`
}

type FirewallConfig struct {
	Enabled                   bool           `json:"enabled"`
	GlobalStateOn             bool           `json:"global_state_on"`
	BlockUnmanagedAllowances  bool           `json:"block_unmanaged_allowances"`
	Rules                     []FirewallRule `json:"rules"`
}

type FirewallRule struct {
	Name       string `json:"name"`
	Direction  string `json:"direction"`
	Action     string `json:"action"`
	Protocol   string `json:"protocol"`
	LocalPort  string `json:"local_port"`
	RemotePort string `json:"remote_port"`
	RemoteIP   string `json:"remote_ip"`
}

type AccountSecurityConfig struct {
	Enabled                 bool `json:"enabled"`
	PasswordComplexity      bool `json:"password_complexity"`
	MinPasswordLength       int  `json:"min_password_length"`
	MaxPasswordAgeDays      int  `json:"max_password_age_days"`
	MinPasswordAgeDays      int  `json:"min_password_age_days"`
	LockoutThreshold        int  `json:"lockout_threshold"`
	LockoutDurationMins     int  `json:"lockout_duration_mins"`
	ResetLockoutCounterMins int  `json:"reset_lockout_counter_mins"`
}

type WindowsUpdateConfig struct {
	Enabled                  bool `json:"enabled"`
	AutoUpdateOption         int  `json:"auto_update_option"`
	ScheduledInstallDay      int  `json:"scheduled_install_day"`
	ScheduledInstallHour     int  `json:"scheduled_install_hour"`
	DeferFeatureUpdatesDays  int  `json:"defer_feature_updates_days"`
	DeferQualityUpdatesDays  int  `json:"defer_quality_updates_days"`
}
