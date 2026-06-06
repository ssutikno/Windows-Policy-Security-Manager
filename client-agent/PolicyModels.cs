using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace WWPO.Agent;

public class PolicyEnvelope
{
    [JsonPropertyName("policy_id")]
    public string PolicyID { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("workgroup")]
    public string Workgroup { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("features")]
    public FeaturesConfig Features { get; set; } = new();
}

public class FeaturesConfig
{
    [JsonPropertyName("usb_blocking")]
    public UsbBlockingConfig UsbBlocking { get; set; } = new();

    [JsonPropertyName("software_restriction")]
    public SrpConfig SoftwareRestriction { get; set; } = new();

    [JsonPropertyName("firewall_orchestration")]
    public FirewallConfig FirewallOrchestration { get; set; } = new();

    [JsonPropertyName("account_security")]
    public AccountSecurityConfig AccountSecurity { get; set; } = new();

    [JsonPropertyName("windows_update")]
    public WindowsUpdateConfig WindowsUpdate { get; set; } = new();
}

public class UsbBlockingConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("block_all_mass_storage")]
    public bool BlockAllMassStorage { get; set; }

    [JsonPropertyName("allow_read_only_exceptions")]
    public bool AllowReadOnlyExceptions { get; set; }
}

public class SrpConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("default_level")]
    public string DefaultLevel { get; set; } = "unrestricted"; // "disallowed" or "unrestricted"

    [JsonPropertyName("rules")]
    public List<SrpRule> Rules { get; set; } = new();
}

public class SrpRule
{
    [JsonPropertyName("id")]
    public string ID { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = "path"; // "path" or "hash"

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("hash_alg")]
    public string HashAlg { get; set; } = "sha256";

    [JsonPropertyName("file_size_bytes")]
    public long FileSizeBytes { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; } = "disallow"; // "disallow" or "allow"

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
}

public class FirewallConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("global_state_on")]
    public bool GlobalStateOn { get; set; }

    [JsonPropertyName("block_unmanaged_allowances")]
    public bool BlockUnmanagedAllowances { get; set; }

    [JsonPropertyName("rules")]
    public List<FirewallRule> Rules { get; set; } = new();
}

public class FirewallRule
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("direction")]
    public string Direction { get; set; } = "in"; // "in" or "out"

    [JsonPropertyName("action")]
    public string Action { get; set; } = "allow"; // "allow" or "block"

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "TCP"; // "TCP", "UDP", or "any"

    [JsonPropertyName("local_port")]
    public string LocalPort { get; set; } = "any";

    [JsonPropertyName("remote_port")]
    public string RemotePort { get; set; } = "any";

    [JsonPropertyName("remote_ip")]
    public string RemoteIP { get; set; } = "any";
}

public class AccountSecurityConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("password_complexity")]
    public bool PasswordComplexity { get; set; }

    [JsonPropertyName("min_password_length")]
    public int MinPasswordLength { get; set; } = 12;

    [JsonPropertyName("max_password_age_days")]
    public int MaxPasswordAgeDays { get; set; } = 90;

    [JsonPropertyName("min_password_age_days")]
    public int MinPasswordAgeDays { get; set; } = 1;

    [JsonPropertyName("lockout_threshold")]
    public int LockoutThreshold { get; set; } = 5;

    [JsonPropertyName("lockout_duration_mins")]
    public int LockoutDurationMins { get; set; } = 30;

    [JsonPropertyName("reset_lockout_counter_mins")]
    public int ResetLockoutCounterMins { get; set; } = 30;
}

public class WindowsUpdateConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("auto_update_option")]
    public int AutoUpdateOption { get; set; } = 4; // 4 = Scheduled auto-install

    [JsonPropertyName("scheduled_install_day")]
    public int ScheduledInstallDay { get; set; } = 0; // 0 = Every day

    [JsonPropertyName("scheduled_install_hour")]
    public int ScheduledInstallHour { get; set; } = 3; // 3 AM

    [JsonPropertyName("defer_feature_updates_days")]
    public int DeferFeatureUpdatesDays { get; set; } = 180;

    [JsonPropertyName("defer_quality_updates_days")]
    public int DeferQualityUpdatesDays { get; set; } = 7;
}
