using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

namespace WWPO.Agent;

public static class PolicyEnforcer
{
    private static readonly string WwpoTempDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WWPO", "Temp")
        : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WWPO_Data", "Temp");

    public static void Enforce(PolicyEnvelope policy, ConnectionManager? conn = null)
    {
        Console.WriteLine($"[ENFORCER] Executing compliance checks for policy version {policy.Version}...");

        if (!Directory.Exists(WwpoTempDir))
        {
            Directory.CreateDirectory(WwpoTempDir);
        }

        try
        {
            if (policy.Features.UsbBlocking != null)
                EnforceUsbBlocking(policy.Features.UsbBlocking, conn);

            if (policy.Features.SoftwareRestriction != null)
                EnforceSrp(policy.Features.SoftwareRestriction, conn);

            if (policy.Features.FirewallOrchestration != null)
                EnforceFirewall(policy.Features.FirewallOrchestration, conn);

            if (policy.Features.AccountSecurity != null)
                EnforceAccountSecurity(policy.Features.AccountSecurity, conn);

            if (policy.Features.WindowsUpdate != null)
                EnforceWindowsUpdate(policy.Features.WindowsUpdate, conn);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ENFORCER] Critical error in enforcement loop: {ex.Message}");
            conn?.SendEventAsync("ALERT", $"Critical policy application error: {ex.Message}").Wait(1000);
        }
    }

    // 1. USB Storage Blocking
    private static void EnforceUsbBlocking(UsbBlockingConfig config, ConnectionManager? conn)
    {
        Console.WriteLine("[USB] Auditing USB Mass Storage policy...");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[USB] [MOCK] Would set USBSTOR\\Start to {(config.Enabled && config.BlockAllMassStorage ? 4 : 3)}");
            return;
        }

        try
        {
            // USBSTOR service control
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true))
            {
                if (key != null)
                {
                    int targetValue = config.Enabled && config.BlockAllMassStorage ? 4 : 3;
                    int currentValue = (int)(key.GetValue("Start") ?? 3);
                    if (currentValue != targetValue)
                    {
                        key.SetValue("Start", targetValue, Microsoft.Win32.RegistryValueKind.DWord);
                        var msg = $"Reverted manual USB storage modifications: set HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start to {targetValue}";
                        Console.WriteLine($"[USB] [HEALED] {msg}");
                        conn?.SendEventAsync("HEAL_ACTION", msg);
                    }
                }
            }

            // Removable Storage Devices group policies
            var policyPath = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
            int targetPolicyVal = config.Enabled ? 1 : 0;

            using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(policyPath, true))
            {
                if (key != null)
                {
                    int currentRead = (int)(key.GetValue("Deny_Read") ?? 0);
                    int currentWrite = (int)(key.GetValue("Deny_Write") ?? 0);

                    if (currentRead != targetPolicyVal || currentWrite != targetPolicyVal)
                    {
                        key.SetValue("Deny_Read", targetPolicyVal, Microsoft.Win32.RegistryValueKind.DWord);
                        key.SetValue("Deny_Write", targetPolicyVal, Microsoft.Win32.RegistryValueKind.DWord);
                        var msg = $"Reverted manual registry overrides: set RemovableStorageDevices Deny_Read/Write policy to {targetPolicyVal}";
                        Console.WriteLine($"[USB] [HEALED] {msg}");
                        conn?.SendEventAsync("HEAL_ACTION", msg);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[USB] Error enforcing: {ex.Message}");
        }
    }

    // 2. Software Restriction Policies (SRP)
    private static void EnforceSrp(SrpConfig config, ConnectionManager? conn)
    {
        Console.WriteLine("[SRP] Auditing Software Restriction Rules...");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[SRP] [MOCK] Would enforce SRP. Rule count: {config.Rules.Count}");
            return;
        }

        try
        {
            var baseSrpPath = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
            using (var baseKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(baseSrpPath, true))
            {
                if (baseKey != null)
                {
                    // Ensure SRP is globally enabled and set default level
                    int targetDefaultLevel = config.DefaultLevel.ToLower() == "disallowed" ? 262144 : 327680;
                    int currentDefaultLevel = (int)(baseKey.GetValue("DefaultLevel") ?? 327680);
                    
                    if (currentDefaultLevel != targetDefaultLevel)
                    {
                        baseKey.SetValue("DefaultLevel", targetDefaultLevel, Microsoft.Win32.RegistryValueKind.DWord);
                        conn?.SendEventAsync("HEAL_ACTION", $"Corrected SRP DefaultLevel to {targetDefaultLevel}");
                    }
                    baseKey.SetValue("AuthenticodeEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }

            // Sync Path Rules
            var pathsSubkey = baseSrpPath + @"\0\Paths";
            // Clean out old WWPO rules (by checking Descriptions or names)
            using (var pathsKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(pathsSubkey, true))
            {
                if (pathsKey != null)
                {
                    foreach (var subkeyName in pathsKey.GetSubKeyNames())
                    {
                        using var sub = pathsKey.OpenSubKey(subkeyName);
                        var desc = sub?.GetValue("Description")?.ToString();
                        if (desc != null && desc.StartsWith("WWPO_"))
                        {
                            pathsKey.DeleteSubKeyTree(subkeyName, false);
                        }
                    }

                    // Add current active path rules
                    if (config.Enabled)
                    {
                        foreach (var rule in config.Rules)
                        {
                            if (rule.Type.ToLower() == "path")
                            {
                                var ruleGuid = Guid.NewGuid().ToString("B");
                                using var ruleKey = pathsKey.CreateSubKey(ruleGuid, true);
                                ruleKey.SetValue("ItemData", rule.Value, Microsoft.Win32.RegistryValueKind.String);
                                ruleKey.SetValue("SaferFlags", 0, Microsoft.Win32.RegistryValueKind.DWord);
                                ruleKey.SetValue("Description", $"WWPO_{rule.ID}: {rule.Description}", Microsoft.Win32.RegistryValueKind.String);
                            }
                        }
                    }
                }
            }

            // Sync Hash Rules
            var hashesSubkey = baseSrpPath + @"\0\Hashes";
            using (var hashesKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(hashesSubkey, true))
            {
                if (hashesKey != null)
                {
                    foreach (var subkeyName in hashesKey.GetSubKeyNames())
                    {
                        using var sub = hashesKey.OpenSubKey(subkeyName);
                        var desc = sub?.GetValue("Description")?.ToString();
                        if (desc != null && desc.StartsWith("WWPO_"))
                        {
                            hashesKey.DeleteSubKeyTree(subkeyName, false);
                        }
                    }

                    if (config.Enabled)
                    {
                        foreach (var rule in config.Rules)
                        {
                            if (rule.Type.ToLower() == "hash")
                            {
                                var ruleGuid = Guid.NewGuid().ToString("B");
                                using var ruleKey = hashesKey.CreateSubKey(ruleGuid, true);
                                
                                // Convert hex string to binary bytes
                                var hashBytes = StringToByteArray(rule.Value);
                                ruleKey.SetValue("ItemData", hashBytes, Microsoft.Win32.RegistryValueKind.Binary);
                                ruleKey.SetValue("HashAlg", rule.HashAlg.ToLower() == "sha256" ? 0x800c : 0x8003, Microsoft.Win32.RegistryValueKind.DWord);
                                ruleKey.SetValue("ItemSize", rule.FileSizeBytes, Microsoft.Win32.RegistryValueKind.QWord);
                                ruleKey.SetValue("SaferFlags", 0, Microsoft.Win32.RegistryValueKind.DWord);
                                ruleKey.SetValue("Description", $"WWPO_{rule.ID}: {rule.Description}", Microsoft.Win32.RegistryValueKind.String);
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SRP] Error enforcing: {ex.Message}");
        }
    }

    // 3. Windows Firewall Orchestration
    private static void EnforceFirewall(FirewallConfig config, ConnectionManager? conn)
    {
        Console.WriteLine("[FIREWALL] Auditing Windows Firewall profiles and rules...");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[FIREWALL] [MOCK] Would enforce firewall. Profiles state ON: {config.GlobalStateOn}. Rule count: {config.Rules.Count}");
            return;
        }

        try
        {
            // 1. Enforce global states
            if (config.GlobalStateOn)
            {
                RunNetshCommand("advfirewall set allprofiles state on");
            }

            // 2. Query active rules and purge custom old WWPO rules
            // We retrieve rules list by name filter, but it's simpler to run netsh to delete old rules
            // with names matching "WWPO_" and add them back to make sure they are correct.
            // First: Purge existing WWPO_ rules
            // Actually, we can delete all rules matching the WWPO_ prefix
            // netsh advfirewall firewall delete rule name=all
            // Wait, we delete rules matching the name:
            foreach (var rule in config.Rules)
            {
                var ruleName = $"WWPO_{rule.Name}";
                RunNetshCommand($"advfirewall firewall delete rule name=\"{ruleName}\"");

                if (config.Enabled)
                {
                    // Add rule back
                    var command = new StringBuilder("advfirewall firewall add rule ");
                    command.Append($"name=\"{ruleName}\" ");
                    command.Append($"dir={rule.Direction} ");
                    command.Append($"action={rule.Action} ");
                    
                    if (rule.Protocol.ToLower() != "any")
                    {
                        command.Append($"protocol={rule.Protocol} ");
                    }
                    if (rule.LocalPort.ToLower() != "any")
                    {
                        command.Append($"localport={rule.LocalPort} ");
                    }
                    if (rule.RemotePort.ToLower() != "any")
                    {
                        command.Append($"remoteport={rule.RemotePort} ");
                    }
                    if (rule.RemoteIP.ToLower() != "any")
                    {
                        command.Append($"remoteip={rule.RemoteIP} ");
                    }

                    RunNetshCommand(command.ToString());
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FIREWALL] Error enforcing: {ex.Message}");
        }
    }

    // 4. Account Security & Hardening
    private static void EnforceAccountSecurity(AccountSecurityConfig config, ConnectionManager? conn)
    {
        Console.WriteLine("[ACCOUNTS] Auditing Account Hardening & Security Policies...");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[ACCOUNTS] [MOCK] Would run secedit template config. MinimumPasswordLength: {config.MinPasswordLength}");
            return;
        }

        try
        {
            var infPath = Path.Combine(WwpoTempDir, "sec_template.inf");
            var sdbPath = Path.Combine(WwpoTempDir, "sec_db.sdb");

            // 1. Export active security policy
            RunCommand("secedit.exe", $"/export /cfg \"{infPath}\" /areas SECURITYPOLICY");

            if (!File.Exists(infPath))
            {
                Console.WriteLine("[ACCOUNTS] Error: Failed to export active security policies.");
                return;
            }

            // 2. Read and modify the INI file
            var lines = File.ReadAllLines(infPath, Encoding.Unicode); // Secedit templates are Unicode
            var updatedLines = new List<string>();
            bool inSystemAccessSection = false;

            var securitySettings = new Dictionary<string, string>
            {
                { "PasswordComplexity", config.PasswordComplexity ? "1" : "0" },
                { "MinimumPasswordLength", config.MinPasswordLength.ToString() },
                { "MaximumPasswordAge", config.MaxPasswordAgeDays.ToString() },
                { "MinimumPasswordAge", config.MinPasswordAgeDays.ToString() },
                { "LockoutBadCount", config.LockoutThreshold.ToString() },
                { "ResetLockoutCount", config.ResetLockoutCounterMins.ToString() },
                { "LockoutDuration", config.LockoutDurationMins.ToString() }
            };

            var appliedKeys = new HashSet<string>();

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Equals("[System Access]", StringComparison.OrdinalIgnoreCase))
                {
                    inSystemAccessSection = true;
                    updatedLines.Add(line);
                    continue;
                }

                if (trimmed.StartsWith("[") && inSystemAccessSection)
                {
                    // We left System Access section, append any missing settings
                    foreach (var kvp in securitySettings)
                    {
                        if (!appliedKeys.Contains(kvp.Key))
                        {
                            updatedLines.Add($"{kvp.Key} = {kvp.Value}");
                        }
                    }
                    inSystemAccessSection = false;
                }

                if (inSystemAccessSection && trimmed.Contains("="))
                {
                    var parts = trimmed.Split('=');
                    var key = parts[0].Trim();
                    if (securitySettings.ContainsKey(key))
                    {
                        updatedLines.Add($"{key} = {securitySettings[key]}");
                        appliedKeys.Add(key);
                        continue;
                    }
                }

                updatedLines.Add(line);
            }

            // Write back updated INF configuration
            File.WriteAllLines(infPath, updatedLines, Encoding.Unicode);

            // 3. Configure/import the updated policy
            RunCommand("secedit.exe", $"/configure /db \"{sdbPath}\" /cfg \"{infPath}\" /areas SECURITYPOLICY");
            
            // Clean up temporary database files
            try
            {
                if (File.Exists(infPath)) File.Delete(infPath);
                if (File.Exists(sdbPath)) File.Delete(sdbPath);
            }
            catch { /* Ignore deletion errors */ }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ACCOUNTS] Error enforcing: {ex.Message}");
        }
    }

    // 5. Windows Update Scheduling
    private static void EnforceWindowsUpdate(WindowsUpdateConfig config, ConnectionManager? conn)
    {
        Console.WriteLine("[UPDATE] Auditing Windows Update Policies...");
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[UPDATE] [MOCK] Would enforce Windows Update scheduling. Option: {config.AutoUpdateOption}");
            return;
        }

        try
        {
            var updateAuPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
            var updateRootPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

            using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(updateAuPath, true))
            {
                if (key != null)
                {
                    key.SetValue("NoAutoUpdate", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("AUOptions", config.AutoUpdateOption, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("ScheduledInstallDay", config.ScheduledInstallDay, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("ScheduledInstallTime", config.ScheduledInstallHour, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }

            using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(updateRootPath, true))
            {
                if (key != null)
                {
                    key.SetValue("DeferFeatureUpdates", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("DeferFeatureUpdatesPeriodInDays", config.DeferFeatureUpdatesDays, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("DeferQualityUpdates", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    key.SetValue("DeferQualityUpdatesPeriodInDays", config.DeferQualityUpdatesDays, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UPDATE] Error enforcing: {ex.Message}");
        }
    }

    // Utility Methods
    private static void RunNetshCommand(string arguments)
    {
        RunCommand("netsh.exe", arguments);
    }

    private static void RunCommand(string filename, string arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = filename,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(startInfo);
            if (process != null)
            {
                process.WaitForExit(15000); // 15 second execution timeout
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SHELL] Failed to execute {filename} {arguments}: {ex.Message}");
        }
    }

    private static byte[] StringToByteArray(string hex)
    {
        int numberChars = hex.Length;
        byte[] bytes = new byte[numberChars / 2];
        for (int i = 0; i < numberChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
}
