using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace WWPO.Agent;

public class AgentConfig
{
    public string AgentID { get; set; } = string.Empty;
    public string ConnectionSecret { get; set; } = string.Empty;
    public string Workgroup { get; set; } = string.Empty;
    public string MasterIP { get; set; } = "127.0.0.1";
    public string SetupToken { get; set; } = string.Empty;
}

public static class ConfigManager
{
    private static readonly string ConfigDir = GetConfigDirectory();
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    private static string GetConfigDirectory()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // C:\ProgramData\WWPO
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WWPO");
        }
        else
        {
            // Local fallback directory for development
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WWPO_Data");
        }
    }

    public static bool ConfigExists()
    {
        return File.Exists(ConfigPath);
    }

    public static AgentConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath))
            {
                // Return default empty config
                return new AgentConfig();
            }

            var json = File.ReadAllText(ConfigPath);
            return JsonSerializer.Deserialize<AgentConfig>(json) ?? new AgentConfig();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading config: {ex.Message}");
            return new AgentConfig();
        }
    }

    public static void Save(AgentConfig config)
    {
        try
        {
            if (!Directory.Exists(ConfigDir))
            {
                Directory.CreateDirectory(ConfigDir);
            }

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(config, options);
            File.WriteAllText(ConfigPath, json);

            // Enforce restrictive file permissions (SYSTEM-only / Owner-only)
            ApplyFileSecurity(ConfigPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving config: {ex.Message}");
        }
    }

    private static void ApplyFileSecurity(string filePath)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                // Restrict permissions using standard Windows ACLs
                var fileInfo = new FileInfo(filePath);
                var fileSecurity = fileInfo.GetAccessControl();

                // Disable inheritance and remove inherited rules
                fileSecurity.SetAccessRuleProtection(true, false);

                // Add explicit rules for SYSTEM and Administrators
                var systemAccount = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var adminAccount = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

                var systemRule = new System.Security.AccessControl.FileSystemAccessRule(
                    systemAccount,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);

                var adminRule = new System.Security.AccessControl.FileSystemAccessRule(
                    adminAccount,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);

                fileSecurity.AddAccessRule(systemRule);
                fileSecurity.AddAccessRule(adminRule);

                fileInfo.SetAccessControl(fileSecurity);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to apply Windows NTFS ACL security: {ex.Message}");
            }
        }
        else
        {
            // POSIX fallback: Read/Write by owner only (chmod 600)
            try
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to apply POSIX permissions: {ex.Message}");
            }
        }
    }
}
