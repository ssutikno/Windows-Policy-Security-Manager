using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WWPO.Agent;

public static class SystemMetadata
{
    public static string GetHostname()
    {
        return Environment.MachineName;
    }

    public static string GetOSVersion()
    {
        return $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})";
    }

    public static string GetMachineUUID()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Query Windows Registry or WMI for BIOS UUID
                // Attempt to read from Registry key: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                var guid = key?.GetValue("MachineGuid")?.ToString();
                if (!string.IsNullOrEmpty(guid))
                {
                    return guid.Trim();
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // Read product_uuid on Linux
                if (File.Exists("/sys/class/dmi/id/product_uuid"))
                {
                    return File.ReadAllText("/sys/class/dmi/id/product_uuid").Trim();
                }
                if (File.Exists("/etc/machine-id"))
                {
                    return File.ReadAllText("/etc/machine-id").Trim();
                }
            }
        }
        catch
        {
            // Fallback to MAC-address-based stable UUID
        }

        return GetFallbackMACUUID();
    }

    private static string GetFallbackMACUUID()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up && 
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var mac = ni.GetPhysicalAddress().ToString();
                    if (!string.IsNullOrEmpty(mac))
                    {
                        // Generate deterministic UUID from MAC address
                        using var sha = SHA256.Create();
                        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(mac));
                        return new Guid(hash.AsSpan(0, 16)).ToString();
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        // Ultimate fallback: Random Guid
        return Guid.NewGuid().ToString();
    }
}
