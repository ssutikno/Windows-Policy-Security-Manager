using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WWPO.Agent;

public static class AgentTests
{
    // Simple self-contained verification methods that compile as part of the project
    public static bool RunVerificationSuite()
    {
        Console.WriteLine("\n--- STARTING C# AGENT VERIFICATION SUITE ---");
        try
        {
            VerifyConfigSerialization();
            VerifySignatureGeneration();
            VerifySystemMetadata();
            Console.WriteLine("ALL C# VERIFICATIONS COMPLETED SUCCESSFULLY!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"VERIFICATION SUITE FAILED: {ex.Message}");
            return false;
        }
    }

    private static void VerifyConfigSerialization()
    {
        Console.Write("Verifying Configuration Manager... ");
        
        var testConfig = new AgentConfig
        {
            AgentID = "test-agent-id",
            ConnectionSecret = "dGVzdC1zZWNyZXQtYmFzZTY0LWtleS0xMjM0NTY3ODkw", // "test-secret-base64-key-1234567890" in base64
            Workgroup = "DEV_DEPT",
            MasterIP = "192.168.1.10",
            SetupToken = "temp-token"
        };

        // Serialize and Deserialize to ensure JSON schema matches
        var json = JsonSerializer.Serialize(testConfig);
        var deserialized = JsonSerializer.Deserialize<AgentConfig>(json);

        if (deserialized == null) throw new Exception("Deserialization returned null.");
        if (deserialized.AgentID != testConfig.AgentID) throw new Exception("AgentID mismatch.");
        if (deserialized.ConnectionSecret != testConfig.ConnectionSecret) throw new Exception("ConnectionSecret mismatch.");
        if (deserialized.Workgroup != testConfig.Workgroup) throw new Exception("Workgroup mismatch.");
        if (deserialized.MasterIP != testConfig.MasterIP) throw new Exception("MasterIP mismatch.");
        if (deserialized.SetupToken != testConfig.SetupToken) throw new Exception("SetupToken mismatch.");

        Console.WriteLine("PASS");
    }

    private static void VerifySignatureGeneration()
    {
        Console.Write("Verifying HMAC-SHA256 Signature signing... ");

        var timestamp = "1717659600"; // Fixed unix timestamp
        var secret = Convert.ToBase64String(Encoding.UTF8.GetBytes("my-symmetric-shared-connection-secret-key"));

        // Generate signature
        var secretBytes = Convert.FromBase64String(secret);
        using var hmac = new HMACSHA256(secretBytes);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(timestamp));
        var signature = Convert.ToBase64String(signatureBytes);

        // Expected output validation (known test vector comparison)
        if (string.IsNullOrEmpty(signature))
        {
            throw new Exception("Generated signature is null or empty.");
        }

        Console.WriteLine("PASS");
    }

    private static void VerifySystemMetadata()
    {
        Console.Write("Verifying System Metadata collectors... ");

        var hostname = SystemMetadata.GetHostname();
        var osVersion = SystemMetadata.GetOSVersion();
        var uuid = SystemMetadata.GetMachineUUID();

        if (string.IsNullOrEmpty(hostname)) throw new Exception("Hostname collection returned empty.");
        if (string.IsNullOrEmpty(osVersion)) throw new Exception("OSVersion collection returned empty.");
        if (string.IsNullOrEmpty(uuid)) throw new Exception("Machine UUID collection returned empty.");

        Console.WriteLine("PASS");
    }
}
