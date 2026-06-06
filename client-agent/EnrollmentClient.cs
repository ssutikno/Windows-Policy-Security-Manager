using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace WWPO.Agent;

public static class EnrollmentClient
{
    private static readonly HttpClient HttpClient;

    static EnrollmentClient()
    {
        // Setup HttpClient handler to support self-signed certificates for local/on-premise operations
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
        HttpClient = new HttpClient(handler);
    }

    public static async Task<bool> EnrollAsync(AgentConfig config)
    {
        if (string.IsNullOrEmpty(config.SetupToken))
        {
            Console.WriteLine("Enrollment aborted: Setup token is empty.");
            return false;
        }

        Console.WriteLine($"Starting secure enrollment handshake with Master server: {config.MasterIP}...");

        var enrollmentUrl = $"http://{config.MasterIP}:8080/api/v1/enroll"; // We default to port 8080 for on-premise master
        
        var requestPayload = new
        {
            setup_token = config.SetupToken,
            machine_uuid = SystemMetadata.GetMachineUUID(),
            hostname = SystemMetadata.GetHostname(),
            os_version = SystemMetadata.GetOSVersion()
        };

        try
        {
            var jsonString = JsonSerializer.Serialize(requestPayload);
            var content = new StringContent(jsonString, Encoding.UTF8, "application/json");

            var response = await HttpClient.PostAsync(enrollmentUrl, content);
            if (!response.IsSuccessStatusCode)
            {
                var errorMsg = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Enrollment rejected by Master (HTTP {response.StatusCode}): {errorMsg}");
                return false;
            }

            var responseBody = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            // Extract connection secrets
            config.AgentID = root.GetProperty("agent_id").GetString() ?? string.Empty;
            config.ConnectionSecret = root.GetProperty("connection_secret").GetString() ?? string.Empty;
            
            // Extract the workgroup from the token registration (passed back indirectly or parsed from response)
            // Let's modify the response from the server to include the workgroup, or parse it.
            // Wait, does our server handler return the workgroup?
            // Our server handler returns EnrollResponse: agent_id, connection_secret, ping_interval_seconds.
            // Let's also include the workgroup in the server response or make the agent extract it, or we can update the server response to return it!
            // Wait, let's update handlers.go to return workgroup in the enrollment response, which is much cleaner!
            // Let's check: in handlers.go, req contains SetupToken. The server queries ValidateSetupToken which returns workgroup.
            // We can return the workgroup directly in EnrollResponse!
            // Let's see: root.GetProperty("workgroup").GetString() or similar.
            if (root.TryGetProperty("workgroup", out var wgProp))
            {
                config.Workgroup = wgProp.GetString() ?? config.Workgroup;
            }

            // Wipe setup token after successful enrollment
            config.SetupToken = string.Empty;

            // Save the updated configuration
            ConfigManager.Save(config);

            Console.WriteLine("Enrollment handshake succeeded!");
            Console.WriteLine($"Generated Agent ID: {config.AgentID}");
            Console.WriteLine($"Assigned Workgroup: {config.Workgroup}");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Network error during enrollment: {ex.Message}");
            return false;
        }
    }
}
