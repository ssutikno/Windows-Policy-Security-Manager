using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WWPO.Agent;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private AgentConfig _config = new();
    private ConnectionManager? _connManager;
    private readonly string _cachePath;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        
        // Resolve cache file path
        var dataDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WWPO")
            : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WWPO_Data");
        
        _cachePath = Path.Combine(dataDir, "policy_cache.json");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WWPO Security Agent Service started.");

        // 1. Load configuration state
        _config = ConfigManager.Load();

        // If config is completely empty, write a default skeleton configuration for local admins to edit
        if (string.IsNullOrEmpty(_config.AgentID) && string.IsNullOrEmpty(_config.SetupToken))
        {
            _logger.LogWarning("Agent not enrolled. Generating skeleton configuration file. Please populate SetupToken and MasterIP in config.json.");
            _config.MasterIP = "127.0.0.1";
            _config.SetupToken = "ENTER_TOKEN_HERE";
            ConfigManager.Save(_config);
        }

        // 2. Perform enrollment handshake if needed
        while (string.IsNullOrEmpty(_config.AgentID) && !stoppingToken.IsCancellationRequested)
        {
            if (_config.SetupToken != "ENTER_TOKEN_HERE" && !string.IsNullOrEmpty(_config.SetupToken))
            {
                var success = await EnrollmentClient.EnrollAsync(_config);
                if (success)
                {
                    // Reload configuration
                    _config = ConfigManager.Load();
                    break;
                }
            }
            
            _logger.LogWarning("Waiting 15 seconds to attempt enrollment. Ensure SetupToken and MasterIP are correctly configured.");
            await Task.Delay(15000, stoppingToken);
            _config = ConfigManager.Load();
        }

        if (stoppingToken.IsCancellationRequested) return;

        // 3. Enforce offline cached policy immediately on boot
        var cachedPolicy = LoadCachedPolicy();
        if (cachedPolicy != null)
        {
            _logger.LogInformation("Loaded cached policy from local storage. Enforcing security settings immediately...");
            PolicyEnforcer.Enforce(cachedPolicy);
        }

        // 4. Start WebSocket listener
        _connManager = new ConnectionManager(_config);
        _connManager.OnPolicyReceived += HandlePolicyUpdate;

        // Start connection manager in a separate task
        var wsTask = Task.Run(() => _connManager.StartAsync(), stoppingToken);

        // 5. Start Active Self-Healing 60-Second Loop
        var healTask = RunSelfHealingLoopAsync(stoppingToken);

        // Wait until service is terminated
        await Task.WhenAny(wsTask, healTask);
    }

    private void HandlePolicyUpdate(string jsonPayload)
    {
        try
        {
            var policy = JsonSerializer.Deserialize<PolicyEnvelope>(jsonPayload);
            if (policy != null)
            {
                _logger.LogInformation("Applying received policy: version {version} ({id})", policy.Version, policy.PolicyID);
                
                // Save to local cache
                File.WriteAllText(_cachePath, jsonPayload);
                
                // Enforce policies
                PolicyEnforcer.Enforce(policy, _connManager);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply incoming policy.");
        }
    }

    private async Task RunSelfHealingLoopAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Active Self-Healing engine worker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            // Execute self-healing checks every 60 seconds
            await Task.Delay(60000, stoppingToken);

            if (stoppingToken.IsCancellationRequested) break;

            var cachedPolicy = LoadCachedPolicy();
            if (cachedPolicy != null)
            {
                _logger.LogInformation("Running periodic policy enforcement audit...");
                PolicyEnforcer.Enforce(cachedPolicy, _connManager);
            }
        }
    }

    private PolicyEnvelope? LoadCachedPolicy()
    {
        try
        {
            if (File.Exists(_cachePath))
            {
                var json = File.ReadAllText(_cachePath);
                return JsonSerializer.Deserialize<PolicyEnvelope>(json);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading local cached policy file.");
        }
        return null;
    }

    public override void Dispose()
    {
        _connManager?.Stop();
        base.Dispose();
    }
}
