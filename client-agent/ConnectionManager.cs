using System;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WWPO.Agent;

public class ConnectionManager
{
    private readonly AgentConfig _config;
    private readonly CancellationTokenSource _cts = new();
    private ClientWebSocket? _webSocket;
    private readonly int[] _backoffIntervals = { 5, 10, 30, 60, 300 };
    private int _backoffIndex = 0;
    private DateTime _lastPongReceived = DateTime.UtcNow;

    public event Action<string>? OnPolicyReceived;

    public ConnectionManager(AgentConfig config)
    {
        _config = config;
    }

    public async Task StartAsync()
    {
        Console.WriteLine("WebSocket Connection Manager started.");

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                if (_webSocket == null || _webSocket.State != WebSocketState.Open)
                {
                    await ConnectWithRetryAsync();
                }

                if (_webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    _backoffIndex = 0; // Reset backoff index on successful connection
                    _lastPongReceived = DateTime.UtcNow;

                    using var localCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                    var receiveTask = ReceiveLoopAsync(_webSocket, localCts.Token);
                    var pingTask = PingLoopAsync(_webSocket, localCts.Token);

                    // Wait until either task fails or exits (indicating connection drop)
                    await Task.WhenAny(receiveTask, pingTask);
                    
                    // Cancel the other task if one exited
                    localCts.Cancel();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WebSocket main loop error: {ex.Message}");
            }

            // Clean up socket
            CloseSocket();
            
            // Wait a short duration before trying to reconnect
            await Task.Delay(2000, _cts.Token);
        }
    }

    public void Stop()
    {
        _cts.Cancel();
        CloseSocket();
    }

    private void CloseSocket()
    {
        if (_webSocket != null)
        {
            try
            {
                _webSocket.Dispose();
            }
            catch { /* Ignore */ }
            _webSocket = null;
        }
    }

    private async Task ConnectWithRetryAsync()
    {
        while (_webSocket == null || _webSocket.State != WebSocketState.Open)
        {
            if (_cts.Token.IsCancellationRequested) return;

            try
            {
                _webSocket = new ClientWebSocket();
                
                // Bypass certificate validation for local/on-premise deployment
                _webSocket.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var signature = GenerateSignature(timestamp, _config.ConnectionSecret);

                var wsUri = new Uri($"ws://{_config.MasterIP}:8080/api/v1/connect?agent_id={_config.AgentID}&timestamp={timestamp}&signature={Uri.EscapeDataString(signature)}");

                Console.WriteLine($"Attempting WebSocket connection to: {wsUri.GetLeftPart(UriPartial.Path)}");
                await _webSocket.ConnectAsync(wsUri, _cts.Token);
                Console.WriteLine("WebSocket connection established successfully!");
                return;
            }
            catch (Exception ex)
            {
                var interval = _backoffIntervals[_backoffIndex];
                Console.WriteLine($"Connection attempt failed: {ex.Message}. Retrying in {interval} seconds...");
                
                // Implement exponential backoff increment
                if (_backoffIndex < _backoffIntervals.Length - 1)
                {
                    _backoffIndex++;
                }

                await Task.Delay(TimeSpan.FromSeconds(interval), _cts.Token);
            }
        }
    }

    private static string GenerateSignature(string timestamp, string secretBase64)
    {
        var secretBytes = Convert.FromBase64String(secretBase64);
        using var hmac = new HMACSHA256(secretBytes);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(timestamp));
        return Convert.ToBase64ToString(signatureBytes);
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken ct)
    {
        var buffer = new byte[4096];

        try
        {
            while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                var result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    Console.WriteLine("WebSocket close frame received from Master.");
                    break;
                }

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    if (message == "pong")
                    {
                        _lastPongReceived = DateTime.UtcNow;
                    }
                    else
                    {
                        ProcessInboundMessage(message);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"WebSocket receive error: {ex.Message}");
        }
    }

    private async Task PingLoopAsync(ClientWebSocket socket, CancellationToken ct)
    {
        var pingBytes = Encoding.UTF8.GetBytes("ping");

        try
        {
            while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                await Task.Delay(30000, ct); // Send ping every 30 seconds

                // Check for Pong timeout: if we haven't received a pong in 40 seconds, drop connection
                if (DateTime.UtcNow - _lastPongReceived > TimeSpan.FromSeconds(40))
                {
                    Console.WriteLine("WebSocket Pong timeout detected. Terminating connection.");
                    break;
                }

                await socket.SendAsync(new ArraySegment<byte>(pingBytes), WebSocketMessageType.Text, true, ct);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"WebSocket ping error: {ex.Message}");
        }
    }

    private void ProcessInboundMessage(string messageJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(messageJson);
            var root = doc.RootElement;

            if (!root.TryGetProperty("workgroup", out var workgroupProp))
            {
                Console.WriteLine("Dropped payload: Missing workgroup string.");
                return;
            }

            var targetWorkgroup = workgroupProp.GetString();
            if (targetWorkgroup != _config.Workgroup)
            {
                // strict logical network isolation check
                Console.WriteLine($"[SECURITY] Payload discarded: target workgroup ({targetWorkgroup}) does not match local assigned workgroup ({_config.Workgroup}).");
                return;
            }

            Console.WriteLine("Valid policy payload matching assigned Workgroup received.");
            OnPolicyReceived?.Invoke(messageJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing inbound WebSocket payload: {ex.Message}");
        }
    }

    // Helper to send alert events back to Master
    public async Task SendEventAsync(string eventType, string message)
    {
        if (_webSocket == null || _webSocket.State != WebSocketState.Open) return;

        try
        {
            var eventPayload = new
            {
                event_type = eventType,
                message = message,
                timestamp = DateTime.UtcNow
            };

            var json = JsonSerializer.Serialize(eventPayload);
            var bytes = Encoding.UTF8.GetBytes(json);

            await _webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send alert event over WebSocket: {ex.Message}");
        }
    }
}
