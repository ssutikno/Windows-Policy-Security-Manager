# WWPO Master Control Server Setup Guide

This folder contains the compiled binaries and configuration assets for the **Windows Workgroup Policy Orchestrator (WWPO) Master Control Server**.

## Features Included
* **Embedded WebUI Dashboard**: The React-based admin console is fully embedded into the executable. Navigating to port `:8080` loads the web interface directly.
* **Unified Database**: Stores agent inventories, telemetry, security event logs, and setup tokens inside a local SQLite database (`wwpo.db`).

---

## 1. Running on Linux

### Quick Start
To run the master control server interactively:
```bash
chmod +x ./master-server
./master-server
```

### Running as a Persistent Daemon (Systemd)
To configure the server to run continuously in the background:
1. Copy the executable and service descriptor:
   ```bash
   sudo mkdir -p /opt/wwpo-master
   sudo cp master-server /opt/wwpo-master/
   sudo cp wwpo-master.service /etc/systemd/system/
   ```
2. Enable and start the systemd service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable wwpo-master.service
   sudo systemctl start wwpo-master.service
   ```
3. Inspect runtime logs:
   ```bash
   journalctl -u wwpo-master.service -f
   ```

---

## 2. Running on Windows

### Quick Start
To run the server in a terminal window, launch Command Prompt or PowerShell:
```cmd
.\master-server.exe
```

---

## 3. Operations & CLI Commands

### Generating Enrollment Setup Tokens
To generate a secure enrollment token for a logical workgroup, invoke the `--gentoken` CLI argument:
```bash
# On Linux
./master-server --gentoken "DEVELOPERS" --duration 120

# On Windows
.\master-server.exe --gentoken "DEVELOPERS" --duration 120
```
Parameters:
* `--gentoken`: Name of the target workgroup matching client configurations.
* `--duration`: Token validity window in minutes (default is 120 minutes).
