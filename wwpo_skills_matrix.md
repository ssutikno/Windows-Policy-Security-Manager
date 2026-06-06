# Windows Workgroup Policy Orchestrator (WWPO)
## Technical Skills Matrix & Developer Competency Guide

This document maps the architectural requirements defined in the WWPO PRD/Technical Specification to the engineering skills and competencies required to successfully build, test, and deploy the system.

---

## 1. Domain-Specific Skill Matrix

```mermaid
mindmap
  root((WWPO Development))
    Go Client Agent (Windows)
      Windows Registry Manipulation
      Firewall (netsh) Orchestration
      Secedit Security Policies
      Windows Service Integration
    Go Master Backend
      Concurrency & goroutines
      WebSocket Connections
      SQLite Embedded Database
      RESTful HTTPS APIs
    React Frontend
      Dashboard State Management
      WSS Connections
      Responsive CSS
    Security & Cryptography
      HMAC-SHA256 Signatures
      TLS 1.3 & Cert Pinning
      NTFS ACLs
```

---

## 2. Component-by-Component Competencies

### 2.1 Go Client Agent Developer (Go / Windows APIs)
*The Go Client Agent runs as a native Windows Service (with POSIX fallbacks for local dev) using elevated local privileges (`SYSTEM` / `Administrators`). Development requires expertise in Go cross-compilation, Windows platform-specific APIs, and system administration utilities.*

| Sub-Skill Area | Specific Competencies | Relevant WWPO Feature |
| :--- | :--- | :--- |
| **Windows Registry Administration** | Invoking registry commands and parsing outcomes. Handling security baselines for USB mass storage blocking, Safer path restriction configurations (SRP), and Windows Updates. | USB Stor blocking, Software Restriction Policies (SRP), Windows Update settings. |
| **Windows Service Development** | Building long-running, native Windows Services using Go's `golang.org/x/sys/windows/svc` control interface. Handling service signals (Stop, Shutdown) and executing clean exits. | Core agent execution model. |
| **Windows Firewall Orchestration** | Dynamically manipulating active firewall configurations using shell commands (`netsh advfirewall`) or powershell cmdlet invocations. | Firewall Orchestration. |
| **Secedit.exe Configuration** | Implementing program wrappers to run `secedit.exe` securely. Exporting, dynamically modifying `.inf` configuration templates (INI structure), and applying baseline policies. | Local Account hardening and lockout thresholds. |
| **WebSocket Client Engine** | Managing client-side persistent WebSocket connections. Implementing handshake signature checks, heartbeat ping/pong keepalives, and connection resilience. | Connection Upkeep and Resilience. |

---

### 2.2 Go Master Backend Developer (Golang)
*The Master backend manages real-time network states, processes duplex WebSocket traffic, and provides administrative APIs.*

| Sub-Skill Area | Specific Competencies | Relevant WWPO Feature |
| :--- | :--- | :--- |
| **Go Concurrency & Sync** | Safe concurrent access in multi-threaded environments. High-performance connection maps (`sync.Map`), channels, mutexes, and goroutine leak prevention. | Active socket memory map. |
| **WebSocket Engineering** | Low-level socket programming using library packages (e.g., `gorilla/websocket` or `nhooyr/websocket`). Handshakes, message-routing, read/write timeout parameters. | Real-time policy pushes. |
| **Embedded Databases (SQLite)** | SQLite database engine configuration in Go. SQL schema definition, transactions, indexing, and concurrency configurations (e.g., Write-Ahead Logging `WAL` mode). | Asset tracking, configuration database. |
| **RESTful API Design** | Constructing secure HTTP routers, input validation (e.g., payload sanitization), CORS policy administration, and structured JSON responses. | Agent enrollment, admin requests. |

---

### 2.3 React UI Developer (Frontend Engineering)
*The React administrative dashboard displays device states and enables policy authoring.*

| Sub-Skill Area | Specific Competencies | Relevant WWPO Feature |
| :--- | :--- | :--- |
| **Dashboard State Management** | Maintaining real-time state mappings for active, offline, and compromised agent services using React state hooks or Redux/Zustand. | Real-time asset health displays. |
| **Real-time Client Sockets** | Integrating WebSockets into the React component lifecycle. Handling component unmounting, automatic reconnection, and socket event listeners. | Live security event feed. |
| **Policy JSON Authoring UI** | Building dynamic forms that serialize user inputs into complex nested JSON configuration objects matching the Master schema. | Policy deployment workflows. |

---

### 2.4 Security & Cryptography Engineer (Cross-Disciplinary)
*Security is central to WWPO because it runs with local system privileges and controls endpoint protection.*

* **HMAC & Symmetric Signatures:** Generating and validating HMAC-SHA256 signatures for authenticating WebSockets connections using a shared secret.
* **Outbound Transport Protection:** Configuration of TLS 1.3, strict cipher-suites, and certificate validation methods (such as certificate pinning) to prevent Man-in-the-Middle (MitM) attacks.
* **Access Control Lists (ACLs):** Understanding Windows security descriptors and configuring DACLs on local files/registry hives to restrict modification to `SYSTEM` and `Administrators`.
* **Credential Vaulting:** Storing keys securely on endpoints (e.g., using Windows Data Protection API (DPAPI) or local filesystem ACL protections).

---

## 3. QA & Validation Engineer (Testing & Automation)

To validate the security engine, QA engineers need specific testing competencies:

1. **Virtualization & Sandbox Deployment:** Setting up local Windows Workgroup VMs (Windows 10/11 Professional or Enterprise) to test policy enforcement without disrupting corporate environments.
2. **Fault Injection Testing:** Simulating network failures, proxy interruptions, DNS poisoning, and firewall blocks to test the Go Client Agent's backoff and local offline policy cache enforcement behaviors.
3. **OS-State Auditing:** Utilizing Windows tools (`Regedit.exe`, `Secpol.msc`, `Eventvwr.msc`, `wf.msc`) to manually verify changes applied by the Go agent service and confirm the behavior of the self-healing engine.
4. **Security Penetration Testing:** Simulating a compromised local user attempting to bypass registry blocks or run restricted applications to ensure the self-healing loops and service protection locks function.
