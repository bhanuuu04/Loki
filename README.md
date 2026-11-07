# Loki: Cross-Platform Cybersecurity Agent Harness Platform

**Loki** is a production-grade, cross-platform AI cybersecurity assessment and research runtime built with Python, FastAPI, and Pydantic. It provides multi-provider LLM support with **first-class NVIDIA NIM integration**, OS-specific execution adapters (Windows, Linux, WSL2, Docker), security knowledge engines (CWE, OWASP Top 10), automated scope & policy enforcement, and a real-time Web UI.

---

## ⚡ Quickstart (Clone, Setup & Chat)

### 1. Clone & Install
```bash
git clone https://github.com/bhanuuu04/Loki.git
cd Loki

# On Kali Linux / Debian / Ubuntu:
pip install -e . --break-system-packages

# On Windows / macOS:
pip install -e .
```

### 2. Run Setup
```bash
loki setup
```
*(Interactive wizard: enter your API key and use **↑/↓ arrow keys** to select your model).*

### 3. Start Chatting with Loki!
```bash
loki
```

---

### Alternative: Convenience Scripts (No Pip Flags Needed)
- **Linux / Kali Linux:** Run `./setup.sh` then `./loki.sh` *(already marked executable in git — no `chmod` needed)*.
- **Windows:** Run `.\setup.bat` then `.\loki.bat`.

---

## Architecture Overview

```
+─────────────────────────────────────────────────────────────────────────────+
|                                LOKI PLATFORM                                |
+─────────────────────────────────────────────────────────────────────────────+
|                                                                             |
|   [ Web UI / SSE ] ──── [ REST API (FastAPI) ] ──── [ CLI (loki doctor) ]   |
|                                     │                                       |
|                                     ▼                                       |
|                         [ LokiAgent Runtime Loop ]                          |
|                       (ReAct / Thought-Action Cycle)                        |
|                                     │                                       |
|        ┌────────────────────────────┼───────────────────────────┐           |
|        ▼                            ▼                           ▼           |
| [ Multi-Provider Layer ]   [ Security Engine ]       [ Platform Adapters ]  |
|  • NVIDIA NIM (1st Class)   • Scope Manager           • Windows Native      |
|    - Hosted & Self-Hosted   • Policy Engine (Modes)   • Linux / Kali POSIX  |
|    - Capability Detection   • Audit Logger            • WSL2 Bridge         |
|  • OpenAI-Compatible        • CWE & OWASP Engines     • Docker Isolated     |
|  • Google Gemini / Claude   • Assessment & Findings   • Auto-OS Detection   |
|  • Deterministic Mock       • Report Generator (HTML)                       |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## One-Command Installation

### Windows 10/11 (PowerShell)
Open PowerShell as Administrator or regular user:
```powershell
# Local execution
.\install.ps1

# Remote deployment
irm https://raw.githubusercontent.com/your-org/loki/main/install.ps1 | iex
```

### Linux / Kali Linux / Ubuntu (Bash)
```bash
# Local execution
chmod +x install.sh && ./install.sh

# Remote deployment
curl -fsSL https://raw.githubusercontent.com/your-org/loki/main/install.sh | bash
```

### Uninstallation
- **Windows:** `.\uninstall.ps1`
- **Linux:** `chmod +x uninstall.sh && ./uninstall.sh`

---

## System Health & Diagnostics (`loki doctor`)

Run an automated end-to-end diagnostic of your operating system, Python runtime, active platform adapter, package dependencies, storage permissions, and LLM configuration:

```bash
python -m loki.cli.main doctor
# Or if installed on PATH:
loki doctor
```

Output displays clear `PASS`, `WARN`, or `FAIL` statuses:
```
─── LOKI SYSTEM DIAGNOSTIC (DOCTOR) ───
+----------------+--------------------------+------------+-------------------------------------+
| Category       | Component                | Status     | Details                             |
+================+==========================+============+=====================================+
| System         | Operating System         | PASS       | Windows (11) on AMD64               |
| System         | Python Version           | PASS       | 3.14.4 (>= 3.10 required)           |
| Dependencies   | Python Packages          | PASS       | All core dependencies installed     |
| Execution      | Active Platform Adapter  | PASS       | windows_native                      |
| Execution      | WSL2 Subsystem           | PASS       | WSL2 executable available on PATH   |
| Execution      | Docker Runtime           | WARN       | Docker not installed (optional)     |
| Storage        | Directory Permissions    | PASS       | Assessments & reports writable      |
| Tools          | Security Tool Catalog    | PASS       | 11 documented security tools        |
| LLM            | Default Provider         | PASS       | mock (Model: mock-agent-v1)         |
| LLM            | NVIDIA NIM Auth          | PASS       | Configured (integrate.api.nvidia)   |
+----------------+--------------------------+------------+-------------------------------------+
```

---

## NVIDIA NIM Integration (First-Class Provider)

Loki connects to **NVIDIA Inference Microservices (NIM)** hosted at `integrate.api.nvidia.com` or private on-premise NIM container clusters.

### 1. Configuration in `.env`
```env
LOKI_PROVIDER=nvidia
NVIDIA_NIM_API_KEY=nvapi-your-key-here
NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_NIM_MODEL=meta/llama-3.3-70b-instruct
```

### 2. Supported Models
Any model hosted on your NIM endpoint is supported dynamically without code changes, including:
- `meta/llama-3.3-70b-instruct`
- `nvidia/llama-3.1-nemotron-70b-instruct`
- `mistralai/mistral-large-2-instruct`
- `google/gemma-2-27b-it`
- `qwen/qwen2.5-72b-instruct`

### 3. Model Discovery & Capability Probing
```bash
# Discover available models on the active endpoint
python -m loki.cli.main models list --provider nvidia

# Probe model compatibility (tests auth, generation, streaming, tool-calling & latency)
python -m loki.cli.main models test --provider nvidia
```

---

## Cross-Platform Execution Adapters

Loki dynamically detects the host operating system (`PlatformDetector`) and selects the appropriate execution adapter (`loki.platform`):

- **Windows Native Adapter (`windows_native`)**:
  - Handles Windows process invocation with argument arrays.
  - Detects native `.exe`, `.cmd`, and `.bat` tools.
  - **WSL2 Bridge**: If a Linux security tool is required, delegates execution via `wsl -e <tool>` if WSL is available.
- **Linux / Kali Adapter (`linux_native`)**:
  - Direct POSIX process execution.
  - Automatically queries `/usr/sbin`, `/sbin`, and user PATH for installed security tools.
- **Docker Isolated Adapter (`docker_isolated`)**:
  - Runs security tools inside isolated containers (e.g. `kalilinux/kali-rolling`).

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `loki` | Launch interactive conversational chat session (Hermes style) |
| `loki setup` / `loki onboard` | Run interactive onboarding wizard with provider and model setup |
| `loki onboard --reset` | Reset configuration to defaults and re-run onboarding |
| `loki model` | Interactively select and switch AI models using arrow keys |
| `loki doctor` | Run full system health and platform diagnostics |
| `loki version` | Print current Loki version |
| `loki config` | View active configuration and provider parameters |
| `loki start` / `loki serve` | Start the FastAPI API & Web UI on `http://127.0.0.1:8000` |
| `loki run "<prompt>"` | Run an agent prompt with real-time step streaming |
| `loki eval <suite.json>` | Execute benchmark evaluation suites |
| `loki models list` | Query and list available models from active provider |
| `loki models test` | Run capability probe (connectivity, streaming, tools) |
| `loki tools` | List all registered tools in the runtime |

---

## Slash Commands (Inside Interactive Chat)

| Command | Description |
| :--- | :--- |
| `/help` | Display list of available chat commands |
| `/model [id]` | Select model with interactive arrow-key menu, or specify model ID |
| `/provider <name>` | Switch provider (`nvidia`, `mock`, `gemini`, `openai`, `ollama`) |
| `/mode <name>` | Switch execution mode (`safe`, `audit`, `nomercy`) |
| `/scope [target]` | View authorized scope or add a target (`/scope add 192.168.1.1`) |
| `/tools` | Display list of available security and system tools |
| `/status` | View session token usage, turn count, and health stats |
| `/history` | View conversation history in the current session |
| `/clear` | Clear terminal screen |
| `/exit` / `/quit` | Exit conversational session |

---

## Automated CI/CD

A matrix test workflow is configured in `.github/workflows/ci.yml` that automatically tests every commit and pull request on:
- **Ubuntu Latest** (Python 3.10 & 3.11)
- **Windows Latest** (Python 3.10 & 3.11)

---

## Running Local Unit Tests

```bash
python -m pytest -v
```
All unit and integration test cases pass natively.


## Security configuration and isolated execution

Loki automatically creates its operator credentials during `loki setup` (and on first chat startup if setup was skipped). Users do **not** need to manually generate or export security keys.

The independent `LOKI_OPERATOR_TOKEN` and `LOKI_AUTH_SIGNING_KEY` values are generated locally and stored outside the repository in:
- Linux/macOS: `~/.loki/security.env`
- Windows: `%LOCALAPPDATA%\\Loki\\security.env`

On POSIX systems, Loki restricts the directory to owner-only access (`0700`) and the secret file to owner read/write (`0600`). Existing process/environment credentials take precedence. Secrets are never printed or written to the project's `.env` file. The security file is preserved when provider configuration is reset.

Scope configuration and authorization-ticket issuance remain operator-side operations, never LLM-callable tools. Tickets are bound to the active assessment and approved target. Run `loki doctor` to inspect setup status without displaying secret values.

## Assessment modes

Switch modes inside chat with `/mode safe`, `/mode audit`, or `/mode nomercy`.

| Mode | Behaviour |
| :--- | :--- |
| `SAFE` | Passive reconnaissance and low-impact checks. High-risk active scanning and credential testing are blocked. |
| `AUDIT` | Controlled active vulnerability testing, including injection probes, scanners and fuzzing, within the approved target scope. |
| `NOMERCY` | Highest testing intensity. Enables recognized credential-audit tools after explicit operator confirmation. Destructive and denial-of-service/stress-test operations remain blocked. |

Old mode names `aggressive` and `advanced_audit` remain accepted as aliases for `audit` and `nomercy`.

**Modes never expand scope.** All network targets must still be within the explicitly approved assessment scope, excluded targets remain blocked, and shell/Python code runs in Docker rather than directly on the host. Per-minute policy limits apply to tool invocations; they are not a substitute for a per-login attempt budget inside a third-party brute-force utility.

**Docker is required for generated shell and Python execution.** Loki refuses these operations if Docker is unavailable or a container cannot be started. Python containers have networking disabled, and shell containers default to networking disabled. Do not enable unrestricted container egress: active remote testing needs a scope-aware network enforcement layer before broad network access is enabled.

Do not place API keys, passwords, bearer tokens, or session cookies in prompts or tool arguments. Store provider credentials in the local provider configuration and secrets in protected environment variables or a secrets manager.
