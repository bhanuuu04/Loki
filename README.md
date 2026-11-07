<div align="center">

# Loki

### AI-powered cybersecurity assessment, testing, and research — with scope and policy controls.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/bhanuuu04/Loki/actions/workflows/ci.yml/badge.svg)](https://github.com/bhanuuu04/Loki/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Kali-lightgrey)](#platform-support)

**Loki** is an operator-controlled AI agent harness for security assessments. It combines configurable language models, security tools, target-scope enforcement, execution policies, and a terminal-first workflow.

[Get Started](#-get-started) · [Commands](#-command-reference) · [NOMERCY Lab Mode](#-nomercy-lab-proof-of-access)

</div>

---

## Contents

- [What is Loki?](#-what-is-loki)
- [Key capabilities](#-key-capabilities)
- [Get started](#-get-started)
- [Run the Web UI](#-run-the-web-ui)
- [Assessment workflow](#-assessment-workflow)
- [NOMERCY lab proof-of-access](#-nomercy-lab-proof-of-access)
- [Command reference](#-command-reference)
- [Configuration and secrets](#-configuration-and-secrets)
- [Platform support](#-platform-support)
- [Tests and development](#-tests-and-development)
- [Security boundaries](#-security-boundaries)

---

## 🧭 What is Loki?

Loki helps security researchers and developers run structured assessments against systems they own or are explicitly authorized to test.

Instead of treating every request as permission to scan anything, Loki is designed around three ideas:

1. **Define the scope** — specify which hosts are approved for the assessment.
2. **Choose the testing policy** — select the level of testing appropriate for the engagement.
3. **Verify before reporting** — distinguish an observed response from evidence that a test actually caused access.

Loki can be used through its interactive CLI or its local FastAPI-based Web UI.

## ✨ Key capabilities

| Area | What it provides |
| --- | --- |
| **AI providers** | NVIDIA NIM, OpenAI, Google Gemini, Ollama, and an offline Mock provider |
| **Assessment policies** | SAFE, AUDIT, and NOMERCY modes with operator confirmation for high-intensity testing |
| **Scope management** | Approved targets, exclusions, and scope checks before target interaction |
| **Security tooling** | A registered tool catalog, security checks, assessment findings, and reporting support |
| **Lab verification** | Canary-based proof-of-access checks for seeded dummy records in disposable environments |
| **Execution adapters** | Native Windows and Linux support, WSL2 integration, and Docker-based isolation |
| **Interfaces** | Interactive terminal, FastAPI endpoints, and a browser-based UI |
| **Diagnostics** | \`loki doctor\` for environment and dependency checks |

### How the pieces fit together

\`\`\`mermaid
flowchart TD
    A["Operator"] --> B["Loki CLI / Web UI"]
    B --> C["AI Agent Runtime"]
    C --> D["Policy & Scope Gateway"]
    D --> E["Security Tools"]
    E --> F["Approved Target / Lab"]
    C --> G["Assessment Findings"]
    G --> H["Reports & Evidence"]
    I["LLM Provider"] <--> C
\`\`\`

The model helps plan and interpret work. Loki's policy and scope layers govern tool execution; selecting a more intensive mode does not grant permission to test additional targets.

---

## 🚀 Get started

### Requirements

- Python **3.10 or newer**
- An AI provider API key, or use the **Mock** provider to try Loki without one
- Docker is optional for basic setup. It is required for Loki's containerized shell/Python execution features.
- Git

### 1. Clone the repository

\`\`\`bash
git clone https://github.com/bhanuuu04/Loki.git
cd Loki
\`\`\`

### 2. Create a virtual environment

**Linux / macOS / Kali Linux**

\`\`\`bash
python3 -m venv .venv
source .venv/bin/activate
\`\`\`

On Debian-based systems, install the venv package first if needed:

\`\`\`bash
sudo apt update
sudo apt install -y python3-venv
\`\`\`

**Windows PowerShell**

\`\`\`powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
\`\`\`

### 3. Install Loki

\`\`\`bash
python -m pip install --upgrade pip
python -m pip install -e .
\`\`\`

### 4. Configure an AI provider

Run the interactive setup wizard:

\`\`\`bash
loki onboard
\`\`\`

Choose a provider from the menu:

| Provider | When to use it |
| --- | --- |
| **NVIDIA NIM** | Recommended hosted or self-hosted model provider |
| **OpenAI** | Use an OpenAI API key |
| **Google Gemini** | Use a Gemini API key |
| **Ollama** | Connect to a local Ollama server |
| **Mock** | Offline testing; no API key required |

The wizard saves provider settings locally. You can rerun it later with \`loki onboard --reset\`.

### 5. Check your installation and launch Loki

\`\`\`bash
loki doctor
loki
\`\`\`

That’s it. Loki opens its interactive terminal session.

> **Command not found?** Make sure your virtual environment is activated. You can also run commands through Python, for example: \`python -m loki.cli.main doctor\`.

---

## 🖥️ Run the Web UI

Start the local API and browser interface:

\`\`\`bash
loki start
\`\`\`

Then open:

**http://127.0.0.1:8000**

You can choose a different local port:

\`\`\`bash
loki start --host 127.0.0.1 --port 8080
\`\`\`

Keep the service bound to localhost unless you have separately configured and secured any remote access. Do not expose an unauthenticated development interface directly to the public internet.

---

## 🎯 Assessment workflow

A typical assessment follows this sequence:

### 1. Add only authorized targets

Inside the interactive Loki session:

\`\`\`text
/scope
/scope add example.test
\`\`\`

Replace \`example.test\` with a domain, IP address, or host that you own or have written permission to assess. Review the active scope before running tools.

### 2. Select an assessment mode

\`\`\`text
/mode safe
/mode audit
/mode nomercy
\`\`\`

| Mode | Intended use |
| --- | --- |
| **SAFE** | Passive reconnaissance and low-impact checks |
| **AUDIT** | Controlled active vulnerability testing within the approved scope |
| **NOMERCY** | Highest testing intensity, including recognized credential-audit tools after explicit operator confirmation |

NOMERCY requires an interactive confirmation. Destructive actions and denial-of-service or stress testing remain blocked.

### 3. Run checks and review results

Useful commands:

\`\`\`text
/tools
/status
/history
\`\`\`

Ask Loki to perform a specific assessment task and keep the target, objective, and constraints explicit. Review the evidence and findings before treating a result as confirmed.

---

## 🧪 NOMERCY lab proof-of-access

NOMERCY includes a **canary-based verification workflow** for disposable labs and cloned applications. It is designed to check whether a seeded dummy JSON record was actually returned — not to dump arbitrary application data.

<blockquote>
  <strong>Use this only on a disposable environment you own or are explicitly authorized to test.</strong> Do not seed canaries into production data or use this feature to access real user information.
</blockquote>

### What the verifier checks

- **Direct access check:** makes one scoped HTTP GET and looks for the exact canary in a recognized JSON field.
- **Payload comparison:** when testing one query parameter, makes a no-payload control request first, followed by one request containing the supplied test value.
- **Causal verification:** reports injection as verified only when the canary is absent from the control response and present in the injected response.
- **Minimal evidence:** returns only the matching fixture record, with sensitive-looking fields redacted.

### Step-by-step lab setup

**1. Create a canary marker**

Run this in a separate terminal:

\`\`\`bash
loki lab-canary
\`\`\`

Copy the generated marker. It will look like:

\`\`\`text
LOKI-LAB-CANARY:your-generated-value
\`\`\`

**2. Seed it into a dummy JSON record**

Add the exact marker to a test fixture served by your disposable lab. Use the \`loki_canary\` field:

\`\`\`json
{
  "id": "loki-fixture-001",
  "loki_canary": "LOKI-LAB-CANARY:paste-your-generated-value-here",
  "record": "dummy-lab-data"
}
\`\`\`

Replace the example marker with the value generated by your own Loki installation. Keep the marker out of the request URL and test payload.

**3. Start Loki and scope it to the lab**

\`\`\`text
/scope add lab.example.test
/mode nomercy
\`\`\`

Confirm the NOMERCY prompt. Use your actual disposable lab hostname.

**4. Enable lab verification**

\`\`\`text
/lab status
/lab enable
\`\`\`

Read the confirmation prompt and enable it only for the disposable environment.

**5. Ask Loki to verify the fixture**

Provide the scoped endpoint, the canary marker, and — when testing an injection hypothesis — the single query-parameter name and test value. Ask Loki to use \`verify_lab_data_access\` and compare the control request with the test request.

**6. Turn it off when finished**

\`\`\`text
/lab disable
\`\`\`

### Verification limits

| Guardrail | Current behavior |
| --- | --- |
| HTTP method | GET only |
| Injection input | One query parameter |
| Response format | JSON only |
| Maximum response size | 64 KiB |
| Authentication | No cookies, session tokens, or credentials are sent |
| Redirects | Not followed |
| Returned data | Only the exact canary-matched fixture, sanitized |
| Remote code execution | Not supported |

A direct canary match proves that the seeded record was retrievable. It does **not** prove that a payload caused the access. Loki reports injection as verified only when the control-versus-test comparison supports that conclusion.

---

## ⌨️ Command reference

### Terminal commands

| Command | Purpose |
| --- | --- |
| \`loki\` | Start interactive chat |
| \`loki onboard\` | Open the provider setup wizard |
| \`loki onboard --reset\` | Reset provider configuration and rerun setup |
| \`loki doctor\` | Check dependencies and platform readiness |
| \`loki start\` | Start the local Web UI and API |
| \`loki run "your prompt"\` | Run one prompt and exit |
| \`loki tools\` | List registered tools |
| \`loki model\` | Open the model selector |
| \`loki model --list --provider nvidia\` | List models from a provider |
| \`loki model --test --provider nvidia\` | Test provider compatibility |
| \`loki eval path/to/suite.json\` | Run a benchmark suite |
| \`loki config\` | Inspect active configuration |
| \`loki lab-canary\` | Generate a lab fixture marker |
| \`loki --version\` | Print the installed version |

### Commands inside interactive chat

| Command | Purpose |
| --- | --- |
| \`/help\` | Show available chat commands |
| \`/model [id]\` | Select or switch the model |
| \`/provider [name]\` | Switch provider |
| \`/mode [safe\|audit\|nomercy]\` | Change assessment mode |
| \`/scope\` | View the approved target scope |
| \`/scope add <target>\` | Add an authorized target |
| \`/scope exclude <target>\` | Exclude a target |
| \`/lab status\` | Check lab verification status |
| \`/lab enable\` | Enable canary verification after confirmation |
| \`/lab disable\` | Disable canary verification |
| \`/tools\` | List available tools |
| \`/status\` | Show session status |
| \`/history\` | View conversation history |
| \`/reset\` | Reset conversation memory |
| \`/clear\` | Clear the terminal |
| \`/exit\` or \`/quit\` | Exit Loki |

---

## 🔐 Configuration and secrets

Provider configuration is stored in the project’s local \`.env\` file. Start with \`.env.example\` if you prefer to configure values manually.

**Never commit your \`.env\` file or paste API keys, passwords, bearer tokens, or session cookies into prompts.**

Loki also generates its operator security credentials locally and stores them separately from the project configuration:

| Operating system | Location |
| --- | --- |
| Linux / macOS | \`~/.loki/security.env\` |
| Windows | \`%LOCALAPPDATA%\\Loki\\security.env\` |

On POSIX systems, Loki applies restrictive permissions to the security directory and file. Run \`loki doctor\` to check setup status without displaying secret values.

---

## 💻 Platform support

| Platform | Support |
| --- | --- |
| Linux | Native execution adapter |
| Kali Linux | Native Linux adapter; suitable for a security-tool workstation |
| Windows | Native Windows adapter |
| WSL2 | Bridge for Linux tools on Windows when WSL is installed |
| Docker | Isolated execution adapter for supported containerized tasks |

Docker and WSL2 are optional for basic CLI use. Containerized shell/Python execution depends on Docker being installed and available.

---

## 🧰 Tests and development

Install the test dependencies:

\`\`\`bash
python -m pip install pytest pytest-asyncio
\`\`\`

Run the test suite:

\`\`\`bash
python -m pytest -v
\`\`\`

The GitHub Actions workflow runs the test suite on Ubuntu and Windows with Python 3.10 and 3.11.

Contributions are welcome. For substantial changes, open an issue first to discuss the proposed behavior, then submit a pull request with tests and a clear description.

---

## 🛡️ Security boundaries

Loki is an assessment framework, not permission to test arbitrary systems.

- Only assess targets you own or have explicit authorization to test.
- Assessment modes do not expand the configured target scope.
- High-intensity modes require operator confirmation.
- Destructive and denial-of-service actions remain blocked.
- Generated shell and Python tasks run through the configured Docker isolation path; Python execution is network-disabled.
- The lab verifier is limited to scoped GET requests and seeded canary fixtures. It is not an arbitrary data-extraction tool or a remote code-execution feature.
- Do not enable unrestricted container network access as a shortcut around scope enforcement.

**Responsible use is the operator’s responsibility.** Always obtain permission, define the allowed testing window, and follow the rules of engagement for the environment.

---

<div align="center">

**Built for controlled security research.**

[Repository](https://github.com/bhanuuu04/Loki) · [Issues](https://github.com/bhanuuu04/Loki/issues) · [Discussions](https://github.com/bhanuuu04/Loki/discussions)

</div>
