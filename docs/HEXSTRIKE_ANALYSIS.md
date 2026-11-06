# HexStrike AI Architecture Analysis & Integration Strategy for Loki

## 1. Executive Summary

**HexStrike AI** (`0x4m4/hexstrike-ai`) is an open-source security toolchain server built on the Model Context Protocol (MCP) and FastMCP. It exposes 150+ security tools as callable MCP functions to external LLM clients (such as Claude Desktop or Copilot).

For **Loki**, the objective is to remain a **100% standalone, independent cybersecurity agent** (resembling Hermes Agent) without relying on external MCP client/server layers, Claude Desktop, or external orchestrators.

This document details:
1. Architectural analysis of HexStrike AI.
2. Reusable software engineering patterns and schemas.
3. Native integration into Loki's internal `ToolRegistry` and `PolicyEngine`.

---

## 2. HexStrike AI Architecture Breakdown

```
[ External AI Client (Claude Desktop) ]
                │
         (stdio / MCP JSON-RPC)
                ▼
      [ FastMCP Server ] (hexstrike-ai)
                │
   ┌────────────┴────────────┐
   ▼                         ▼
[ 150+ Tool Handlers ]    [ Output Sanitizer ]
   │
   ▼
[ Local Subprocess Execution ] (Kali Linux CLI)
```

### Key Limitations of the Pure MCP Pattern for Loki:
- **Client Dependency**: Requires an external UI/host (e.g. Claude Desktop) to supply the model and reasoning loop.
- **Protocol Overhead**: Wraps every tool execution in JSON-RPC IPC over `stdio`.
- **Stateless Tool Invocations**: Does not maintain assessment session state, target inventories, scope boundaries, or unified audit logging.

---

## 3. Loki Standalone Pattern (Direct Integration)

Instead of running an external MCP server, Loki adopts HexStrike's tool definitions natively:

```
[ User (CLI / Web UI) ]
         │
         ▼
[ LokiAgent ReAct Loop ] ◄──► [ NVIDIA NIM / Provider Layer ]
         │
         ▼
[ Loki Tool Registry & Catalog ]
   ├── Tool Categorization (Recon, Web, Cloud, Crypto, Fuzzing)
   ├── Argument Schemas (Type hints & Pydantic models)
   ├── Scope & Policy Engine (Target boundary & Risk check)
   └── Platform Adapter (Windows Native, Linux POSIX, WSL2, Docker)
         │
         ▼
[ Assessment Store & Report Generator ]
```

---

## 4. Reusable Engineering Patterns Extracted from HexStrike

1. **Tool Categorization**:
   - `information_gathering`: Nmap, Masscan, Sublist3r, Amass, TheHarvester
   - `web_security`: Nikto, WhatWeb, Wfuzz, Gobuster, Ffuf, WPScan
   - `vulnerability_analysis`: Nuclei, Trivy, Semgrep
   - `cryptography`: SSLScan, Testssl.sh
   - `network_analysis`: TCPDump, TShark

2. **Command Construction Pattern**:
   - Explicit argument lists (array of strings) preventing shell injection.
   - Separate mandatory targets from optional tuning flags (rate limits, timeouts).

3. **Output Parsing**:
   - Stripping ANSI escape codes.
   - Parsing structured JSON or XML outputs (e.g. Nmap XML `-oX`, Ffuf JSON `-o`).

---

## 5. License & Attribution Notice

Components, schemas, and parameter mappings adapted from HexStrike AI are licensed under the MIT License by Muhammad Osama (`0x4m4`). Original copyright and license terms are preserved in Loki's third-party notices.
