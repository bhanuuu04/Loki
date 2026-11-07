"""
Persistent tool-effectiveness memory for adaptive investigations.

Stores only task class, tool name, outcome counters, and timestamps. It never
persists prompts, target names, command arguments, credentials, or tool output.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional
import json
import os
import shlex
import re


MEMORY_SCHEMA_VERSION = 1
MAX_TASKS = 32
MAX_TOOLS_PER_TASK = 160
TASK_PATTERNS = (
    ("origin_ip_verification", r"\b(origin\s+ip|origin\s+address|real\s+ip|ip\s+behind\s+(?:the\s+)?cdn|actual\s+server\s+ip)\b"),
    ("subdomain_discovery", r"\b(subdomain|subdomains|sub-domain|sub-domain|enumerate\s+domains)\b"),
    ("web_fingerprinting", r"\b(whatweb|technology\s+stack|tech\s+stack|fingerprint\s+(?:the\s+)?web|web\s+server|cms\s+detect)\b"),
    ("dns_reconnaissance", r"\b(dns|nameserver|name\s+server|mx\s+record|txt\s+record|a\s+record|aaaa\s+record)\b"),
    ("network_discovery", r"\b(port\s+scan|port\s+scanning|open\s+ports|service\s+discovery|network\s+scan)\b"),
    ("vulnerability_assessment", r"\b(vulnerabilit|security\s+audit|pentest|penetration\s+test|cve|misconfiguration)\b"),
    ("wireless_assessment", r"\b(wifi|wi-fi|wireless|802\.11|bluetooth)\b"),
    ("password_audit", r"\b(password|hashcat|john\s+the\s+ripper|password\s+audit|credential\s+audit)\b"),
    ("forensics", r"\b(forensic|disk\s+image|memory\s+dump|pcap|packet\s+capture)\b"),
    ("reverse_engineering", r"\b(reverse\s+engineer|decompile|disassembl|binary\s+analysis|apk\s+analysis)\b"),
)

INVESTIGATION_VERBS = re.compile(
    r"\b(find|identify|discover|locate|trace|enumerate|map|fingerprint|investigate|determine|analy[sz]e|check|audit|assess|recon)\b",
    re.IGNORECASE,
)

NO_RESULT_MARKERS = (
    "no results",
    "no result",
    "no records found",
    "no active subdomains",
    "no matching",
    "not found",
    "not detected",
    "could not resolve",
    "couldn't resolve",
    "resolution failed",
    "no addresses",
    "not available",
    "not installed",
    "command not found",
    "zero results",
    "0 results",
    "not verified",
    "inconclusive",
)
BLOCKED_MARKERS = (
    "scope violation",
    "out of scope",
    "authorization denied",
    "authorization error",
    "policy violation",
    "execution refused",
    "blocked:",
)
ERROR_MARKERS = (
    "traceback",
    "connection error",
    "timeout",
    "timed out",
    "failed:",
    "error:",
    "exception:",
    "could not connect",
)
POSITIVE_MARKERS = (
    "ip addresses:",
    "primary hostname:",
    "discovered ",
    "resolved ",
    "found ",
    "certificate names:",
    "records returned:",
    "open ports:",
    "matched results:",
    "verified:",
    "confirmed:",
)


def classify_task(prompt: str) -> str:
    """Map a user objective to a stable, non-identifying task category."""
    value = (prompt or "").lower()
    for task_type, pattern in TASK_PATTERNS:
        if re.search(pattern, value):
            return task_type
    if INVESTIGATION_VERBS.search(value):
        return "general_investigation"
    return "general"


def is_investigation_request(prompt: str) -> bool:
    """Return whether the prompt describes an information-finding task."""
    return bool(INVESTIGATION_VERBS.search(prompt or ""))


def effective_tool_name(tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> str:
    """
    Extract the real executable when Loki invokes a command through run_command.

    This makes learning distinguish curl, nmap, whatweb, etc. instead of giving
    every shell-based method the same run_command score.
    """
    normalized = (tool_name or "").strip().lower()
    if normalized not in {"run_command", "shell_exec", "bash"}:
        return tool_name or "unknown"

    command = str((arguments or {}).get("command", "")).strip()
    if not command:
        return normalized
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        tokens = command.split()
    wrappers = {"sudo", "env", "stdbuf", "proxychains", "proxychains4", "nice", "time"}
    while tokens and os.path.basename(tokens[0]).lower().removesuffix(".exe") in wrappers:
        tokens.pop(0)
    if tokens and os.path.basename(tokens[0]).lower().removesuffix(".exe") == "timeout":
        tokens = tokens[2:]
    if not tokens:
        return normalized
    executable = os.path.basename(tokens[0]).lower().removesuffix(".exe")
    if re.fullmatch(r"[a-z0-9_.+-]{1,100}", executable):
        return executable
    return normalized


def classify_tool_outcome(
    output: Any,
    is_error: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
    task_type: str = "general",
) -> str:
    """
    Classify a tool result without storing its contents.

    For origin-IP work, a normal DNS answer is deliberately only partial evidence:
    an A record can identify a CDN edge rather than the protected origin.
    """
    metadata = metadata or {}
    if metadata.get("authorized") is False or metadata.get("risk") == "blocked":
        return "blocked"
    if is_error:
        return "error"

    if isinstance(output, str):
        value = output
    else:
        try:
            value = json.dumps(output, ensure_ascii=False, default=str)
        except Exception:
            value = str(output)
    normalized = value.strip().lower()

    if not normalized:
        return "no_result"
    if any(marker in normalized for marker in BLOCKED_MARKERS):
        return "blocked"
    if any(marker in normalized for marker in NO_RESULT_MARKERS):
        return "no_result"
    if any(marker in normalized for marker in ERROR_MARKERS):
        return "error"

    if task_type == "origin_ip_verification":
        if any(marker in normalized for marker in ("owner inventory", "authoritative origin record", "origin ip verified")):
            return "success"
        # DNS/CDN front-door responses must not be learned as verified origin IPs.
        if any(marker in normalized for marker in ("cloudflare", "cloudfront", "fastly", "akamai", "cdn edge", "edge ip")):
            return "partial"
        if "ip addresses:" in normalized or "a record" in normalized:
            return "partial"

    if any(marker in normalized for marker in POSITIVE_MARKERS):
        return "success"
    if len(normalized) > 80:
        return "partial"
    return "partial"


class ToolPerformanceMemory:
    """
    Small persistent scorecard for tool outcomes by task category.

    A smoothed score rewards tools that repeatedly return useful evidence while
    preventing one lucky result from permanently dominating future rankings.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        configured = path or os.getenv("LOKI_TOOL_PERFORMANCE_PATH")
        self.path = (
            Path(configured).expanduser()
            if configured
            else Path.home() / ".loki" / "tool-performance.json"
        )
        self._lock = RLock()
        self._data: Dict[str, Any] = {
            "schema_version": MEMORY_SCHEMA_VERSION,
            "updated_at": None,
            "tasks": {},
        }
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if payload.get("schema_version") != MEMORY_SCHEMA_VERSION:
                return
            tasks = payload.get("tasks", {})
            if not isinstance(tasks, dict):
                return
            clean: Dict[str, Any] = {}
            for task, entries in list(tasks.items())[:MAX_TASKS]:
                if not isinstance(entries, dict):
                    continue
                clean_task: Dict[str, Any] = {}
                for name, stats in list(entries.items())[:MAX_TOOLS_PER_TASK]:
                    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", str(name)):
                        continue
                    if not isinstance(stats, dict):
                        continue
                    clean_task[name] = {
                        key: max(0, int(stats.get(key, 0) or 0))
                        for key in ("success", "partial", "no_result", "error", "blocked")
                    }
                    clean_task[name]["last_outcome"] = str(stats.get("last_outcome", ""))[:20]
                    clean_task[name]["last_used"] = str(stats.get("last_used", ""))[:40]
                clean[str(task)[:64]] = clean_task
            self._data = {
                "schema_version": MEMORY_SCHEMA_VERSION,
                "updated_at": payload.get("updated_at"),
                "tasks": clean,
            }
        except (OSError, ValueError, TypeError, AttributeError):
            # Corrupt or inaccessible learning data must never prevent Loki startup.
            return

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(self.path)

    def record(
        self,
        task_type: str,
        tool_name: str,
        outcome: str,
    ) -> Dict[str, Any]:
        """Update counters for one tool result. Only outcome labels are persisted."""
        safe_task = re.sub(r"[^a-z0-9_-]", "_", (task_type or "general").lower())[:64] or "general"
        safe_tool = (tool_name or "unknown").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", safe_tool):
            safe_tool = "unknown"
        safe_outcome = outcome if outcome in {"success", "partial", "no_result", "error", "blocked"} else "partial"

        with self._lock:
            tasks = self._data.setdefault("tasks", {})
            task_stats = tasks.setdefault(safe_task, {})
            stats = task_stats.setdefault(
                safe_tool,
                {
                    "success": 0,
                    "partial": 0,
                    "no_result": 0,
                    "error": 0,
                    "blocked": 0,
                    "last_outcome": "",
                    "last_used": "",
                },
            )
            stats[safe_outcome] = int(stats.get(safe_outcome, 0)) + 1
            stats["last_outcome"] = safe_outcome
            stats["last_used"] = datetime.now(timezone.utc).isoformat()
            self._data["updated_at"] = stats["last_used"]

            # Bound growth by retaining the most recently used task/tool pairs.
            if len(tasks) > MAX_TASKS:
                oldest_task = next(iter(tasks))
                if oldest_task != safe_task:
                    tasks.pop(oldest_task, None)
            if len(task_stats) > MAX_TOOLS_PER_TASK:
                oldest_tool = min(
                    task_stats,
                    key=lambda name: task_stats[name].get("last_used", ""),
                )
                if oldest_tool != safe_tool:
                    task_stats.pop(oldest_tool, None)
            self._save()
            return dict(stats)

    @staticmethod
    def score(stats: Dict[str, Any]) -> float:
        total = sum(
            int(stats.get(key, 0) or 0)
            for key in ("success", "partial", "no_result", "error", "blocked")
        )
        weighted = (
            int(stats.get("success", 0) or 0)
            + 0.5 * int(stats.get("partial", 0) or 0)
        )
        return (weighted + 1.0) / (total + 2.0)

    def rank_tool_names(self, task_type: str, names: Iterable[str]) -> List[str]:
        """Rank candidate tools by observed usefulness for the current task type."""
        with self._lock:
            stats = self._data.get("tasks", {}).get(task_type, {})
            original = list(dict.fromkeys(names))
            original_rank = {name: index for index, name in enumerate(original)}
            return sorted(
                original,
                key=lambda name: (
                    -self.score(stats.get(name, {})),
                    -sum(int(stats.get(name, {}).get(k, 0) or 0) for k in ("success", "partial")),
                    original_rank[name],
                ),
            )

    def get_task_stats(self, task_type: str) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            stats = self._data.get("tasks", {}).get(task_type, {})
            return {
                name: {
                    **values,
                    "score": round(self.score(values), 3),
                    "attempts": sum(
                        int(values.get(key, 0) or 0)
                        for key in ("success", "partial", "no_result", "error", "blocked")
                    ),
                }
                for name, values in stats.items()
            }

    def format_guidance(self, task_type: str, limit: int = 8) -> str:
        """Format a compact ranking hint for the model; no raw outputs or targets."""
        stats = self.get_task_stats(task_type)
        if not stats:
            return "No prior tool-effectiveness data exists for this task category."
        ranked = sorted(
            stats.items(),
            key=lambda item: (-item[1]["score"], -item[1]["success"], item[0].lower()),
        )
        lines = []
        for name, values in ranked[: max(1, min(limit, 12))]:
            lines.append(
                f"- {name}: effectiveness {values['score']:.2f}; "
                f"{values['success']} useful, {values['partial']} partial, "
                f"{values['no_result']} no-result, {values['error']} errors, "
                f"{values['blocked']} blocked."
            )
        return "\n".join(lines)

    def summary(self, task_type: Optional[str] = None) -> str:
        """Human-readable, privacy-preserving performance summary."""
        with self._lock:
            tasks = self._data.get("tasks", {})
            selected = {task_type: tasks.get(task_type, {})} if task_type else tasks
            if not any(selected.values()):
                return "No tool-effectiveness history has been recorded yet."
            blocks = []
            for category, tools in selected.items():
                blocks.append(f"[{category}]")
                ranked = sorted(
                    tools.items(),
                    key=lambda item: (
                        -self.score(item[1]),
                        -int(item[1].get("success", 0)),
                        item[0].lower(),
                    ),
                )
                for name, stats in ranked[:20]:
                    total = sum(int(stats.get(key, 0)) for key in ("success", "partial", "no_result", "error", "blocked"))
                    blocks.append(
                        f"  {name}: score={self.score(stats):.2f}, attempts={total}, "
                        f"useful={stats.get('success', 0)}, partial={stats.get('partial', 0)}, "
                        f"no-result={stats.get('no_result', 0)}, errors={stats.get('error', 0)}, "
                        f"blocked={stats.get('blocked', 0)}, last={stats.get('last_outcome', 'n/a')}"
                    )
            return "\n".join(blocks)

    def clear(self) -> None:
        """Clear the local tool-learning cache."""
        with self._lock:
            self._data = {
                "schema_version": MEMORY_SCHEMA_VERSION,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "tasks": {},
            }
            self._save()


tool_performance_memory = ToolPerformanceMemory()
