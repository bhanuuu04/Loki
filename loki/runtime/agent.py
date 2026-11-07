"""
Core LokiAgent execution engine and harness loop.
"""

from typing import Any, AsyncIterator, Callable, List, Optional, Union
import asyncio
import time
import uuid

from loki.config import settings
from loki.providers.base import BaseLLMProvider
from loki.providers.factory import get_provider
from loki.runtime.context import AgentContext
from loki.runtime.memory import MemoryStore
from loki.tools.base import Tool
from loki.tools.builtins import ALL_BUILTIN_TOOLS
from loki.tools.security_tools import ALL_SECURITY_TOOLS
from loki.tools.registry import ToolRegistry
from loki.security.gateway import ExecutionGateway
from loki.security.context import AssessmentSecurityContext
from loki.knowledge.tool_registry.performance_memory import (
    ToolPerformanceMemory,
    classify_task,
    classify_tool_outcome,
    effective_tool_name,
    is_investigation_request,
    tool_performance_memory,
)
from loki.types import (
    AgentEvent,
    AgentStep,
    EventType,
    LLMResponse,
    Role,
    RunResult,
    RunStatus,
    TokenUsage,
    ToolResult,
)

DEFAULT_SYSTEM_PROMPT = """You are Loki, an advanced autonomous AI cybersecurity and systems research agent.
You assist security engineers in conducting authorized security assessments, reconnaissance, vulnerability analysis, and defensive audits.
You have access to specialized security tools, knowledge bases (CWE, OWASP Top 10), and built-in reconnaissance modules.

Operational Rules:
1. Scope & Authorization: You must operate strictly within the declared and authorized assessment scope. All tool executions are strictly mediated by the Execution Gateway and verified against authorized targets and CIDRs. Never attempt to expand scope or target out-of-scope assets autonomously.
2. Built-in Tools: Always prefer built-in tools (e.g. enumerate_subdomains, dns_lookup, audit_http_security_headers) for reconnaissance instead of guessing external commands.
3. System Environment: You operate in an interactive user shell without root/sudo access. Never run package manager installations such as apt-get, dnf, or brew. If an external tool is missing on PATH, use alternative built-in modules or inform the user how they can install it with sudo.
4. Python Scripts: Use python_exec for offline analysis and scripts inside the isolated no-network container. Do not claim that a script reached a target unless a dedicated scoped network tool confirms it.
5. Lab proof-of-access: In NOMERCY, only use verify_lab_data_access when the operator has enabled /lab mode and supplied a LOKI-LAB-CANARY marker seeded in a dummy record. You may send one payload in one query parameter, but the marker itself must never be placed in the request. When a payload is supplied, the tool compares a no-payload control response with the injected response. Claim an injection verified only when the canary is absent in the control response and present in the injected response. If the canary is already accessible without the payload, report data access but do not claim the payload caused an exploit. A direct canary fetch without a payload is not proof of exploitability. Never infer successful compromise from a reflected payload, HTTP status, or SQL error alone.
6. Kali tool discovery: For an unfamiliar security task or executable, call discover_kali_tools with the user's objective before selecting a command. Use get_kali_tool_details to inspect the selected entry, aliases, package, and documentation. Then call check_kali_tool_availability to verify that the executable exists inside the configured Docker shell image before trying to run it. Do not invent binaries, package names, or flags. Catalogue membership is not proof of installation. A host-installed binary is not necessarily present in the Docker shell image.
7. Tool selection and calling: Prefer the smallest relevant built-in tool. For Kali command work, discover candidates, inspect one candidate, verify the target with check_scope_authorization when applicable, then make one minimal tool call and inspect its exit code and output before continuing. Do not send many speculative commands in parallel. If a command is missing, search for an alternative rather than repeatedly retrying.
8. Network and execution boundaries: The generic run_command shell runs inside the configured Docker image with networking disabled. Do not use it for live remote scanning or claim that it reached a target. Use a dedicated network-capable tool that enforces active scope, or explain when the requested tool is not yet supported by a scoped network adapter. Never weaken sandbox networking or scope controls to make a tool work.
9. Installation: Never install Kali tools automatically. Show the package and installation hint, and let the operator decide whether to install it.
10. Goal-driven investigations: Treat requests to find, identify, locate, fingerprint, or enumerate something as an objective, not a one-tool task. A failed tool is one observation, not a reason to stop. When the objective is unresolved, try a materially different authorized method, avoid repeating the same failed method without a new hypothesis, and use the remaining run budget. Keep a short method ledger with the tool, what it established, and what it did not establish. Distinguish a method that returned no data from a method that was blocked by policy.
11. Learned tool effectiveness: Use the task-specific effectiveness memory in the live system context. Rank historically successful tools earlier for similar objectives, but treat the score as a hint rather than proof. Update the memory from every tool result. A useful result should increase priority; repeated no-result/error outcomes should lower priority. New tools start neutral. Never store or expose raw tool output, target names, prompts, or credentials in the learning memory.
12. Origin IP and CDN handling: For an origin-IP request, distinguish an ordinary DNS answer and a CDN edge IP from an independently verified origin address. Use only in-scope DNS observations and owner-provided DNS-zone, CDN, hosting, or cloud asset inventory. If a CDN is in front, do not attempt to bypass it, mine leaked origin databases, exploit misconfigurations, brute-force virtual hosts, or probe candidate origin IPs. If owner-controlled inventory is not available, say the origin is not verified; continue only with safe adjacent facts such as CDN/provider identification, public DNS records, certificate names, and in-scope technology metadata.
13. Additional useful information: Prioritize the exact question first. Once it is answered or no further safe method exists, include concise relevant side findings (for example DNS/NS/MX/TXT observations, certificate names, server headers, technology fingerprints, and in-scope subdomains). Label observations, inferences, and verified facts separately.
14. Network and execution boundaries: The generic run_command shell runs inside the configured Docker image with networking disabled. Do not use it for live remote scanning or claim that it reached a target. Use a dedicated network-capable tool that enforces active scope, or explain when the requested tool is not yet supported by a scoped network adapter. Never weaken sandbox networking or scope controls to make a tool work.
15. Installation: Never install Kali tools automatically. Show the package and installation hint, and let the operator decide whether to install it.
16. Reporting: Present findings systematically in clear GitHub-flavored Markdown. Group results with bullet points or tables, and provide clear remediation guidance.
"""


class LokiAgent:
    """
    Autonomous ReAct execution harness.
    Coordinates between LLM providers, tool calls, and state management.
    """

    def __init__(
        self,
        provider: Optional[Union[BaseLLMProvider, str]] = None,
        tools: Optional[List[Tool]] = None,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        max_steps: int = 10,
        temperature: float = 0.2,
        memory_store: Optional[MemoryStore] = None,
        gateway: Optional[ExecutionGateway] = None,
        include_builtins: bool = True,
        include_security_tools: bool = True,
        tool_learning: Optional[ToolPerformanceMemory] = None,
        max_adaptive_continuations: Optional[int] = None,
    ):
        if isinstance(provider, str):
            self.provider = get_provider(provider)
        elif provider is not None:
            self.provider = provider
        else:
            self.provider = get_provider(settings.default_provider)

        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self.temperature = temperature
        self.memory_store = memory_store or MemoryStore()
        self.tool_learning = tool_learning or tool_performance_memory
        continuation_budget = settings.max_adaptive_continuations if max_adaptive_continuations is None else max_adaptive_continuations
        self.max_adaptive_continuations = max(0, min(int(continuation_budget), 12))

        self.security_context = AssessmentSecurityContext.get_default()
        self._follow_default_security_context = gateway is None
        self.gateway = gateway or self.security_context.gateway
        self.registry = ToolRegistry(gateway=self.gateway)
        if include_builtins:
            for bt in ALL_BUILTIN_TOOLS:
                self.registry.register(bt)
        if include_security_tools:
            for st in ALL_SECURITY_TOOLS:
                self.registry.register(st)
        if tools:
            for t in tools:
                self.registry.register(t)

        self._event_listeners: List[Callable[[AgentEvent], Any]] = []

    def _refresh_security_context(self) -> None:
        """
        Rebind a default-backed agent if the process-wide assessment context changed.

        CLI scope commands and security tools resolve the current default context.
        Refreshing here prevents an agent created before a context reset from
        continuing to authorize against an obsolete ScopeManager/Gateway.
        Explicitly supplied gateways remain bound to their caller-provided context.
        """
        if not self._follow_default_security_context:
            return

        current_context = AssessmentSecurityContext.get_default()
        if current_context is self.security_context:
            return

        self.security_context = current_context
        self.gateway = current_context.gateway
        self.registry.set_gateway(self.gateway)

    def _build_runtime_system_prompt(self, task_type: str = "general") -> str:
        """
        Add an authoritative snapshot of the live scope and policy to the prompt.

        The snapshot is rebuilt for every run so old chat history cannot override
        scope changes made through operator commands.
        """
        scope_manager = self.gateway.scope_manager
        config = scope_manager.config
        mode = getattr(self.gateway.policy_engine.mode, "value", str(self.gateway.policy_engine.mode))
        targets = sorted(config.targets)
        exclusions = sorted(config.excluded_targets)

        target_lines = "\n".join(f"- {target}" for target in targets) or "- None"
        exclusion_lines = "\n".join(f"- {target}" for target in exclusions) or "- None"

        return (
            f"{self.system_prompt.rstrip()}\n\n"
            "LIVE AUTHORIZATION SNAPSHOT (refreshed immediately before this run)\n"
            f"Assessment: {config.assessment_name}\n"
            f"Scope version: {config.version}\n"
            f"Execution mode: {str(mode).upper()}\n"
            f"Authorized targets ({len(targets)}):\n{target_lines}\n"
            f"Excluded targets ({len(exclusions)}):\n{exclusion_lines}\n"
            f"Subdomains allowed: {bool(config.allow_subdomains)}\n"
            f"Lab verification enabled: {bool(config.lab_mode_enabled)}\n\n"
            "This snapshot is the current operator-approved scope. Do not repeat an older "
            "target list from conversation history or claim that a listed target is out of "
            "scope based on stale context. Prefer the built-in authorization/DNS tools when "
            "checking a target. The Execution Gateway remains the final authority and may "
            "still reject an address that resolves into a forbidden or excluded network.\n\n"
            f"CURRENT OBJECTIVE CATEGORY: {task_type}\n"
            "LEARNED TOOL EFFECTIVENESS (privacy-preserving local history):\n"
            f"{self.tool_learning.format_guidance(task_type)}\n\n"
            "When the objective is unresolved, use a different source/method rather than stopping after one failed lookup. "
            "Do not repeat failed methods without a new hypothesis. Use learned rankings to choose the next candidate, "
            "but verify every result and remain within scope.\n"
        )

    @staticmethod
    def _looks_unresolved(task_type: str, response: str) -> bool:
        value = (response or "").lower()
        blocked = (
            "scope violation", "out of scope", "authorization denied",
            "authorization error", "policy violation",
        )
        if any(marker in value for marker in blocked):
            return False

        terminal = (
            "all safe methods exhausted", "no further safe method",
            "no more authorized methods", "remaining methods are blocked",
            "no additional supported tools",
        )
        if any(marker in value for marker in terminal):
            return False

        unresolved = (
            "unable to", "cannot find", "can't find", "could not find",
            "couldn't find", "can't be found", "could not resolve", "unable to resolve",
            "no results", "no result", "not found", "not identified",
            "cannot determine", "can't determine", "unknown", "inconclusive",
            "origin remains unknown", "origin could not be confirmed",
            "does not reveal the origin", "did not reveal the origin",
            "edge address only", "not enough evidence", "not verified",
            "couldn't identify",
        )
        if any(marker in value for marker in unresolved):
            return True

        if task_type == "origin_ip_verification":
            mentions_cdn = any(
                marker in value for marker in ("cdn", "cloudflare", "cloudfront", "fastly", "akamai")
            )
            verified_origin = any(
                marker in value for marker in ("owner inventory", "authoritative origin record", "origin ip verified")
            )
            return mentions_cdn and not verified_origin
        return False

    @staticmethod
    def _continuation_message(
        task_type: str,
        outcomes: List[tuple[str, str]],
        continuation_number: int,
        max_continuations: int,
    ) -> str:
        ledger = ", ".join(f"{name}={outcome}" for name, outcome in outcomes[-20:]) or "No tools called yet"
        return (
            f"INVESTIGATION CONTINUATION {continuation_number}/{max_continuations}. "
            f"The primary objective ({task_type}) is still unresolved. "
            f"Methods tried so far: {ledger}. "
            "Continue with a materially different, authorized method if one is available. "
            "Do not repeat a no-result/error method without a new hypothesis; consult the updated "
            "tool-effectiveness memory and prioritize methods with prior useful results. "
            "Separate the primary objective from additional useful observations. "
            "If every remaining method is blocked or unsafe, stop and explain the limitation honestly."
        )

    def add_listener(self, listener: Callable[[AgentEvent], Any]) -> None:
        """Register a callback to receive real-time execution events."""
        self._event_listeners.append(listener)

    def remove_listener(self, listener: Callable[[AgentEvent], Any]) -> None:
        if listener in self._event_listeners:
            self._event_listeners.remove(listener)

    async def _emit(self, event_type: EventType, run_id: str, data: dict) -> AgentEvent:
        event = AgentEvent(event_type=event_type, run_id=run_id, data=data)
        for listener in self._event_listeners:
            try:
                res = listener(event)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
        return event

    async def run(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        context: Optional[AgentContext] = None,
    ) -> RunResult:
        """Execute the agent loop until task completion or step limit reached."""
        run_id = f"run_{uuid.uuid4().hex[:10]}"
        start_time = time.perf_counter()

        await self._emit(
            EventType.RUN_START,
            run_id,
            {"prompt": prompt, "model": self.provider.model, "session_id": session_id},
        )

        # Resolve shared authorization and task-specific learning before loading history.
        self._refresh_security_context()
        task_type = classify_task(prompt)
        runtime_system_prompt = self._build_runtime_system_prompt(task_type)
        tool_outcomes: List[tuple[str, str]] = []
        continuation_count = 0

        # Initialize or load context
        if context is None:
            if session_id:
                context = self.memory_store.load_session(
                    session_id, system_prompt=runtime_system_prompt
                )
            else:
                context = AgentContext(system_prompt=runtime_system_prompt)

        # Replace any saved/stale system message with the current live authorization snapshot.
        context.set_system_prompt(runtime_system_prompt)
        context.add_user_message(prompt)

        steps: List[AgentStep] = []
        total_usage = TokenUsage()
        tool_schemas = self.registry.get_schemas()

        current_status = RunStatus.SUCCESS
        final_answer = ""
        error_msg = None

        try:
            for step_idx in range(1, self.max_steps + 1):
                step_start_time = time.perf_counter()
                await self._emit(
                    EventType.STEP_START,
                    run_id,
                    {"step_number": step_idx, "max_steps": self.max_steps},
                )

                # 1. Ask Provider for next action
                try:
                    response: LLMResponse = await self.provider.chat_complete(
                        messages=context.get_messages(),
                        tools=tool_schemas if tool_schemas else None,
                        temperature=self.temperature,
                    )
                except Exception as e:
                    error_msg = f"LLM error during step {step_idx}: {str(e)}"
                    current_status = RunStatus.ERROR
                    if not final_answer:
                        final_answer = error_msg
                    await self._emit(EventType.ERROR, run_id, {"error": error_msg})
                    break

                # Accumulate token usage
                total_usage.prompt_tokens += response.usage.prompt_tokens
                total_usage.completion_tokens += response.usage.completion_tokens
                total_usage.total_tokens += response.usage.total_tokens

                thought = response.content or ""
                if thought:
                    await self._emit(
                        EventType.THOUGHT,
                        run_id,
                        {"step_number": step_idx, "thought": thought},
                    )

                # 2. Check if tools need to be called
                if response.tool_calls:
                    tool_results: List[ToolResult] = []

                    # Record assistant message with tool calls in history
                    context.add_assistant_message(
                        content=thought, tool_calls=response.tool_calls
                    )

                    for tc in response.tool_calls:
                        await self._emit(
                            EventType.TOOL_CALL_START,
                            run_id,
                            {
                                "step_number": step_idx,
                                "tool_call_id": tc.id,
                                "tool_name": tc.name,
                                "arguments": tc.arguments,
                            },
                        )

                        # Execute tool through the existing policy/scope gateway.
                        t_res = await self.registry.execute_call(tc)
                        tool_results.append(t_res)

                        # Persist only task category, tool name, and a coarse outcome label.
                        learning_name = effective_tool_name(tc.name, tc.arguments)
                        outcome = classify_tool_outcome(
                            t_res.output,
                            is_error=t_res.is_error,
                            metadata=t_res.metadata,
                            task_type=task_type,
                        )
                        if tc.name in {
                            "discover_kali_tools", "get_kali_tool_details",
                            "check_kali_tool_availability", "search_security_tool_catalog",
                            "check_scope_authorization",
                        } and outcome == "success":
                            outcome = "partial"
                        try:
                            self.tool_learning.record(task_type, learning_name, outcome)
                        except Exception:
                            # Learning is advisory; a local disk error must not stop an assessment.
                            pass
                        tool_outcomes.append((learning_name, outcome))

                        # Add result and refresh learned priorities for the next model turn.
                        context.add_tool_result(t_res)
                        context.set_system_prompt(self._build_runtime_system_prompt(task_type))

                        await self._emit(
                            EventType.TOOL_CALL_END,
                            run_id,
                            {
                                "step_number": step_idx,
                                "tool_call_id": tc.id,
                                "tool_name": tc.name,
                                "output": t_res.output,
                                "is_error": t_res.is_error,
                                "execution_time_ms": t_res.execution_time_ms,
                            },
                        )

                    step_latency = (time.perf_counter() - step_start_time) * 1000
                    step_obj = AgentStep(
                        step_number=step_idx,
                        thought=thought,
                        tool_calls=response.tool_calls,
                        tool_results=tool_results,
                        latency_ms=step_latency,
                        token_usage=response.usage,
                    )
                    steps.append(step_obj)
                    await self._emit(
                        EventType.STEP_END,
                        run_id,
                        {"step_number": step_idx, "latency_ms": step_latency},
                    )

                else:
                    # No tool calls: final answer reached!
                    final_answer = thought
                    context.add_assistant_message(content=final_answer)

                    step_latency = (time.perf_counter() - step_start_time) * 1000
                    step_obj = AgentStep(
                        step_number=step_idx,
                        thought=thought,
                        tool_calls=[],
                        tool_results=[],
                        latency_ms=step_latency,
                        token_usage=response.usage,
                    )
                    steps.append(step_obj)
                    await self._emit(
                        EventType.STEP_END,
                        run_id,
                        {"step_number": step_idx, "latency_ms": step_latency},
                    )

                    unresolved = (
                        is_investigation_request(prompt)
                        and bool(self.registry.list_tools())
                        and self._looks_unresolved(task_type, final_answer)
                    )
                    if (
                        unresolved
                        and continuation_count < self.max_adaptive_continuations
                        and step_idx < self.max_steps
                    ):
                        continuation_count += 1
                        context.add_user_message(
                            self._continuation_message(
                                task_type,
                                tool_outcomes,
                                continuation_count,
                                self.max_adaptive_continuations,
                            )
                        )
                        final_answer = ""
                        continue
                    break
            else:
                # Reached max steps: Request final synthesis from model
                current_status = RunStatus.MAX_STEPS_REACHED
                try:
                    context.add_user_message(
                        "The configured investigation step budget has been reached. Synthesize the results now. "
                        "State whether the primary objective was verified, unresolved, or blocked; list distinct methods "
                        "tried and their outcomes; distinguish observations from inferences; include relevant additional "
                        "information; and explain which methods were not attempted and why. Never claim a CDN edge IP "
                        "is the protected origin."
                    )
                    synthesis_resp = await self.provider.chat_complete(
                        messages=context.get_messages(),
                        tools=None,
                        temperature=self.temperature,
                    )
                    final_answer = synthesis_resp.content or f"Reached execution limit ({self.max_steps} steps). See session history for findings."
                    context.add_assistant_message(content=final_answer)
                except Exception:
                    final_answer = f"Completed {len(steps)} investigation steps. Detailed observations have been recorded."

        except Exception as e:
            current_status = RunStatus.ERROR
            error_msg = f"Agent harness execution exception: {str(e)}"
            if not final_answer:
                final_answer = error_msg
            await self._emit(EventType.ERROR, run_id, {"error": error_msg})

        # Save session memory if requested
        if session_id:
            self.memory_store.save_session(session_id, context)

        total_latency = (time.perf_counter() - start_time) * 1000
        run_res = RunResult(
            run_id=run_id,
            status=current_status,
            final_response=final_answer,
            steps=steps,
            total_usage=total_usage,
            total_latency_ms=total_latency,
            error_message=error_msg,
        )

        await self._emit(
            EventType.RUN_END,
            run_id,
            {
                "status": current_status.value,
                "final_response": final_answer,
                "total_steps": len(steps),
                "total_tokens": total_usage.total_tokens,
                "total_latency_ms": total_latency,
            },
        )
        return run_res

    async def stream_events(
        self, prompt: str, session_id: Optional[str] = None
    ) -> AsyncIterator[AgentEvent]:
        """Async generator yielding AgentEvents as the run progresses."""
        queue: asyncio.Queue[Optional[AgentEvent]] = asyncio.Queue()

        def listener(evt: AgentEvent):
            queue.put_nowait(evt)

        self.add_listener(listener)

        async def _run_task():
            try:
                await self.run(prompt=prompt, session_id=session_id)
            finally:
                queue.put_nowait(None)

        task = asyncio.create_task(_run_task())

        try:
            while True:
                evt = await queue.get()
                if evt is None:
                    break
                yield evt
        finally:
            self.remove_listener(listener)
            await task
