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
1. Scope & Verification: Always ensure targets are authorized. When the user specifies or requests an assessment on a target in chat (e.g. "target is schoolknot.com", "schoolknot.com is in authorized scope", "find subdomains for example.com"), immediately authorize it using `authorize_target(target="...")` and proceed directly with the assessment.
2. Built-in Tools: Always prefer built-in tools (e.g. enumerate_subdomains, dns_lookup, audit_http_security_headers) for reconnaissance instead of guessing external commands.
3. System Environment: You operate in an interactive user shell without root/sudo access. Never run package manager installations (e.g. `apt-get install`, `dnf`, `brew`) as they fail due to permission locks. If an external tool is missing on PATH, use alternative built-in modules or inform the user how they can install it with sudo.
4. Python Scripts: When using python_exec, write clean, robust, and complete Python scripts that handle exceptions gracefully and print concise results.
5. Reporting: Present findings systematically in clear GitHub-flavored Markdown. Group results with bullet points or tables, and provide clear remediation guidance.
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
        include_builtins: bool = True,
        include_security_tools: bool = True,
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

        self.registry = ToolRegistry()
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

        # Initialize or load context
        if context is None:
            if session_id:
                context = self.memory_store.load_session(session_id, system_prompt=self.system_prompt)
            else:
                context = AgentContext(system_prompt=self.system_prompt)

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

                        # Execute tool
                        t_res = await self.registry.execute_call(tc)
                        tool_results.append(t_res)

                        # Add tool result to context history
                        context.add_tool_result(t_res)

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
                    break
            else:
                # Reached max steps without completing
                current_status = RunStatus.MAX_STEPS_REACHED
                final_answer = "Max step limit reached before agent concluded execution."

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
