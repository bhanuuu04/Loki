"""
Core domain types and data contracts for Loki Agent Harness.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
import time


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    call_id: str
    tool_name: str
    output: Any
    is_error: bool = False
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    role: Role
    content: Optional[str] = ""
    name: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"role": self.role.value, "content": self.content or ""}
        if self.name:
            data["name"] = self.name
        if self.tool_calls:
            data["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments},
                }
                for tc in self.tool_calls
            ]
        if self.tool_call_id:
            data["tool_call_id"] = self.tool_call_id
        return data


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class LLMResponse(BaseModel):
    content: Optional[str] = ""
    tool_calls: List[ToolCall] = Field(default_factory=list)
    usage: TokenUsage = Field(default_factory=TokenUsage)
    latency_ms: float = 0.0
    model: str = ""


class AgentStep(BaseModel):
    step_number: int
    thought: Optional[str] = None
    tool_calls: List[ToolCall] = Field(default_factory=list)
    tool_results: List[ToolResult] = Field(default_factory=list)
    latency_ms: float = 0.0
    token_usage: TokenUsage = Field(default_factory=TokenUsage)


class RunStatus(str, Enum):
    SUCCESS = "success"
    MAX_STEPS_REACHED = "max_steps_reached"
    ERROR = "error"
    INTERRUPTED = "interrupted"


class RunResult(BaseModel):
    run_id: str
    status: RunStatus
    final_response: str
    steps: List[AgentStep] = Field(default_factory=list)
    total_usage: TokenUsage = Field(default_factory=TokenUsage)
    total_latency_ms: float = 0.0
    error_message: Optional[str] = None


class EventType(str, Enum):
    RUN_START = "run_start"
    STEP_START = "step_start"
    LLM_TOKEN = "llm_token"
    THOUGHT = "thought"
    TOOL_CALL_START = "tool_call_start"
    TOOL_CALL_END = "tool_call_end"
    STEP_END = "step_end"
    RUN_END = "run_end"
    ERROR = "error"


class AgentEvent(BaseModel):
    event_type: EventType
    run_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class GraderType(str, Enum):
    EXACT_MATCH = "exact_match"
    CONTAINS = "contains"
    REGEX = "regex"
    CODE_ASSERT = "code_assert"
    LLM_JUDGE = "llm_judge"


class EvalCase(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    prompt: str
    expected_output: Optional[str] = None
    grader_type: GraderType = GraderType.CONTAINS
    grader_config: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class EvalResult(BaseModel):
    case_id: str
    passed: bool
    score: float  # 0.0 to 1.0
    reason: str
    run_result: RunResult
    duration_ms: float
