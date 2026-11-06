import pytest
from loki.tools.base import tool, Tool
from loki.tools.registry import ToolRegistry
from loki.tools.builtins.math_tools import calculator
from loki.types import ToolCall


def test_tool_decorator_schema():
    @tool(name="add_nums", description="Adds two numbers")
    def add(a: int, b: int) -> int:
        return a + b

    assert add.name == "add_nums"
    assert add.description == "Adds two numbers"
    assert not add.is_async

    schema = add.to_openai_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "add_nums"
    assert "a" in schema["function"]["parameters"]["properties"]
    assert "b" in schema["function"]["parameters"]["properties"]


@pytest.mark.asyncio
async def test_tool_execution():
    registry = ToolRegistry()
    registry.register(calculator)

    # Valid execution
    call = ToolCall(id="c1", name="calculator", arguments={"expression": "10 * 5 + 2"})
    result = await registry.execute_call(call)
    assert not result.is_error
    assert result.output == "52"
    assert result.call_id == "c1"

    # Tool not found error handling
    call_missing = ToolCall(id="c2", name="non_existent_tool", arguments={})
    res_missing = await registry.execute_call(call_missing)
    assert res_missing.is_error
    assert "not found" in res_missing.output


def test_python_exec_isolated_subprocess():
    from loki.tools.builtins.python_tools import python_exec
    output = python_exec("print('isolated_calc:', 12 * 12)")
    assert "isolated_calc: 144" in output


@pytest.mark.asyncio
async def test_dns_lookup_and_scope():
    from loki.tools.security_tools import dns_lookup, scope_mgr, ScopeConfig
    scope_mgr.set_config(ScopeConfig(assessment_name="DNS Test", targets=["localhost", "127.0.0.1"]))
    res = await dns_lookup("localhost")
    assert "127.0.0.1" in res or "localhost" in res
