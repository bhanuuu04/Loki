"""
Built-in calculator and web request tools.
"""

import ast
import operator
import httpx
from loki.tools.base import tool


# Safe math operators
_MATH_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval_math(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _safe_eval_math(node.body)
    elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _MATH_OPERATORS:
            raise ValueError(f"Unsupported math operator: {op_type.__name__}")
        left = _safe_eval_math(node.left)
        right = _safe_eval_math(node.right)
        return _MATH_OPERATORS[op_type](left, right)
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _MATH_OPERATORS:
            raise ValueError(f"Unsupported unary operator: {op_type.__name__}")
        operand = _safe_eval_math(node.operand)
        return _MATH_OPERATORS[op_type](operand)
    else:
        raise ValueError(f"Unsupported syntax in math expression: {type(node).__name__}")


@tool(name="calculator", description="Safely evaluate a mathematical expression like '2 + 2 * 10' or '(100 - 25) / 5'.")
def calculator(expression: str) -> str:
    """Evaluate safe arithmetic expressions."""
    try:
        expr = expression.strip()
        tree = ast.parse(expr, mode="eval")
        result = _safe_eval_math(tree)
        # Format whole floats as ints for cleaner output
        if isinstance(result, float) and result.is_integer():
            return str(int(result))
        return str(result)
    except Exception as e:
        return f"Calculation error: {str(e)}"


@tool(name="http_get", description="Send an HTTP GET request to a URL and return status code and response body.")
async def http_get(url: str) -> str:
    """Fetch content from a web URL."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            text = resp.text
            if len(text) > 4000:
                text = text[:4000] + "\n...[truncated]"
            return f"Status: {resp.status_code}\n\n{text}"
    except Exception as e:
        return f"HTTP error: {type(e).__name__}: {str(e)}"
