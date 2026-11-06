"""
Graders and evaluation verification logic for Loki.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import re
from loki.types import EvalCase, RunResult


class BaseGrader(ABC):
    @abstractmethod
    async def grade(self, case: EvalCase, result: RunResult) -> tuple[bool, float, str]:
        """
        Returns (passed: bool, score: float [0.0 - 1.0], reason: str).
        """
        pass


class ExactMatchGrader(BaseGrader):
    async def grade(self, case: EvalCase, result: RunResult) -> tuple[bool, float, str]:
        expected = (case.expected_output or "").strip()
        actual = result.final_response.strip()
        case_sensitive = case.grader_config.get("case_sensitive", False)

        if not case_sensitive:
            expected = expected.lower()
            actual = actual.lower()

        passed = expected == actual
        score = 1.0 if passed else 0.0
        reason = f"Exact match {'succeeded' if passed else 'failed'}. Expected: '{case.expected_output}', Actual: '{result.final_response}'"
        return passed, score, reason


class ContainsGrader(BaseGrader):
    async def grade(self, case: EvalCase, result: RunResult) -> tuple[bool, float, str]:
        expected = (case.expected_output or "").strip()
        actual = result.final_response
        case_sensitive = case.grader_config.get("case_sensitive", False)

        if not case_sensitive:
            expected = expected.lower()
            actual = actual.lower()

        passed = expected in actual
        score = 1.0 if passed else 0.0
        reason = (
            f"Found '{case.expected_output}' in response."
            if passed
            else f"Expected substring '{case.expected_output}' not found in: '{result.final_response}'"
        )
        return passed, score, reason


class RegexGrader(BaseGrader):
    async def grade(self, case: EvalCase, result: RunResult) -> tuple[bool, float, str]:
        pattern = case.expected_output or case.grader_config.get("pattern", "")
        if not pattern:
            return False, 0.0, "No regex pattern provided in case expected_output or grader_config."

        flags = 0 if case.grader_config.get("case_sensitive", False) else re.IGNORECASE
        match = re.search(pattern, result.final_response, flags=flags)
        passed = bool(match)
        score = 1.0 if passed else 0.0
        reason = (
            f"Pattern '{pattern}' matched text: '{match.group(0)}'"
            if match
            else f"Pattern '{pattern}' did not match output: '{result.final_response}'"
        )
        return passed, score, reason


class CodeAssertGrader(BaseGrader):
    async def grade(self, case: EvalCase, result: RunResult) -> tuple[bool, float, str]:
        code = case.grader_config.get("code", "")
        if not code:
            return False, 0.0, "No assertion code provided in grader_config['code']."

        local_vars = {"result": result, "response": result.final_response, "steps": result.steps}
        try:
            exec(code, {"__builtins__": __builtins__}, local_vars)
            return True, 1.0, "Code assertions passed successfully."
        except AssertionError as ae:
            return False, 0.0, f"Assertion failed: {str(ae) or 'AssertionError'}"
        except Exception as e:
            return False, 0.0, f"Evaluation script error: {type(e).__name__}: {str(e)}"
