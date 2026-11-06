"""
Benchmark suite and evaluation dataset representation.
"""

from typing import List, Optional
import json
from pathlib import Path
from pydantic import BaseModel, Field
from loki.types import EvalCase


class BenchmarkSuite(BaseModel):
    name: str
    description: str = ""
    cases: List[EvalCase] = Field(default_factory=list)

    @classmethod
    def from_json(cls, json_path_or_str: str) -> "BenchmarkSuite":
        path = Path(json_path_or_str)
        if path.exists() and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = json.loads(json_path_or_str)
        return cls(**data)

    def to_json(self, file_path: Optional[str] = None) -> str:
        data = self.model_dump_json(indent=2)
        if file_path:
            Path(file_path).write_text(data, encoding="utf-8")
        return data
