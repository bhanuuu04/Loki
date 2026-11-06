@echo off
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe -m loki %*
) else (
    python -m loki %*
)
