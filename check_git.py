#!/usr/bin/env python3
import subprocess
import sys

result = subprocess.run(["git", "status", "--short"], capture_output=True, text=True, cwd="/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy")
print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)

result2 = subprocess.run(["git", "diff", "--stat"], capture_output=True, text=True, cwd="/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy")
print("DIFF STAT:", result2.stdout)

result3 = subprocess.run(["git", "log", "--oneline", "-5"], capture_output=True, text=True, cwd="/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy")
print("LOG:", result3.stdout)
