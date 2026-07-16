#!/usr/bin/env python3
import subprocess
import sys

cwd = "/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy"

result = subprocess.run(["git", "status", "--short"], capture_output=True, text=True, cwd=cwd)
print("=== STATUS ===")
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

result2 = subprocess.run(["git", "diff", "--stat"], capture_output=True, text=True, cwd=cwd)
print("=== DIFF ===")
print(result2.stdout)

result3 = subprocess.run(["git", "log", "--oneline", "-5"], capture_output=True, text=True, cwd=cwd)
print("=== LOG ===")
print(result3.stdout)

result4 = subprocess.run(["git", "branch", "-a"], capture_output=True, text=True, cwd=cwd)
print("=== BRANCH ===")
print(result4.stdout)
