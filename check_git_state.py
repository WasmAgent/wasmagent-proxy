#!/usr/bin/env python3
import subprocess
import os

os.chdir('/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy')

# Check git status
result = subprocess.run(['git', 'status', '--short'], capture_output=True, text=True)
print("=== git status --short ===")
print(result.stdout)
print(result.stderr)

# Check git diff stat
result = subprocess.run(['git', 'diff', '--stat'], capture_output=True, text=True)
print("=== git diff --stat ===")
print(result.stdout)
print(result.stderr)

# Check git log
result = subprocess.run(['git', 'log', '--oneline', '-5'], capture_output=True, text=True)
print("=== git log -5 ===")
print(result.stdout)
print(result.stderr)

# Check git diff for specific files
result = subprocess.run(['git', 'diff', '--', '.claude-bot/verify.yml'], capture_output=True, text=True)
print("=== git diff .claude-bot/verify.yml ===")
print(result.stdout)
print(result.stderr)
