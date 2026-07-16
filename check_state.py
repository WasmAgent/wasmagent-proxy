#!/usr/bin/env python3
import subprocess
result = subprocess.run(['git', '-C', '/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy', 'status', '--short'], capture_output=True, text=True)
print(result.stdout)
result2 = subprocess.run(['git', '-C', '/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy', 'diff', '--stat'], capture_output=True, text=True)
print(result2.stdout)
result3 = subprocess.run(['git', '-C', '/srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy', 'log', '--oneline', '-10'], capture_output=True, text=True)
print(result3.stdout)
