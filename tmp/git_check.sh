#!/bin/bash
cd /srv/claude-bot/worktrees/WasmAgent_wasmagent-proxy
git log --oneline -5 2>&1
echo "---"
git diff HEAD 2>&1
echo "---"
git status --short 2>&1