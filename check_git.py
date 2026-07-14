#!/usr/bin/env python3
"""Check_git helper for CI validation."""
import subprocess
import sys

def main():
    result = subprocess.run(["git", "diff", "--stat"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        sys.exit(1)
    # Check if there are any changes
    if result.stdout.strip():
        print("Changes detected (non-empty diff)")
    else:
        print("No changes detected (empty diff)")

if __name__ == "__main__":
    main()
