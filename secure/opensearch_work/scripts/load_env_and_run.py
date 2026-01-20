#!/usr/bin/env python3
"""
Load environment variables from .env file and run a script.

Usage:
    python3 load_env_and_run.py <script_to_run> [script_args...]
"""

import os
import sys
import subprocess
from pathlib import Path


def load_env_file(env_file_path: str = None):
    """Load environment variables from a .env file."""
    if env_file_path is None:
        # Look for .env in opensearch_work directory
        script_dir = Path(__file__).parent
        opensearch_work_dir = script_dir.parent
        env_file_path = opensearch_work_dir / '.env'

    env_file = Path(env_file_path)

    if not env_file.exists():
        print(f"Warning: .env file not found at {env_file}")
        print("Please create a .env file or set environment variables manually.")
        return False

    print(f"Loading environment variables from {env_file}")

    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                os.environ[key] = value
                print(f"  Loaded: {key}")

    return True


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python3 load_env_and_run.py <script_to_run> [script_args...]")
        sys.exit(1)

    script_to_run = sys.argv[1]
    script_args = sys.argv[2:]

    # Try to load .env file
    load_env_file()

    # Run the script
    print(f"\nRunning: {script_to_run} {' '.join(script_args)}")
    print("=" * 60)

    result = subprocess.run([sys.executable, script_to_run] + script_args)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
