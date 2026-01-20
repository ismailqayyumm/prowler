"""
Helper to load environment variables from .env file if it exists
"""
import os
from pathlib import Path

def load_env_file():
    """Load .env file from project root if it exists."""
    # Try to find .env file in project root
    project_root = Path(__file__).parent.parent
    env_file = project_root / ".env"

    if env_file.exists():
        print(f"Loading environment variables from {env_file}")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value
        return True
    return False
