import os
from pathlib import Path


def _load_env():
    """Load .env file by searching upward from this file to the project root.
    Uses os.environ[] direct set (not setdefault) so .env always takes effect
    unless overridden by explicit env vars from .mcp.json."""
    current = Path(__file__).resolve().parent
    for _ in range(6):  # search up to 6 levels
        env_file = current / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip()
                    # Set if not already in environment (from .mcp.json or shell)
                    if key not in os.environ or not os.environ[key]:
                        os.environ[key] = value
            return
        current = current.parent


_load_env()

def _intenv(key: str, default: int) -> int:
    """Parse int env var; fall back to default on missing/malformed."""
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


BURP_API_HOST = os.environ.get("BURP_API_HOST", "127.0.0.1")
BURP_API_PORT = _intenv("BURP_API_PORT", 8111)
BURP_API_TIMEOUT = _intenv("BURP_API_TIMEOUT", 30)
# Default proxy host to same as API host (they're almost always the same machine)
BURP_PROXY_HOST = os.environ.get("BURP_PROXY_HOST", BURP_API_HOST)
BURP_PROXY_PORT = _intenv("BURP_PROXY_PORT", 8080)

BASE_URL = f"http://{BURP_API_HOST}:{BURP_API_PORT}"
BURP_PROXY_URL = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
