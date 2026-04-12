import os
from pathlib import Path


def _load_env():
    """Load .env file by searching upward from this file to the project root."""
    current = Path(__file__).resolve().parent
    for _ in range(6):  # search up to 6 levels
        env_file = current / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())
            return
        current = current.parent


_load_env()

BURP_API_HOST = os.environ.get("BURP_API_HOST", "127.0.0.1")
BURP_API_PORT = int(os.environ.get("BURP_API_PORT", "8111"))
BURP_API_TIMEOUT = int(os.environ.get("BURP_API_TIMEOUT", "30"))
BURP_MAX_RESPONSE_SIZE = int(os.environ.get("BURP_MAX_RESPONSE_SIZE", "50000"))
# Default proxy host to same as API host (they're almost always the same machine)
BURP_PROXY_HOST = os.environ.get("BURP_PROXY_HOST", BURP_API_HOST)
BURP_PROXY_PORT = int(os.environ.get("BURP_PROXY_PORT", "8080"))

BASE_URL = f"http://{BURP_API_HOST}:{BURP_API_PORT}"
BURP_PROXY_URL = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
