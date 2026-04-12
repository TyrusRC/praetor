import os
from pathlib import Path

# Load .env from project root if it exists
_env_file = Path(__file__).resolve().parents[3] / ".env"
if _env_file.is_file():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

BURP_API_HOST = os.environ.get("BURP_API_HOST", "127.0.0.1")
BURP_API_PORT = int(os.environ.get("BURP_API_PORT", "8111"))
BURP_API_TIMEOUT = int(os.environ.get("BURP_API_TIMEOUT", "30"))
BURP_MAX_RESPONSE_SIZE = int(os.environ.get("BURP_MAX_RESPONSE_SIZE", "50000"))
BURP_PROXY_HOST = os.environ.get("BURP_PROXY_HOST", "127.0.0.1")
BURP_PROXY_PORT = int(os.environ.get("BURP_PROXY_PORT", "8080"))

BASE_URL = f"http://{BURP_API_HOST}:{BURP_API_PORT}"
BURP_PROXY_URL = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
