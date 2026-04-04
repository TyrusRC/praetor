import os

BURP_API_HOST = os.environ.get("BURP_API_HOST", "127.0.0.1")
BURP_API_PORT = int(os.environ.get("BURP_API_PORT", "8111"))
BURP_API_TIMEOUT = int(os.environ.get("BURP_API_TIMEOUT", "30"))
BURP_MAX_RESPONSE_SIZE = int(os.environ.get("BURP_MAX_RESPONSE_SIZE", "50000"))

BASE_URL = f"http://{BURP_API_HOST}:{BURP_API_PORT}"
