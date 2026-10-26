"""Built-in OOB HTTP callback server for Burp Community users.

When Burp Collaborator is unavailable (Community edition, air-gapped), this
spins up a lightweight HTTP listener that records every inbound request. The
agent uses it exactly like Collaborator: generate a unique path, inject it
into the blind payload, then poll for hits.

The server binds to 0.0.0.0 on a high port (default 9999) so external targets
can reach it. The operator must ensure the port is reachable from the target
(port-forward, ngrok, or same-network).
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Optional


@dataclass
class OobHit:
    interaction_id: str
    timestamp: float
    client_ip: str
    method: str
    path: str
    headers: dict[str, str]
    body: str
    query: str


@dataclass
class LocalOobServer:
    port: int = 9999
    host: str = "0.0.0.0"
    _server: Optional[HTTPServer] = field(default=None, repr=False)
    _thread: Optional[Thread] = field(default=None, repr=False)
    _hits: list[OobHit] = field(default_factory=list, repr=False)
    _running: bool = False

    def start(self) -> str:
        if self._running:
            return f"OOB server already running on :{self.port}"
        hits = self._hits
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record("GET")

            def do_POST(self):
                self._record("POST")

            def do_PUT(self):
                self._record("PUT")

            def do_HEAD(self):
                self._record("HEAD")

            def do_OPTIONS(self):
                self._record("OPTIONS")

            def _record(self, method: str):
                content_len = int(self.headers.get("Content-Length", 0))
                body = ""
                if content_len > 0:
                    body = self.rfile.read(min(content_len, 65536)).decode(
                        "utf-8", errors="replace"
                    )
                path = self.path
                query = ""
                if "?" in path:
                    path, query = path.split("?", 1)
                hdrs = {k: v for k, v in self.headers.items()}
                hit = OobHit(
                    interaction_id=path.strip("/").split("/")[0] if "/" in path else path.strip("/"),
                    timestamp=time.time(),
                    client_ip=self.client_address[0],
                    method=method,
                    path=self.path,
                    headers=hdrs,
                    body=body,
                    query=query,
                )
                hits.append(hit)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        try:
            self._server = HTTPServer((self.host, self.port), Handler)
        except OSError as e:
            return f"Failed to bind OOB server on {self.host}:{self.port}: {e}"
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True
        return f"OOB callback server started on {self.host}:{self.port}"

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._running = False

    def generate_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def get_hits(self, interaction_id: str = "") -> list[OobHit]:
        if not interaction_id:
            return list(self._hits)
        return [h for h in self._hits if h.interaction_id == interaction_id]

    def clear(self):
        self._hits.clear()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def hit_count(self) -> int:
        return len(self._hits)


_LOCAL_OOB: LocalOobServer | None = None


def get_local_oob() -> LocalOobServer:
    global _LOCAL_OOB
    if _LOCAL_OOB is None:
        port = int(os.environ.get("PRAETOR_OOB_PORT", "9999"))
        _LOCAL_OOB = LocalOobServer(port=port)
    return _LOCAL_OOB
