"""g9-lab: the loopback lab target — a deliberately flawed service the
full pipeline can really run against.

Loopback-only (binds 127.0.0.1, ephemeral ports). Planting real,
discoverable weaknesses so the full active run produces real
candidate findings through the real chain:

  - missing security headers (HSTS/CSP/X-Frame-Options)
  - an exposed /.env with a (fake) secret
  - an unlisted /admin panel
  - a downloadable /backup.zip
  - an outdated server banner
  - no TLS (plain HTTP)
  - a second "debug" port that shouldn't be exposed
"""

from __future__ import annotations

import http.server
import socketserver
import threading

INDEX = b"""<!doctype html><html><head><title>Lab Tenant Portal</title></head>
<body><h1>Lab Tenant Portal</h1><p>payment records demo app</p>
<a href="/admin">admin</a></body></html>"""

ADMIN = b"""<!doctype html><html><head><title>Admin</title></head>
<body><h1>Admin panel</h1>unauthenticated admin surface</body></html>"""

ENV = b"DB_PASSWORD=lab-fake-secret-not-real\nSTRIPE_KEY=sk_test_lab_fake\n"

BACKUP = b"PK\x03\x04lab-backup-archive"

DEBUG_BANNER = b"LabDebugConsole 1.0 - internal use only\n"


class LabHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AncientServer/1.0"

    def log_message(self, *a):  # quiet
        pass

    def _respond(self, code: int, body: bytes, ctype: str = "text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._respond(200, INDEX)
        elif self.path == "/admin":
            self._respond(200, ADMIN)
        elif self.path == "/.env":
            self._respond(200, ENV, "text/plain")
        elif self.path == "/backup.zip":
            self._respond(200, BACKUP, "application/zip")
        elif self.path == "/robots.txt":
            self._respond(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        else:
            self._respond(404, b"not found")


class DebugHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AncientServer/1.0"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(DEBUG_BANNER)))
        self.end_headers()
        self.wfile.write(DEBUG_BANNER)


class _Server(socketserver.TCPServer):
    allow_reuse_address = True


class LabTarget:
    """Two loopback services: the main HTTP app and an exposed debug port."""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.http: _Server | None = None
        self.debug: _Server | None = None

    def start(self) -> "LabTarget":
        self.http = _Server((self.host, 0), LabHandler)
        self.debug = _Server((self.host, 0), DebugHandler)
        for srv in (self.http, self.debug):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        return self

    @property
    def http_port(self) -> int:
        return self.http.server_address[1]

    @property
    def debug_port(self) -> int:
        return self.debug.server_address[1]

    def stop(self) -> None:
        for srv in (self.http, self.debug):
            if srv:
                srv.shutdown()
                srv.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
