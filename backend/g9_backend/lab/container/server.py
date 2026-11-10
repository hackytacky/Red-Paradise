"""Containerized lab target — mirrors g9_backend/lab/target.py:
missing security headers, exposed /.env, /admin, /backup.zip,
ancient banner, no TLS. Loopback-safe: only reachable inside the
compose network."""
import http.server

INDEX = b"<!doctype html><html><head><title>Lab Tenant Portal</title></head><body><h1>Lab Tenant Portal</h1><a href='/admin'>admin</a></body></html>"
ADMIN = b"<!doctype html><html><head><title>Admin</title></head><body><h1>Admin panel</h1>unauthenticated admin surface</body></html>"
ENV = b"DB_PASSWORD=lab-fake-secret-not-real\n"
BACKUP = b"PK\x03\x04lab-backup-archive"


class H(http.server.BaseHTTPRequestHandler):
    server_version = "AncientServer/1.0"

    def log_message(self, *a):
        pass

    def _r(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        routes = {"/": INDEX, "/admin": ADMIN, "/.env": ENV, "/backup.zip": BACKUP,
                  "/robots.txt": b"User-agent: *\nDisallow: /admin\n"}
        if self.path in routes:
            self._r(200, routes[self.path])
        else:
            self._r(404, b"not found")


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
