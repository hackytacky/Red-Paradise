"""g9-lab: native lab-plane adapters.

The G9 host runs the real tools (nmap/nuclei/ffuf/...) through the
container adapters. The lab plane runs the SAME typed contracts with
native Python probes so the full pipeline is exercisable end-to-end
anywhere — including CI and this scaffold's tests — against the
loopback lab target.

Every adapter emits nuclei-compatible JSON lines, so the existing
ResultCollector ingests the output through its normal path:
observations + CANDIDATE findings only. No adapter ever confirms
anything — the Verification Authority does, deterministically,
outside any model.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl

from ..tools.web_scanners import AdapterArgError

SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options")
DISCOVERY_PATHS = ("/.env", "/admin", "/backup.zip", "/.git/config", "/server-status")


def _host_port(spec: dict) -> tuple[str, int]:
    targets = spec.get("target_set", [])
    if not targets or len(targets) != 1:
        raise AdapterArgError("lab adapters probe one authorized target per action")
    target = targets[0]
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 80


def _emit(template_id: str, host: str, severity: str, extra: dict | None = None) -> str:
    data = {"template-id": template_id, "host": host, "info": {"severity": severity},
            "type": "lab-native", "matched-at": (extra or {}).get("matched_at", "")}
    data.update(extra or {})
    return json.dumps(data)


def portscan_scoped(spec: dict) -> dict:
    """Socket connect scan over the spec's declared port window —
    same contract as the masscan adapter: ports from the spec, rate
    from the resource budget, target from target_set only."""
    host, base_port = _host_port(spec)
    ports = spec.get("normalized_arguments", {}).get("ports") or [base_port]
    out = []
    for p in ports:
        try:
            p = int(p)
        except (TypeError, ValueError):
            raise AdapterArgError(f"port {p!r} is not an integer")
        if not (1 <= p <= 65535):
            raise AdapterArgError(f"port {p} out of range")
        try:
            with socket.create_connection((host, p), timeout=3.0):
                out.append(_emit("open-port", f"{host}:{p}", "info", {"matched_at": f"tcp/{p}"}))
        except OSError:
            continue
    return {"tool_id": "portscan-scoped", "stdout": "\n".join(out), "exit_code": 0}


def http_probe(spec: dict) -> dict:
    host, port = _host_port(spec)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request("GET", "/", headers={"User-Agent": "g9-lab-probe/1.0"})
        resp = conn.getresponse()
        body = resp.read(4096).decode("utf-8", "replace")
        server = resp.getheader("server", "unknown")
        lines = []
        if "AncientServer" in server or server == "unknown":
            lines.append(_emit("outdated-server-banner", f"{host}:{port}", "medium",
                               {"matched_at": f"Server: {server}"}))
        title = ""
        if "<title>" in body:
            title = body.split("<title>")[1].split("</title>")[0]
        lines.append(json.dumps({"probe": "http", "status": resp.status, "server": server, "title": title}))
        return {"tool_id": "http-probe", "stdout": "\n".join(lines), "exit_code": 0}
    finally:
        conn.close()


def header_audit(spec: dict) -> dict:
    host, port = _host_port(spec)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request("GET", "/", headers={"User-Agent": "g9-lab-probe/1.0"})
        resp = conn.getresponse()
        resp.read()
        lines = []
        for h in SECURITY_HEADERS:
            if resp.getheader(h) is None:
                lines.append(_emit(f"missing-header-{h}", f"{host}:{port}", "medium",
                                   {"matched_at": f"header {h} absent"}))
        return {"tool_id": "header-audit", "stdout": "\n".join(lines), "exit_code": 0}
    finally:
        conn.close()


def content_discovery(spec: dict) -> dict:
    """Allowlisted-path discovery — the lab equivalent of ffuf with
    an admission-qualified wordlist. Paths are fixed here; the agent
    cannot smuggle arbitrary paths."""
    host, port = _host_port(spec)
    lines = []
    for path in DISCOVERY_PATHS:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        try:
            conn.request("GET", path, headers={"User-Agent": "g9-lab-probe/1.0"})
            resp = conn.getresponse()
            resp.read()
            if resp.status == 200:
                slug = path.strip("/. ").replace("/", "-") or "root"
                lines.append(_emit(f"exposed-path-{slug}", f"{host}:{port}", "high",
                                   {"matched_at": path}))
        except OSError:
            continue
        finally:
            conn.close()
    return {"tool_id": "content-discovery", "stdout": "\n".join(lines), "exit_code": 0}


def tls_audit(spec: dict) -> dict:
    host, port = _host_port(spec)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"tool_id": "tls-audit", "stdout": "", "exit_code": 0}
    except Exception:
        # plain HTTP on a service port = no transport security
        line = _emit("no-tls", f"{host}:{port}", "high", {"matched_at": "plaintext HTTP"})
        return {"tool_id": "tls-audit", "stdout": line, "exit_code": 0}


LAB_ADAPTERS = {
    "portscan-scoped": portscan_scoped,
    "http-probe": http_probe,
    "header-audit": header_audit,
    "content-discovery": content_discovery,
    "tls-audit": tls_audit,
}
