"""Authenticated HTTP gateway and operator controls."""
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import Guard, Reviewer, Store, canonical, execute_tool


class App:
    def __init__(self, config, db_path):
        self.config = config
        self.store = Store(db_path)
        key = os.getenv("OPENAI_API_KEY")
        reviewer = Reviewer(key, config.get("review_model", "gpt-6-sol")) if key else None
        self.guard = Guard(config, self.store, reviewer)
        self.admin_key = os.environ[config.get("admin_key_env", "SNITCH_ADMIN_KEY")]
        if len(self.admin_key) < 24:
            raise ValueError("SNITCH_ADMIN_KEY must be at least 24 characters")
        self.agent_keys = {}
        for agent, env in config.get("agents", {}).items():
            token = os.environ[env]
            if len(token) < 24 or token == self.admin_key or token in self.agent_keys.values():
                raise ValueError("Agent keys must be unique and at least 24 characters")
            self.agent_keys[agent] = token
        if not self.agent_keys:
            raise ValueError("Configure at least one agent")
        self.webhook = config.get("alert_webhook_url")
        if self.webhook and not self.webhook.startswith("https://"):
            raise ValueError("Alert webhook URL must use HTTPS")
        self.webhook_secret = os.getenv(config.get("alert_webhook_secret_env", "SNITCH_WEBHOOK_SECRET"), "")
        if self.webhook:
            if len(self.webhook_secret) < 24:
                raise ValueError("Webhook signing secret must be at least 24 characters")
            threading.Thread(target=self.deliver_loop, daemon=True).start()

    def deliver_loop(self):
        while True:
            with self.store.lock:
                row = self.store.db.execute("SELECT id,payload,attempts FROM notices WHERE delivered IS NULL AND next_try<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
            if row:
                nid, payload, attempts = row
                signature = hmac.new(self.webhook_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
                req = urllib.request.Request(self.webhook, payload.encode(),
                                             {"Content-Type": "application/json", "X-Snitch-Signature": "sha256=" + signature})
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status // 100 != 2:
                            raise ValueError("Alert rejected")
                    with self.store.lock:
                        self.store.db.execute("UPDATE notices SET delivered=? WHERE id=?", (time.time(), nid))
                except Exception:
                    with self.store.lock:
                        self.store.db.execute("UPDATE notices SET attempts=?, next_try=? WHERE id=?", (attempts+1, time.time()+min(300, 2**min(attempts, 8)), nid))
            time.sleep(1)

    def identity(self, header):
        if not header.startswith("Bearer "):
            return None
        token = header[7:]
        if hmac.compare_digest(token, self.admin_key):
            return "operator"
        for agent, key in self.agent_keys.items():
            if hmac.compare_digest(token, key):
                return agent
        return None


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # Avoid printing credentials or payloads in server logs.

        def send(self, code, data):
            blob = canonical(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def body(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 65536:
                raise ValueError("Body must be 1..65536 bytes")
            obj = json.loads(self.rfile.read(length))
            if not isinstance(obj, dict):
                raise ValueError("Expected JSON object")
            return obj

        def do_GET(self):
            identity = app.identity(self.headers.get("Authorization", ""))
            if self.path == "/healthz":
                return self.send(200, {"ok": True})
            if identity != "operator":
                return self.send(401, {"error": "Unauthorized"})
            if self.path == "/v1/scores":
                return self.send(200, {"leaderboard": app.store.leaderboard()})
            if self.path == "/v1/reports":
                with app.store.lock:
                    rows = app.store.db.execute("SELECT id,reporter,subject,event_id,reason,status FROM reports ORDER BY id DESC LIMIT 100").fetchall()
                return self.send(200, {"reports": [dict(zip(("id","reporter","subject","event_id","reason","status"), r)) for r in rows]})
            if self.path == "/v1/audit":
                return self.send(200, app.store.verify())
            if self.path == "/v1/incidents":
                with app.store.lock:
                    rows = app.store.db.execute("SELECT id,ts,kind,agent,data FROM events WHERE kind IN ('hold','decision','tool_error') ORDER BY id DESC LIMIT 100").fetchall()
                    holds = app.store.db.execute("SELECT agent,reason,created FROM holds").fetchall()
                    pending = app.store.db.execute("SELECT count(*) FROM notices WHERE delivered IS NULL").fetchone()[0]
                return self.send(200, {"events": [{"id": r[0], "ts": r[1], "kind": r[2], "agent": r[3], "data": json.loads(r[4])} for r in rows],
                                       "holds": [{"agent": a, "reason": reason, "created": ts} for a, reason, ts in holds], "pending_alerts": pending})
            return self.send(404, {"error": "Unknown route"})

        def do_POST(self):
            identity = app.identity(self.headers.get("Authorization", ""))
            if identity is None:
                return self.send(401, {"error": "Unauthorized"})
            try:
                data = self.body()
                if self.path in ("/v1/check", "/v1/execute"):
                    if identity == "operator":
                        return self.send(403, {"error": "Use an agent key"})
                    proposal = {"tool": data.get("tool"), "arguments": data.get("arguments")}
                    if self.path == "/v1/check":
                        return self.send(200, app.guard.check(identity, proposal))
                    key = self.headers.get("Idempotency-Key", "")
                    if not (8 <= len(key) <= 128 and key.isascii() and key.isprintable()):
                        return self.send(400, {"error": "Idempotency-Key required (8..128 printable ASCII characters)"})
                    digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
                    # One execution at a time; retries return the recorded decision without rerunning the tool.
                    with app.guard.execution_lock:
                        with app.store.lock:
                            previous = app.store.db.execute("SELECT agent,digest,response FROM requests WHERE key=?", (key,)).fetchone()
                        if previous:
                            if previous[:2] != (identity, digest):
                                return self.send(409, {"error": "Idempotency key conflict"})
                            return self.send(200, json.loads(previous[2]))
                        spec = app.config.get("tools", {}).get(proposal["tool"])
                        result = app.guard.check(identity, proposal, execute=True,
                                                 call=(lambda: execute_tool(spec, proposal["arguments"], key)) if spec else None)
                        with app.store.lock:
                            app.store.db.execute("INSERT INTO requests VALUES(?,?,?,?)", (key, identity, digest, canonical(result)))
                        return self.send(200, result)
                if self.path == "/v1/report":
                    if identity == "operator":
                        return self.send(403, {"error": "Use an agent key"})
                    subject, event_id, reason = data.get("subject"), data.get("event_id"), data.get("reason")
                    if subject not in app.agent_keys or not isinstance(event_id, int) or not isinstance(reason, str) or not reason.strip():
                        return self.send(400, {"error": "subject, event_id, and reason required"})
                    return self.send(200, {"report_id": app.store.report(identity, subject, event_id, reason)})
                if identity != "operator":
                    return self.send(403, {"error": "Operator access required"})
                if self.path == "/v1/approve":
                    agent = data.get("agent")
                    proposal = {"tool": data.get("tool"), "arguments": data.get("arguments")}
                    if agent not in app.agent_keys or not isinstance(proposal["arguments"], dict) or proposal["tool"] not in app.config.get("tools", {}):
                        return self.send(400, {"error": "Valid agent, tool, and arguments required"})
                    if agent not in app.config["tools"][proposal["tool"]].get("agents", []):
                        return self.send(403, {"error": "Tool not permitted for agent"})
                    with app.guard.execution_lock:
                        eid = app.store.approve(agent, proposal)
                    return self.send(200, {"event_id": eid, "expires_in": 600})
                if self.path == "/v1/award-completion":
                    if data.get("agent") not in app.agent_keys or not isinstance(data.get("event_id"), int):
                        return self.send(400, {"error": "agent and event_id required"})
                    eid = app.store.award_completion(data["agent"], data["event_id"])
                    return self.send(200, {"event_id": eid, "points": 2})
                if self.path == "/v1/resolve-report":
                    if not isinstance(data.get("report_id"), int) or type(data.get("valid")) is not bool:
                        return self.send(400, {"error": "report_id and valid boolean required"})
                    eid = app.store.resolve_report(data["report_id"], data["valid"])
                    return self.send(200, {"event_id": eid})
                if self.path in ("/v1/hold", "/v1/release"):
                    agent = data.get("agent")
                    if agent not in (*app.agent_keys.keys(), "*"):
                        return self.send(400, {"error": "Unknown agent"})
                    with app.guard.execution_lock:
                        eid = app.store.hold(agent, str(data.get("reason", "Operator hold"))[:300]) if self.path.endswith("hold") else app.store.release(agent)
                    return self.send(200, {"event_id": eid, "agent": agent, "held": self.path.endswith("hold")})
                return self.send(404, {"error": "Unknown route"})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                return self.send(400, {"error": str(exc)[:200]})
            except Exception:
                return self.send(500, {"error": "Internal error"})
    return Handler


def serve(config, db_path, host="127.0.0.1", port=8787):
    if host not in ("127.0.0.1", "::1", "localhost") and os.getenv("SNITCH_BEHIND_TLS_PROXY") != "1":
        raise ValueError("Remote binding requires a TLS reverse proxy and SNITCH_BEHIND_TLS_PROXY=1")
    app = App(config, db_path)
    server = ThreadingHTTPServer((host, port), make_handler(app))
    try:
        server.serve_forever()
    finally:
        server.server_close()
