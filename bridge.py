#!/usr/bin/env python3
"""Muse bridge v6: OpenAI-compatible endpoint + worker pull API + multi-agent fan-out.

9Router 'muse' provider -> http://127.0.0.1:8765/v1      (key role=user)
Muse worker (sandbox)   -> https://<tunnel-url>/muse/*    (key role=worker)
                            tunnel via cloudflared quick tunnel (run-tunnel.ps1)

v6 (new): multi-agent fan-out
- POST /v1/fanout {"tasks":[...], "aggregate_prompt": "..."} splits one
  request into N parallel child jobs. Workers claim children with the
  UNCHANGED /muse/pending protocol. When all children are answered, the
  bridge spawns an aggregate job (also a normal job); a worker synthesizes
  the final answer, which is delivered to the waiting parent long-poll.
- GET /v1/fanout/<parent_id> -> status of a fan-out ({done, total, ...}).
- Fan-out trackers live in fanout/<parent_id>.json; stale trackers are
  reaped by the sweeper.

v5:
- Role-based API keys stored in keys.json (NOT printed except at creation):
    python bridge.py keygen --role worker --label muse-vm   # prints key ONCE
    python bridge.py keygen --role user   --label 9router
    python bridge.py keylist                 # label/role/created/key-prefix only
    python bridge.py keydel <prefix|label>    # revoke
- Worker pull API (all require `Authorization: Bearer <worker-key>`):
    GET  /muse/pending?limit=3   -> atomically leases up to `limit` jobs
                                   (lease = LEASE_SECS, default 180s);
                                   {"jobs":[{id,received_at,request}],"count":N,"pending":M}
    POST /muse/answer  {"id","content"} -> completes the job; the waiting
                                          /v1/chat/completions returns it
    POST /muse/release {"id"}           -> releases the lease early; the job
                                          becomes pending again
- Expired leases are returned to pending/ automatically by the sweeper.
- /health stays open (no auth) for tunnel/monitoring checks.

v4 (kept):
- Optional shared-token auth: set BRIDGE_TOKEN env. Still accepted on /v1/*
  as a legacy user-role key (so an existing 9Router config keeps working).
- Request body cap (HTTP 413 over MAX_BODY).
- processing/ dir + sweeper thread: stale/expired processing/ jobs are
  requeued, orphan done/ files are deleted.
- Threaded server; SSE streaming with immediate headers + keepalives.
- Dashboard probe shortcut ("hi" / max_tokens=1024 / non-streaming).

Queue layout (under BRIDGE_QUEUE, default /home/ubuntu/muse-bridge/queue):
  pending/<id>.json      unleased jobs
  processing/<id>.json   leased jobs (contain "_lease":{"by","until"})
  done/<id>.json         answered jobs (contain "content")
"""
import argparse
import hmac
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

QUEUE = os.environ.get("BRIDGE_QUEUE", "/home/ubuntu/muse-bridge/queue").rstrip("/")
PENDING = f"{QUEUE}/pending"
DONE = f"{QUEUE}/done"
PROCESSING = f"{QUEUE}/processing"
FANOUT = f"{QUEUE}/fanout"
KEYS_FILE = os.environ.get("BRIDGE_KEYS",
                           os.path.join(os.path.dirname(QUEUE), "keys.json"))
MAX_PENDING = 5
WAIT_SECS = 240        # how long /v1/chat/completions waits for an answer
LEASE_SECS = int(os.environ.get("BRIDGE_LEASE_SECS", "180"))  # worker lease
KEEPALIVE_SECS = 15
MAX_BODY = 10 * 1024 * 1024  # 10 MB per request body
TOKEN = os.environ.get("BRIDGE_TOKEN", "").strip()  # legacy user key on /v1/*
DONE_ORPHAN_SECS = 600
PROCESSING_STALE_SECS = 600  # fallback when a job has no/invalid lease info
# --- fan-out (v6) ---
MAX_FANOUT_TASKS = 10
FANOUT_WAIT_SECS = 240
FANOUT_STALE_SECS = 900  # tracker older than this gets reaped by sweeper
DEFAULT_AGGREGATE_PROMPT = (
    "Kamu menerima hasil dari beberapa sub-task yang dikerjakan paralel. "
    "Rangkum semuanya menjadi SATU jawaban akhir yang utuh, koheren, dan "
    "langsung menjawab kebutuhan pengguna. Jangan sebutkan bahwa ini hasil "
    "gabungan beberapa task."
)

LOCK = threading.Lock()
RECENT_DONE = {}  # job id -> timestamp of completion (for duplicate-answer detection)
RECENT_DONE_TTL = 3600


# ---------------------------------------------------------------- keys ---
def _load_keys():
    try:
        with open(KEYS_FILE) as f:
            return json.load(f).get("keys", [])
    except Exception:
        return []


def _save_keys(keys):
    os.makedirs(os.path.dirname(KEYS_FILE) or ".", exist_ok=True)
    tmp = KEYS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"keys": keys}, f, indent=2)
    os.replace(tmp, KEYS_FILE)
    try:
        os.chmod(KEYS_FILE, 0o600)
    except Exception:
        pass


def cmd_keygen(role, label):
    if role not in ("user", "worker"):
        print("role must be 'user' or 'worker'", file=sys.stderr)
        return 2
    key = "Muse_kutkey_" + secrets.token_urlsafe(18)
    keys = _load_keys()
    keys.append({"key": key, "role": role, "label": label,
                 "created": datetime.now(timezone.utc).isoformat()})
    _save_keys(keys)
    print(key)  # full key shown ONLY here
    print(f"role={role} label={label} saved to {KEYS_FILE} "
          f"(full key is shown only this once)", file=sys.stderr)
    return 0


def cmd_keylist():
    keys = _load_keys()
    if not keys:
        print("(no keys yet — run: python bridge.py keygen --role worker --label muse-vm)")
        return 0
    print(f"{'LABEL':<20}{'ROLE':<8}{'CREATED':<33}PREFIX")
    for k in keys:
        print(f"{k.get('label',''):<20}{k.get('role',''):<8}"
              f"{k.get('created',''):<33}{k.get('key','')[:14]}...")
    return 0


def cmd_keydel(ident):
    keys = _load_keys()
    keep = [k for k in keys
            if not (k.get("key", "").startswith(ident) or k.get("label") == ident)]
    removed = len(keys) - len(keep)
    if removed:
        _save_keys(keep)
    print(f"removed {removed} key(s)")
    return 0


# --------------------------------------------------------------- queue ---
def _job_path(d, jid):
    # jid is hex from uuid4; guard against path traversal anyway
    safe = "".join(c for c in jid if c.isalnum())[:64]
    return os.path.join(d, safe + ".json")


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _claim_jobs(limit, worker_label):
    """Atomically move up to `limit` pending jobs to processing/ with a lease."""
    claimed, now = [], time.time()
    with LOCK:
        try:
            files = sorted(os.listdir(PENDING))
        except Exception:
            files = []
        for fn in files:
            if len(claimed) >= limit or not fn.endswith(".json"):
                continue
            src, dst = os.path.join(PENDING, fn), os.path.join(PROCESSING, fn)
            try:
                os.rename(src, dst)  # atomic claim within one filesystem
            except FileNotFoundError:
                continue
            try:
                with open(dst) as f:
                    job = json.load(f)
            except Exception:
                job = {"id": fn[:-5]}
            job["_lease"] = {"by": worker_label, "until": now + LEASE_SECS}
            tmp = dst + ".tmp"
            with open(tmp, "w") as f:
                json.dump(job, f)
            os.replace(tmp, dst)
            claimed.append({"id": job.get("id", fn[:-5]),
                            "received_at": job.get("received_at"),
                            "request": job.get("request", {}),
                            # v6 fan-out markers so workers can tell
                            # child/aggregate jobs apart from normal ones
                            "parent_id": job.get("parent_id"),
                            "child_index": job.get("child_index"),
                            "aggregate_for": job.get("aggregate_for")})
        try:
            pending_n = sum(1 for f in os.listdir(PENDING) if f.endswith(".json"))
        except Exception:
            pending_n = 0
    return claimed, pending_n


def _answer_job(jid, content):
    """Returns 'ok' | 'duplicate' | None (unknown id).

    Fan-out hooks (v6): if the answered job is a child (has parent_id),
    record it in the fan-out tracker and spawn the aggregate job when all
    children are done. If it is an aggregate job (has aggregate_for), its
    content becomes the parent's answer in done/<parent_id>.json.
    """
    with LOCK:
        p = _job_path(PROCESSING, jid)
        parent_id, aggregate_for = None, None
        if os.path.exists(p):
            try:
                with open(p) as f:
                    job = json.load(f)
                parent_id = job.get("parent_id")
                aggregate_for = job.get("aggregate_for")
            except Exception:
                pass
            try:
                os.remove(p)
            except Exception:
                pass
            first = True
        elif os.path.exists(_job_path(DONE, jid)):
            first = False  # answered but not yet picked up by the /v1 waiter
        elif jid in RECENT_DONE:
            return "duplicate"  # answered AND already delivered to the client
        else:
            return None
        dp = _job_path(DONE, jid)
        _write_json_atomic(dp, {"content": content,
                                "answered_at": time.time()})
        RECENT_DONE[jid] = time.time()
        if first:
            if parent_id:
                _on_child_answered(parent_id, jid, content)
            if aggregate_for:
                _finish_parent(aggregate_for, content)
    return "ok" if first else "duplicate"


def _release_job(jid):
    """Move a leased job back to pending/. Returns True if it was leased."""
    with LOCK:
        src = _job_path(PROCESSING, jid)
        if not os.path.exists(src):
            return False
        try:
            with open(src) as f:
                job = json.load(f)
        except Exception:
            job = {"id": jid}
        job.pop("_lease", None)
        dst = _job_path(PENDING, jid)
        tmp = dst + ".tmp"
        with open(tmp, "w") as f:
            json.dump(job, f)
        os.replace(tmp, dst)
        try:
            os.remove(src)
        except Exception:
            pass
    return True


# ------------------------------------------------------------ fan-out ---
def _tracker_path(pid):
    safe = "".join(c for c in pid if c.isalnum())[:64]
    return os.path.join(FANOUT, safe + ".json")


def _fanout_tracker(pid):
    try:
        with open(_tracker_path(pid)) as f:
            return json.load(f)
    except Exception:
        return None


def _save_tracker(t):
    _write_json_atomic(_tracker_path(t["id"]), t)


def _spawn_fanout(model, strategy, agg_prompt, tasks):
    """Create parent tracker + N child jobs. Returns parent_id.

    Must be called with LOCK held (or from a context that holds it).
    Child jobs are normal pending/ jobs with parent_id/child_index fields,
    so existing workers claim them with the unchanged /muse/pending protocol.
    """
    pid = uuid.uuid4().hex
    children = []
    for i, t in enumerate(tasks[:MAX_FANOUT_TASKS]):
        if not isinstance(t, dict):
            continue
        cid = uuid.uuid4().hex
        job = {"id": cid, "received_at": time.time(),
               "parent_id": pid, "child_index": i,
               "request": {"model": model, **t}}
        _write_json_atomic(_job_path(PENDING, cid), job)
        children.append(cid)
    _save_tracker({"id": pid, "created_at": time.time(), "model": model,
                   "strategy": strategy, "aggregate_prompt": agg_prompt,
                   "children": children, "answers": {}, "status": "running"})
    return pid


def _spawn_aggregate_job(t, partial=False):
    """Create the aggregate job whose answer becomes the parent's answer."""
    parts = []
    for i, cid in enumerate(t["children"]):
        ans = t["answers"].get(cid, "(belum ada jawaban)")
        parts.append(f"Hasil sub-task {i + 1}:\n{ans}")
    prompt = t["aggregate_prompt"]
    if partial:
        prompt += ("\n\nCatatan: hanya sebagian sub-task yang selesai tepat "
                   "waktu. Rangkum dari hasil yang tersedia.")
    agg_id = "agg-" + t["id"]
    job = {"id": agg_id, "received_at": time.time(),
           "aggregate_for": t["id"],
           "request": {"model": t["model"], "messages": [
               {"role": "system", "content": prompt},
               {"role": "user", "content": "\n\n".join(parts)}]}}
    _write_json_atomic(_job_path(PENDING, agg_id), job)
    return agg_id


def _on_child_answered(pid, cid, content):
    """Record a child's answer; spawn aggregate job when all are done.

    Called from _answer_job while LOCK is held.
    """
    t = _fanout_tracker(pid)
    if not t or t.get("status") != "running":
        return
    t["answers"][cid] = content
    if len(t["answers"]) >= len(t["children"]):
        t["status"] = "aggregating"
        _save_tracker(t)
        _spawn_aggregate_job(t)
    else:
        _save_tracker(t)


def _finish_parent(pid, content):
    """Write the aggregate result as the parent's answer.

    Called from _answer_job while LOCK is held. The parent's long-poll
    (_wait_answer) picks this up from done/<pid>.json.
    """
    _write_json_atomic(_job_path(DONE, pid),
                       {"content": content, "answered_at": time.time(),
                        "aggregated": True})
    t = _fanout_tracker(pid)
    if t:
        t["status"] = "done"
        _save_tracker(t)


def _cleanup_fanout(pid):
    """Best-effort cleanup after a fan-out finishes or times out."""
    t = _fanout_tracker(pid)
    if t:
        for cid in t.get("children", []):
            for d in (PENDING, PROCESSING):
                try:
                    os.remove(_job_path(d, cid))
                except Exception:
                    pass
        try:
            os.remove(_job_path(PENDING, "agg-" + pid))
        except Exception:
            pass
        try:
            os.remove(_job_path(PROCESSING, "agg-" + pid))
        except Exception:
            pass


def _sweep_once():
    """Delete orphan done/ files; return expired/stale processing/ jobs to pending/."""
    now = time.time()
    try:
        for fn in os.listdir(DONE):
            p = os.path.join(DONE, fn)
            try:
                if now - os.path.getmtime(p) > DONE_ORPHAN_SECS:
                    os.remove(p)
            except Exception:
                pass
    except Exception:
        pass
    try:
        for fn in os.listdir(PROCESSING):
            if not fn.endswith(".json"):
                continue
            p = os.path.join(PROCESSING, fn)
            expired = False
            try:
                with open(p) as f:
                    job = json.load(f)
                until = (job.get("_lease") or {}).get("until")
                if isinstance(until, (int, float)) and now > until:
                    expired = True
                elif now - os.path.getmtime(p) > PROCESSING_STALE_SECS:
                    expired = True  # no/invalid lease info: stale fallback
            except Exception:
                expired = True
            if expired:
                _release_job(fn[:-5])
    except Exception:
        pass
    # prune duplicate-answer memory
    try:
        cutoff = now - RECENT_DONE_TTL
        for jid in [j for j, ts in RECENT_DONE.items() if ts < cutoff]:
            del RECENT_DONE[jid]
    except Exception:
        pass
    # reap stale fan-out trackers (v6)
    try:
        for fn in os.listdir(FANOUT):
            if not fn.endswith(".json"):
                continue
            p = os.path.join(FANOUT, fn)
            try:
                with open(p) as f:
                    t = json.load(f)
            except Exception:
                try:
                    os.remove(p)
                except Exception:
                    pass
                continue
            if t.get("status") in ("done",):
                try:
                    if now - t.get("created_at", now) > 3600:
                        os.remove(p)
                except Exception:
                    pass
            elif now - t.get("created_at", now) > FANOUT_STALE_SECS:
                t["status"] = "timeout"
                try:
                    with open(p, "w") as f:
                        json.dump(t, f)
                except Exception:
                    pass
                for cid in t.get("children", []):
                    for d in (PENDING, PROCESSING):
                        try:
                            os.remove(_job_path(d, cid))
                        except Exception:
                            pass
    except Exception:
        pass


def _sweeper():
    while True:
        time.sleep(60)
        _sweep_once()


# ------------------------------------------------------------- handler ---
def _is_dashboard_probe(req):
    """Detect 9Router dashboard's 'Test Connection' probe (15s client timeout)."""
    try:
        if not isinstance(req, dict) or req.get("stream"):
            return False
        if req.get("max_tokens") != 1024:
            return False
        msgs = req.get("messages") or []
        if not msgs:
            return False
        last = msgs[-1]
        return (isinstance(last, dict) and last.get("role") == "user"
                and str(last.get("content", "")).strip().lower() == "hi")
    except Exception:
        return False


def _probe_completion():
    cid = "chatcmpl-" + uuid.uuid4().hex[:12]
    return {"id": cid, "object": "chat.completion", "created": int(time.time()),
            "model": "muse",
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content":
                                     "Halo! Muse online — bridge 9Router aktif dan siap."},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


class H(BaseHTTPRequestHandler):
    timeout = 120

    def log_message(self, *a):
        pass

    def _send(self, code, obj, ctype="application/json"):
        try:
            body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def _role(self):
        """'user' | 'worker' | None from the Bearer key (or legacy BRIDGE_TOKEN)."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        if TOKEN and hmac.compare_digest(token, TOKEN):
            return "user"  # legacy single token counts as a user key
        for k in _load_keys():
            if k.get("key") and hmac.compare_digest(token, k["key"]):
                return k.get("role")
        return None

    def _label(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else ""
        for k in _load_keys():
            if k.get("key") and hmac.compare_digest(token, k["key"]):
                return k.get("label", "?")
        return "token"

    def _require(self, role):
        if self._role() != role:
            self._send(401, {"error": {"message":
                f"unauthorized: need bearer key with role={role}",
                "type": "auth_error", "code": "invalid_api_key"}})
            return False
        return True

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            self._send(413, {"error": {"message":
                f"request body too large (>{MAX_BODY} bytes)"}})
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}") if length else {}
        except Exception:
            self._send(400, {"error": {"message": "bad json"}})
            return None

    # -- GET -----------------------------------------------------------
    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path.rstrip("/") == "/v1/models":
                if not self._require("user"):
                    return
                self._send(200, {"object": "list", "data": [
                    {"id": "muse", "object": "model", "created": 0,
                     "owned_by": "muse"}]})
            elif path == "/health":
                self._send(200, {"ok": True})
            elif path.startswith("/v1/fanout/"):
                # --- fan-out status (v6) ---
                if not self._require("user"):
                    return
                pid = "".join(c for c in path[len("/v1/fanout/"):]
                             if c.isalnum())[:64]
                t = _fanout_tracker(pid)
                if not t:
                    return self._send(404, {"error": {"message":
                        "unknown fan-out id"}})
                children = [{"id": cid, "done": cid in t.get("answers", {})}
                            for cid in t.get("children", [])]
                self._send(200, {"id": pid, "status": t.get("status"),
                                 "done": sum(1 for c in children if c["done"]),
                                 "total": len(children), "children": children})
            elif path.rstrip("/") == "/muse/pending":
                if not self._require("worker"):
                    return
                try:
                    limit = int(parse_qs(urlparse(self.path).query)
                                    .get("limit", ["3"])[0])
                except Exception:
                    limit = 3
                limit = max(1, min(10, limit))
                jobs, pending_n = _claim_jobs(limit, self._label())
                self._send(200, {"jobs": jobs, "count": len(jobs),
                                 "pending": pending_n})
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:
            try:
                self._send(500, {"error": {"message": str(e)[:200]}})
            except Exception:
                pass

    # -- POST ----------------------------------------------------------
    def _cleanup(self, rid: str):
        for d in (PENDING, DONE):
            try:
                os.remove(_job_path(d, rid))
            except Exception:
                pass

    def _wait_answer(self, rid: str, wait_secs=None, keepalive_cb=None):
        deadline = time.time() + (WAIT_SECS if wait_secs is None else wait_secs)
        answer, last_ping = None, time.time()
        while time.time() < deadline:
            dp = _job_path(DONE, rid)
            if os.path.exists(dp):
                try:
                    with open(dp) as f:
                        answer = json.load(f).get("content", "")
                except Exception:
                    answer = ""
                try:
                    os.remove(dp)
                except Exception:
                    pass
                break
            if keepalive_cb and time.time() - last_ping >= KEEPALIVE_SECS:
                if not keepalive_cb():
                    break
                last_ping = time.time()
            time.sleep(1)
        return answer

    def do_POST(self):
        try:
            path = urlparse(self.path).path.rstrip("/")
            if path == "/v1/chat/completions":
                if not self._require("user"):
                    return
                req = self._read_json()
                if req is None:
                    return
                if _is_dashboard_probe(req):
                    return self._send(200, _probe_completion())
                try:
                    npend = sum(1 for f in os.listdir(PENDING)
                                if f.endswith(".json"))
                except Exception:
                    npend = 0
                if npend >= MAX_PENDING:
                    return self._send(429, {"error": {"message":
                        "Muse bridge busy, try again in a bit"}})
                rid = uuid.uuid4().hex
                with open(_job_path(PENDING, rid), "w") as f:
                    json.dump({"id": rid, "received_at": time.time(),
                               "request": req}, f)
                if req.get("stream"):
                    return self._handle_stream(req, rid)
                answer = self._wait_answer(rid)
                self._cleanup(rid)
                if answer is None:
                    return self._send(504, {"error": {"message":
                        "Muse did not answer in time"}})
                self._send(200, _completion(answer))
            elif path == "/v1/fanout":
                # --- multi-agent fan-out (v6) ---
                if not self._require("user"):
                    return
                req = self._read_json()
                if req is None:
                    return
                tasks = req.get("tasks")
                if not isinstance(tasks, list) or not tasks:
                    return self._send(400, {"error": {"message":
                        "need non-empty 'tasks' array"}})
                if len(tasks) > MAX_FANOUT_TASKS:
                    return self._send(400, {"error": {"message":
                        f"max {MAX_FANOUT_TASKS} tasks per fan-out"}})
                model = req.get("model", "muse")
                strategy = req.get("strategy", "parallel")
                agg_prompt = (req.get("aggregate_prompt")
                              or DEFAULT_AGGREGATE_PROMPT)
                with LOCK:
                    pid = _spawn_fanout(model, strategy, agg_prompt, tasks)
                answer = self._wait_answer(pid, FANOUT_WAIT_SECS)
                if answer is None:
                    # timeout: aggregate whatever children answered so far
                    with LOCK:
                        t = _fanout_tracker(pid)
                        if t and t.get("status") == "running" and t.get("answers"):
                            t["status"] = "aggregating"
                            _save_tracker(t)
                            _spawn_aggregate_job(t, partial=True)
                    answer = self._wait_answer(pid, 120)
                    _cleanup_fanout(pid)
                if answer is None:
                    return self._send(504, {"error": {"message":
                        "fan-out timed out"}})
                self._send(200, _completion(answer))
            elif path == "/muse/answer":
                if not self._require("worker"):
                    return
                body = self._read_json()
                if body is None:
                    return
                jid, content = body.get("id", ""), body.get("content", "")
                if not jid or not isinstance(content, str):
                    return self._send(400, {"error": {"message":
                        'need {"id": "...", "content": "..."}'}})
                res = _answer_job(jid, content)
                if res is None:
                    return self._send(404, {"error": {"message":
                        "unknown job id (not leased?)"}})
                self._send(200, {"ok": True, "id": jid,
                                 "duplicate": res == "duplicate"})
            elif path == "/muse/release":
                if not self._require("worker"):
                    return
                body = self._read_json()
                if body is None:
                    return
                if _release_job(body.get("id", "")):
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": {"message":
                        "unknown job id (not leased?)"}})
            else:
                self._send(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception as e:
            try:
                self._send(500, {"error": {"message": str(e)[:200]}})
            except Exception:
                pass

    def _handle_stream(self, req, rid: str):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self._cleanup(rid)
            return
        if not self._sse_write(": connected\n\n"):
            self._cleanup(rid)
            return
        answer = self._wait_answer(rid,
                                   keepalive_cb=lambda: self._sse_write(": ping\n\n"))
        self._cleanup(rid)
        cid = "chatcmpl-" + uuid.uuid4().hex[:12]
        created = int(time.time())
        if answer is None:
            err = {"error": {"message": "Muse did not answer in time",
                             "type": "timeout"}}
            self._sse_write("data: " + json.dumps(err) + "\n\ndata: [DONE]\n\n")
            return
        chunk1 = {"id": cid, "object": "chat.completion.chunk", "created": created,
                  "model": "muse", "choices": [{"index": 0,
                  "delta": {"role": "assistant", "content": answer},
                  "finish_reason": None}]}
        chunk2 = {"id": cid, "object": "chat.completion.chunk", "created": created,
                  "model": "muse", "choices": [{"index": 0, "delta": {},
                  "finish_reason": "stop"}]}
        self._sse_write("data: " + json.dumps(chunk1) + "\n\n")
        self._sse_write("data: " + json.dumps(chunk2) + "\n\ndata: [DONE]\n\n")

    def _sse_write(self, payload: str) -> bool:
        try:
            self.wfile.write(payload.encode())
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return False


def _completion(answer: str):
    cid = "chatcmpl-" + uuid.uuid4().hex[:12]
    return {"id": cid, "object": "chat.completion", "created": int(time.time()),
            "model": "muse",
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": answer},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


# ------------------------------------------------------------------ ---
def cmd_serve():
    import subprocess
    for d in (PENDING, DONE, PROCESSING, FANOUT):
        os.makedirs(d, exist_ok=True)
    # crash recovery: anything left in processing/ goes back to pending/
    try:
        for fn in os.listdir(PROCESSING):
            if fn.endswith(".json"):
                _release_job(fn[:-5])
    except Exception:
        pass

    threading.Thread(target=_sweeper, daemon=True).start()

    def listen_addrs():
        addrs = ["127.0.0.1"]
        try:
            out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True,
                                 text=True, timeout=10).stdout
            for ip in out.split():
                ip = ip.strip()
                if ip and ip not in addrs:
                    addrs.append(ip)
        except Exception:
            pass
        return addrs

    ok = 0
    for addr in listen_addrs():
        try:
            srv = ThreadingHTTPServer((addr, 8765), H)
        except OSError as e:
            print(f"  [!] tidak bisa listen di {addr}:8765 ({e})", flush=True)
            continue
        srv.daemon_threads = True
        srv.allow_reuse_address = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"muse-bridge v5 listening on {addr}:8765", flush=True)
        ok += 1
    if not ok:
        print("FATAL: tidak ada listen address yang berhasil", flush=True)
        return 2
    n = len(_load_keys())
    print(f"keys: {n} in {KEYS_FILE} | "
          f"legacy BRIDGE_TOKEN: {'on (/v1/*)' if TOKEN else 'off'} | "
          f"lease={LEASE_SECS}s wait={WAIT_SECS}s", flush=True)
    threading.Event().wait()


def main():
    ap = argparse.ArgumentParser(prog="bridge.py",
                                 description="Muse bridge v5 for 9Router")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the HTTP bridge (default)")
    g = sub.add_parser("keygen", help="create an API key (printed once)")
    g.add_argument("--role", required=True, choices=["user", "worker"])
    g.add_argument("--label", required=True)
    sub.add_parser("keylist", help="list keys (prefixes only)")
    d = sub.add_parser("keydel", help="revoke a key by prefix or label")
    d.add_argument("ident")
    args = ap.parse_args()
    if args.cmd == "keygen":
        return cmd_keygen(args.role, args.label)
    if args.cmd == "keylist":
        return cmd_keylist()
    if args.cmd == "keydel":
        return cmd_keydel(args.ident)
    return cmd_serve() or 0  # default: serve (v4-compatible: `python bridge.py`)


if __name__ == "__main__":
    sys.exit(main())
