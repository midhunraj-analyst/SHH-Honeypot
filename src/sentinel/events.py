"""Tamper-evident event log.

Every record is one JSON line. Each record carries the SHA-256 of the previous
record, so deleting or editing a line in the middle breaks the chain and
`sentinel-report --verify` will point at the first bad record.
(An attacker who fully owns the box can still truncate the tail; ship the log
off-host to close that gap.)
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64

# 1 = noise, 2 = interesting, 3 = hands-on attacker, 4 = tripwire / exploitation
SEVERITY = {
    "ssh_connect": 1, "ssh_disconnect": 1, "http_request": 1,
    "ssh_auth": 2, "ssh_pubkey": 2, "login_attempt": 2, "ssh_command": 2,
    "tcp_forward_attempt": 3, "download_attempt": 3, "exec_dropped": 3,
    "pipe_to_shell": 3, "file_write": 2, "web_attack": 3,
    "tripwire": 4,
}


def _body(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev: str, body: str) -> str:
    return hashlib.sha256((prev + body).encode()).hexdigest()


class EventLog:
    def __init__(self, path: Path, sensor: str, on_event: Callable[[dict], None] | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.sensor = sensor
        self.on_event = on_event
        self._lock = threading.Lock()
        self._prev = self._load_tail()

    def _load_tail(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with self.path.open("rb") as f:
            f.seek(max(0, self.path.stat().st_size - 65536))
            last = f.read().splitlines()[-1]
        return json.loads(last)["hash"]

    def emit(self, kind: str, **fields) -> dict:
        sev = max(SEVERITY.get(kind, 1), fields.pop("sev", 0))
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "sensor": self.sensor,
            "kind": kind,
            "sev": sev,
            **fields,
        }
        with self._lock:
            rec["prev"] = self._prev
            rec["hash"] = _digest(self._prev, _body(rec))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
            self._prev = rec["hash"]
        if self.on_event:
            try:
                self.on_event(rec)
            except Exception:  # alerting must never break logging
                pass
        return rec


def verify(path: Path) -> tuple[bool, int, int | None]:
    """Return (ok, records_checked, first_bad_line_number)."""
    prev, n = GENESIS, 0
    with Path(path).open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            rec = json.loads(line)
            claimed, claimed_prev = rec.pop("hash"), rec.get("prev")
            if claimed_prev != prev or _digest(prev, _body(rec)) != claimed:
                return False, n, n
            prev = claimed
    return True, n, None
