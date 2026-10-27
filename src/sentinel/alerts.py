"""Webhook alerting with de-duplication and a global rate cap.

Without these two, a single noisy scanner turns your chat channel into a DoS.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request

from .config import Config


class Alerter:
    def __init__(self, cfg: Config, max_per_hour: int = 30):
        self.cfg = cfg
        self.max_per_hour = max_per_hour
        self._seen: dict[tuple, float] = {}
        self._sent: list[float] = []
        self._lock = threading.Lock()

    def __call__(self, ev: dict) -> None:
        if not self.cfg.webhook_url or ev["sev"] < self.cfg.alert_min_severity:
            return
        key = (ev.get("src_ip"), ev["kind"], tuple(ev.get("tags", [])))
        now = time.time()
        with self._lock:
            if now - self._seen.get(key, 0) < self.cfg.alert_dedupe_seconds:
                return
            self._sent = [t for t in self._sent if now - t < 3600]
            if len(self._sent) >= self.max_per_hour:
                return
            self._seen[key] = now
            self._sent.append(now)
            if len(self._seen) > 5000:  # bound memory
                self._seen = {k: v for k, v in self._seen.items() if now - v < 3600}
        # fire-and-forget on a thread so network latency never stalls a session
        threading.Thread(target=self._post, args=(self._format(ev),), daemon=True).start()

    @staticmethod
    def _summary(ev: dict) -> str:
        detail = ev.get("command") or ev.get("path") or ev.get("url") or ev.get("username") or ""
        tags = ",".join(ev.get("tags", []))
        return (f"[sev{ev['sev']}] {ev['kind']} from {ev.get('src_ip', '?')} on {ev['sensor']}"
                f"{' | ' + tags if tags else ''}{' | ' + str(detail)[:200] if detail else ''}")

    def _format(self, ev: dict) -> dict:
        text = self._summary(ev)
        return {"content": text} if self.cfg.webhook_format == "discord" else {"text": text}

    def _post(self, payload: dict) -> None:
        req = urllib.request.Request(
            self.cfg.webhook_url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass
