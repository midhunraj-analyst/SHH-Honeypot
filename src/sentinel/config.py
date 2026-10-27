"""All runtime settings come from environment variables (12-factor style)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass(frozen=True)
class Config:
    sensor_id: str
    data_dir: Path
    bind: str
    ssh_port: int
    http_port: int
    ssh_banner: str
    http_server_header: str
    # abuse limits: a honeypot must never become a free resource for the attacker
    max_conn_per_ip: int
    max_conn_total: int
    session_seconds: int
    idle_seconds: int
    max_commands: int
    # alerting
    webhook_url: str
    webhook_format: str  # slack | discord
    alert_min_severity: int
    alert_dedupe_seconds: int

    @property
    def log_path(self) -> Path:
        return self.data_dir / "events.jsonl"

    @classmethod
    def from_env(cls) -> Config:
        e = os.environ.get
        return cls(
            sensor_id=e("SENSOR_ID", "sensor-01"),
            data_dir=Path(e("DATA_DIR", "./data")),
            bind=e("BIND", "0.0.0.0"),
            ssh_port=_int("SSH_PORT", 2222),
            http_port=_int("HTTP_PORT", 8080),
            ssh_banner=e("SSH_BANNER", "OpenSSH_8.9p1"),
            http_server_header=e("HTTP_SERVER", "nginx/1.18.0 (Ubuntu)"),
            max_conn_per_ip=_int("MAX_CONN_PER_IP", 5),
            max_conn_total=_int("MAX_CONN_TOTAL", 100),
            session_seconds=_int("SESSION_SECONDS", 600),
            idle_seconds=_int("IDLE_SECONDS", 90),
            max_commands=_int("MAX_COMMANDS", 300),
            webhook_url=e("ALERT_WEBHOOK", ""),
            webhook_format=e("ALERT_FORMAT", "slack"),
            alert_min_severity=_int("ALERT_MIN_SEVERITY", 3),
            alert_dedupe_seconds=_int("ALERT_DEDUPE_SECONDS", 900),
        )
