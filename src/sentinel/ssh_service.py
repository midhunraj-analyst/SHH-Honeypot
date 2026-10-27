"""SSH honeypot built directly on asyncssh.

Behaviour worth knowing:
  * Logs every password and public-key attempt (with key fingerprint).
  * Lets an IP "break in" after a per-IP pseudo-random number of failures, or
    immediately on a classic weak credential, so we see what attackers do next.
  * Commands go to the pure-Python Shell, never to a real shell.
  * All port-forwarding requests are logged and refused (stops proxy abuse).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

import asyncssh

from .config import Config
from .enrich import classify_shell
from .events import EventLog
from .limits import ConnLimiter
from .shell import Identity, Shell

WEAK = {"123456", "password", "admin", "root", "toor", "1234", "12345", "admin123", "ubuntu", "raspberry"}
WEAK_USERS = {"root", "admin", "ubuntu", "pi", "user", "test", "oracle", "ubnt"}


@dataclass
class Conn:
    sid: str
    ip: str
    started: float = field(default_factory=time.time)
    commands: int = 0
    tags: set[str] = field(default_factory=set)
    auth_ok: bool = False
    acquired: bool = False


@dataclass
class Ctx:
    cfg: Config
    log: EventLog
    ident: Identity
    limiter: ConnLimiter
    attempts: dict[str, int] = field(default_factory=dict)
    conns: dict[tuple, Conn] = field(default_factory=dict)

    def threshold(self, ip: str) -> int:
        """2-5 failures before this IP 'cracks' the password; stable per IP and sensor."""
        h = hashlib.sha256(f"{ip}|{self.cfg.sensor_id}".encode()).digest()
        return 2 + h[0] % 4


class HoneyServer(asyncssh.SSHServer):
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.peer: tuple = ()
        self.info: Conn | None = None
        self.conn: asyncssh.SSHServerConnection | None = None
        self._announced = False

    # -- lifecycle -------------------------------------------------------------
    def connection_made(self, conn):
        self.conn = conn
        self.peer = conn.get_extra_info("peername")[:2]
        ip = self.peer[0]
        self.info = Conn(sid=uuid.uuid4().hex[:12], ip=ip)
        if not self.ctx.limiter.acquire(ip):
            conn.abort()
            return
        self.info.acquired = True
        self.ctx.conns[self.peer] = self.info

    def connection_lost(self, exc):
        info = self.info
        if not info:
            return
        if info.acquired:
            self.ctx.limiter.release(info.ip)
            self.ctx.conns.pop(self.peer, None)
            self.ctx.log.emit(
                "ssh_disconnect", sid=info.sid, src_ip=info.ip, logged_in=info.auth_ok,
                duration=round(time.time() - info.started, 1), commands=info.commands,
                tags=sorted(info.tags), error=str(exc)[:200] if exc else None)

    # -- auth ------------------------------------------------------------------
    def begin_auth(self, username):
        if not self._announced and self.info and self.conn:
            self._announced = True
            self.ctx.log.emit("ssh_connect", sid=self.info.sid, src_ip=self.info.ip,
                              src_port=self.peer[1],
                              client=self.conn.get_extra_info("client_version", ""))
        return True  # authentication required

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        info, ctx = self.info, self.ctx
        n = ctx.attempts[info.ip] = ctx.attempts.get(info.ip, 0) + 1
        if len(ctx.attempts) > 20_000:
            ctx.attempts.clear()
        ok = bool(password) and (
            (username in WEAK_USERS and password in WEAK) or n >= ctx.threshold(info.ip))
        info.auth_ok = info.auth_ok or ok
        ctx.log.emit("ssh_auth", sid=info.sid, src_ip=info.ip, username=username[:64],
                     password=password[:128], success=ok, attempt=n,
                     tags=["brute_force"] if n >= 3 else [],
                     attack=["T1110.001"] if n >= 3 else [])
        return ok

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        self.ctx.log.emit("ssh_pubkey", sid=self.info.sid, src_ip=self.info.ip,
                          username=username[:64], algo=key.get_algorithm(),
                          fingerprint=key.get_fingerprint())
        return False  # record the key, never accept it

    # -- forwarding is always refused but always logged ---------------------------
    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        self.ctx.log.emit("tcp_forward_attempt", sid=self.info.sid, src_ip=self.info.ip,
                          dest=f"{dest_host}:{dest_port}", direction="direct",
                          tags=["proxy_abuse"], attack=["T1090"])
        return False

    def server_requested(self, listen_host, listen_port):
        self.ctx.log.emit("tcp_forward_attempt", sid=self.info.sid, src_ip=self.info.ip,
                          dest=f"{listen_host}:{listen_port}", direction="reverse",
                          tags=["proxy_abuse"], attack=["T1090"])
        return False


def _record(emit, info: Conn, line: str, cwd: str, exec_mode: bool) -> None:
    meta = classify_shell(line)
    info.commands += 1
    info.tags.update(meta["tags"])
    emit("ssh_command", command=line[:2000], cwd=cwd, exec=exec_mode, **meta)


async def handle_process(ctx: Ctx, process: asyncssh.SSHServerProcess) -> None:
    info = ctx.conns.get(tuple(process.get_extra_info("peername")[:2]))
    if info is None:
        process.exit(1)
        return
    cfg = ctx.cfg
    emit = partial(ctx.log.emit, sid=info.sid, src_ip=info.ip,
                   username=process.get_extra_info("username"))
    shell = Shell(ctx.ident, emit)
    try:
        if process.command is not None:  # `ssh host 'uname -a'` one-shot
            _record(emit, info, process.command, shell.cwd, True)
            process.stdout.write(shell.run(process.command))
            process.exit(0)
            return
        i = ctx.ident
        process.stdout.write(
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux {i.kernel} x86_64)\n\n"
            f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y', time.gmtime(time.time() - 86400 * 3))}"
            f" from 10.{i.ip.split('.')[1]}.0.12\n")
        deadline, prompt = time.monotonic() + cfg.session_seconds, True
        while not shell.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or info.commands >= cfg.max_commands:
                break
            if prompt:
                process.stdout.write(shell.prompt)
            prompt = True
            try:
                line = await asyncio.wait_for(process.stdin.readline(),
                                              timeout=min(cfg.idle_seconds, remaining))
            except (asyncssh.TerminalSizeChanged, asyncssh.BreakReceived, asyncssh.SignalReceived):
                prompt = False
                continue
            except asyncio.TimeoutError:
                break
            if not line:  # EOF
                break
            line = line.strip()
            if line:
                _record(emit, info, line, shell.cwd, False)
                process.stdout.write(shell.run(line))
        process.exit(0)
    except (asyncssh.Error, ConnectionError, BrokenPipeError):
        pass
    finally:
        process.close()


def _host_key(path: Path, alg: str, **kw) -> str:
    if not path.exists():
        asyncssh.generate_private_key(alg, **kw).write_private_key(str(path))
        path.chmod(0o600)
    return str(path)


async def start_ssh(cfg: Config, log: EventLog, ident: Identity):
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(cfg, log, ident, ConnLimiter(cfg.max_conn_per_ip, cfg.max_conn_total))
    keys = [_host_key(cfg.data_dir / "host_ed25519", "ssh-ed25519"),
            _host_key(cfg.data_dir / "host_rsa", "ssh-rsa", key_size=3072)]
    return await asyncssh.create_server(
        lambda: HoneyServer(ctx), cfg.bind, cfg.ssh_port,
        server_host_keys=keys, server_version=cfg.ssh_banner,
        process_factory=lambda p: handle_process(ctx, p),
        login_timeout=30, keepalive_interval=30, keepalive_count_max=3,
        encoding="utf-8", errors="replace")
