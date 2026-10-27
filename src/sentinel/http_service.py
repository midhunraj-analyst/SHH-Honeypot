"""Minimal asyncio HTTP honeypot: fake admin panels, leaky dotfiles, a fake WordPress login.

Hand-rolled on purpose: tiny attack surface, no framework fingerprint, and every
byte of the request is under our control for logging.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from urllib.parse import parse_qs, urlsplit

from .config import Config
from .enrich import classify_web
from .events import EventLog
from .limits import ConnLimiter

MAX_HEADER, MAX_BODY = 16_384, 65_536

LOGIN_PAGE = ("<!doctype html><title>Log In</title><form method=post>"
              "<input name=log placeholder=Username><input name=pwd type=password>"
              "<button>Log In</button></form>")
LOGIN_FAIL = LOGIN_PAGE.replace("<form", "<div id=login_error>The password you entered is incorrect.</div><form")
ENV_FILE = "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=app\nDB_PASS=changeme-2019\n"
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/internal-portal.git\n"
NOT_FOUND = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"

# (path regex, content-type, body, is_login)
ROUTES: list[tuple[re.Pattern, str, str, bool]] = [
    (re.compile(r"^/(wp-login\.php|login|admin/?|administrator/?|user/login|phpmyadmin/?)$", re.I),
     "text/html", LOGIN_PAGE, True),
    (re.compile(r"^/\.env$"), "text/plain", ENV_FILE, False),
    (re.compile(r"^/\.git/config$"), "text/plain", GIT_CONFIG, False),
    (re.compile(r"^/actuator/health$"), "application/json", '{"status":"UP"}', False),
    (re.compile(r"^/(index\.html?)?$"), "text/html", "<html><body><h1>It works!</h1></body></html>", False),
]


def _parse_head(raw: bytes) -> tuple[str, str, str, dict[str, str]]:
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method = parts[0][:16]
    target = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.0"
    headers = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return method, target, version, headers


def _response(status: str, server: str, ctype: str, body: str) -> bytes:
    data = body.encode()
    head = (f"HTTP/1.1 {status}\r\nServer: {server}\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n")
    return head.encode() + data


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 cfg: Config, log: EventLog, limiter: ConnLimiter) -> None:
    ip = (writer.get_extra_info("peername") or ("?", 0))[0]
    if not limiter.acquire(ip):
        writer.close()
        return
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        if len(raw) > MAX_HEADER:
            return
        method, target, _, headers = _parse_head(raw[:-4])
        body = b""
        cl = headers.get("content-length", "")
        n = min(int(cl), MAX_BODY) if cl.isdigit() else 0
        if n:
            body = await asyncio.wait_for(reader.readexactly(n), timeout=10)
        body_s = body.decode("utf-8", "replace")
        url = urlsplit(target)
        info = classify_web(target, headers, body_s)
        route = next((r for r in ROUTES if r[0].match(url.path)), None)
        base = dict(sid=uuid.uuid4().hex[:12], src_ip=ip, method=method, path=target[:500],
                    host=headers.get("host", ""), ua=headers.get("user-agent", "")[:300],
                    body=body_s[:1000], tags=info["tags"], attack=info["attack"], iocs=info["iocs"])
        if method == "POST" and route and route[3]:
            form = parse_qs(body_s)
            log.emit("login_attempt", service="http", sev=2,
                     username=(form.get("log") or form.get("username") or [""])[0][:100],
                     password=(form.get("pwd") or form.get("password") or [""])[0][:100], **base)
            resp = _response("200 OK", cfg.http_server_header, "text/html", LOGIN_FAIL)
        else:
            log.emit("web_attack" if info["tags"] else "http_request", sev=info["sev"], **base)
            if route:
                resp = _response("200 OK", cfg.http_server_header, route[1], route[2])
            else:
                resp = _response("404 Not Found", cfg.http_server_header, "text/html", NOT_FOUND)
        writer.write(resp)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            ConnectionError, ValueError):
        pass
    finally:
        limiter.release(ip)
        writer.close()


async def start_http(cfg: Config, log: EventLog) -> asyncio.AbstractServer:
    limiter = ConnLimiter(cfg.max_conn_per_ip, cfg.max_conn_total)
    return await asyncio.start_server(
        lambda r, w: handle(r, w, cfg, log, limiter), cfg.bind, cfg.http_port, limit=MAX_HEADER * 2)
