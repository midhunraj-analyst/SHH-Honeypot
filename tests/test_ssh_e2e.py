"""End-to-end: real asyncssh client against the real honeypot server on an ephemeral port."""
import asyncio
import json
import os

import pytest

asyncssh = pytest.importorskip("asyncssh")

from sentinel.config import Config  # noqa: E402
from sentinel.events import EventLog, verify  # noqa: E402
from sentinel.shell import Identity  # noqa: E402
from sentinel.ssh_service import start_ssh  # noqa: E402


def test_ssh_session_is_captured(tmp_path):
    os.environ.update(DATA_DIR=str(tmp_path), SSH_PORT="0", BIND="127.0.0.1")
    cfg = Config.from_env()
    log = EventLog(cfg.log_path, "t")

    async def scenario():
        srv = await start_ssh(cfg, log, Identity("t"))
        port = srv.get_port()
        opts = dict(username="root", password="123456", known_hosts=None, client_keys=None)
        async with asyncssh.connect("127.0.0.1", port, **opts) as conn:
            one_shot = await conn.run("uname -a; cat /root/.aws/credentials", check=False)
            proc = await conn.create_process()  # interactive shell, no PTY
            await asyncio.wait_for(proc.stdout.readuntil("# "), 5)
            proc.stdin.write("whoami\n")
            shell_out = await asyncio.wait_for(proc.stdout.readuntil("# "), 5)
            proc.stdin.write("exit\n")
            await asyncio.wait_for(proc.wait(), 5)
        await asyncio.sleep(0.2)
        srv.close()
        return one_shot.stdout, shell_out

    one_shot, shell_out = asyncio.run(scenario())
    assert "Linux" in one_shot and "aws_access_key_id" in one_shot
    assert "root" in shell_out
    ev = [json.loads(line) for line in cfg.log_path.read_text().splitlines()]
    kinds = [e["kind"] for e in ev]
    for expected in ("ssh_connect", "ssh_auth", "ssh_command", "tripwire", "ssh_disconnect"):
        assert expected in kinds, kinds
    assert next(e for e in ev if e["kind"] == "ssh_auth")["success"] is True
    assert verify(cfg.log_path)[0]
