import pytest

pytest.importorskip("asyncssh")

from sentinel.config import Config  # noqa: E402
from sentinel.events import EventLog  # noqa: E402
from sentinel.limits import ConnLimiter  # noqa: E402
from sentinel.shell import Identity  # noqa: E402
from sentinel.ssh_service import Conn, Ctx, HoneyServer  # noqa: E402


def _server(tmp_path, ip="198.51.100.7"):
    import os
    os.environ["DATA_DIR"] = str(tmp_path)
    cfg = Config.from_env()
    ctx = Ctx(cfg, EventLog(cfg.log_path, "t"), Identity("t"), ConnLimiter(5, 100))
    srv = HoneyServer(ctx)
    srv.info = Conn(sid="s", ip=ip)
    return srv, ctx


def test_weak_credential_accepted_immediately(tmp_path):
    srv, _ = _server(tmp_path)
    assert srv.validate_password("root", "123456") is True


def test_ip_eventually_gets_in_after_threshold(tmp_path):
    srv, ctx = _server(tmp_path)
    results = [srv.validate_password("deploy", f"guess{i}") for i in range(6)]
    assert results.index(True) + 1 == ctx.threshold("198.51.100.7")
    assert 2 <= ctx.threshold("198.51.100.7") <= 5


def test_empty_password_never_accepted(tmp_path):
    srv, _ = _server(tmp_path)
    assert not any(srv.validate_password("root", "") for _ in range(10))


def test_pubkey_is_logged_but_never_accepted(tmp_path):
    srv, ctx = _server(tmp_path)

    class K:
        def get_algorithm(self): return "ssh-ed25519"
        def get_fingerprint(self): return "SHA256:abc"

    assert srv.validate_public_key("root", K()) is False
    assert "ssh_pubkey" in ctx.log.path.read_text()


def test_forwarding_refused_and_logged(tmp_path):
    srv, ctx = _server(tmp_path)
    assert srv.connection_requested("example.com", 25, "127.0.0.1", 1234) is False
    assert "tcp_forward_attempt" in ctx.log.path.read_text()
