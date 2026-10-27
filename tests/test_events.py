import json

from sentinel.events import EventLog, verify


def test_chain_verifies(tmp_path):
    log = EventLog(tmp_path / "e.jsonl", "s1")
    for i in range(5):
        log.emit("ssh_auth", src_ip="1.2.3.4", n=i)
    assert verify(tmp_path / "e.jsonl") == (True, 5, None)


def test_chain_survives_restart(tmp_path):
    p = tmp_path / "e.jsonl"
    EventLog(p, "s1").emit("ssh_connect", src_ip="1.1.1.1")
    EventLog(p, "s1").emit("ssh_connect", src_ip="2.2.2.2")
    assert verify(p)[0]


def test_edit_is_detected(tmp_path):
    p = tmp_path / "e.jsonl"
    log = EventLog(p, "s1")
    for i in range(4):
        log.emit("ssh_command", src_ip="1.2.3.4", command=f"cmd{i}")
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["command"] = "nothing to see here"
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, _, bad = verify(p)
    assert not ok and bad == 2


def test_deleted_line_is_detected(tmp_path):
    p = tmp_path / "e.jsonl"
    log = EventLog(p, "s1")
    for i in range(4):
        log.emit("ssh_command", command=str(i))
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    ok, _, bad = verify(p)
    assert not ok and bad == 2


def test_severity_can_be_raised_not_lowered(tmp_path):
    log = EventLog(tmp_path / "e.jsonl", "s1")
    assert log.emit("tripwire", sev=1)["sev"] == 4
    assert log.emit("ssh_connect", sev=3)["sev"] == 3
