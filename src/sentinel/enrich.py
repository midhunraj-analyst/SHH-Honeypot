"""Turn raw attacker input into tags (MITRE ATT&CK) and indicators of compromise."""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

# (regex, tag, ATT&CK technique, minimum severity)
_SHELL_RULES: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r"\b(wget|curl|tftp|ftpget)\b"), "tool_download", "T1105", 3),
    (re.compile(r"\bchmod\s+(\+x|[0-7]*7[0-7]*)\b"), "make_executable", "T1222.002", 3),
    (re.compile(r"authorized_keys"), "ssh_key_persistence", "T1098.004", 4),
    (re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron"), "cron_persistence", "T1053.003", 4),
    (re.compile(r"\bbase64\s+(-d|--decode)\b"), "decode_payload", "T1140", 3),
    (re.compile(r"xmrig|minerd|stratum\+|cpuminer|monero", re.I), "cryptominer", "T1496", 4),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+.*(/var/log|\.bash_history)"),
     "cover_tracks", "T1070.003", 3),
    (re.compile(r"iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+stop\s+(firewalld|ufw)"),
     "disable_defences", "T1562.004", 3),
    (re.compile(r"/dev/tcp/|\bnc(at)?\b.*\s-e\b|bash\s+-i\s+>&|mkfifo"), "reverse_shell", "T1059.004", 4),
    (re.compile(r"/etc/(passwd|shadow)"), "credential_file_read", "T1003.008", 3),
    (re.compile(r"\b(uname|lscpu|nproc|free|df|lsb_release|/proc/cpuinfo|/proc/version)\b"),
     "system_discovery", "T1082", 2),
    (re.compile(r"\b(whoami|id|w|who|last)\b"), "user_discovery", "T1033", 2),
    (re.compile(r"\b(ps|top)\b"), "process_discovery", "T1057", 2),
    (re.compile(r"\b(ifconfig|ip\s+a|ip\s+addr|netstat|ss\s+-)"), "network_discovery", "T1016", 2),
]

_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>;|&]+", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")


def classify_shell(line: str) -> dict:
    tags, techniques, sev = [], [], 2
    for rx, tag, tech, s in _SHELL_RULES:
        if rx.search(line):
            tags.append(tag)
            techniques.append(tech)
            sev = max(sev, s)
    return {
        "tags": tags,
        "attack": sorted(set(techniques)),
        "sev": sev,
        "iocs": {"urls": _URL.findall(line), "ips": sorted(set(_IPV4.findall(line)))},
    }


# --- web ---------------------------------------------------------------------
_WEB_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\$\{(jndi|env|lower|upper|::-)", re.I), "log4shell", "T1190"),
    (re.compile(r"\(\)\s*\{\s*:;\s*\}\s*;"), "shellshock", "T1190"),
    (re.compile(r"\.\./|%2e%2e[/%5c]|\.\.\\", re.I), "path_traversal", "T1190"),
    (re.compile(r"union\s+select|or\s+1=1|sleep\(\d+\)|information_schema|'--", re.I), "sqli", "T1190"),
    (re.compile(r"<script|onerror\s*=|javascript:", re.I), "xss", "T1190"),
    (re.compile(r"(;|\||`|\$\()\s*(wget|curl|sh|bash|nc|id|cat)\b", re.I), "cmd_injection", "T1190"),
    (re.compile(r"(cmd|shell|c99|r57|wso|eval-stdin)\.php|/vendor/phpunit", re.I), "webshell_probe", "T1505.003"),
    (re.compile(r"/\.(env|git|aws|ssh|DS_Store)|wp-config|/\.svn|/actuator|/server-status", re.I),
     "info_leak_probe", "T1595.002"),
]


def classify_web(path: str, headers: dict[str, str], body: str) -> dict:
    blob = unquote_plus(path) + " " + " ".join(headers.values()) + " " + unquote_plus(body)
    tags, techs = [], []
    for rx, tag, tech in _WEB_RULES:
        if rx.search(blob):
            tags.append(tag)
            techs.append(tech)
    sev = 3 if any(t in tags for t in ("log4shell", "shellshock", "cmd_injection", "sqli",
                                        "webshell_probe", "path_traversal")) else (2 if tags else 1)
    return {"tags": tags, "attack": sorted(set(techs)), "sev": sev,
            "iocs": {"urls": _URL.findall(blob)}}
