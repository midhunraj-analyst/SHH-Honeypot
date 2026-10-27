"""Pure-Python shell emulator.

Nothing in this module ever touches the real OS: no subprocess, no real file
I/O, no outbound network. Attacker input is parsed and answered from an
in-memory filesystem. Downloads are *recorded*, never fetched.
"""
from __future__ import annotations

import posixpath
import random
import re
import shlex
import string
import time
from collections.abc import Callable
from urllib.parse import urlparse

Emit = Callable[..., dict]

TRIPWIRES = {
    "/root/.aws/credentials", "/root/.ssh/id_rsa", "/home/deploy/.env",
    "/root/backup.sql", "/etc/shadow",
}
MAX_OUT = 16_384
MAX_FILE = 64_000


class Identity:
    """Stable fake machine identity, derived from a seed so each sensor differs."""

    def __init__(self, seed: str):
        r = random.Random(seed)
        pick = lambda alphabet, k: "".join(r.choices(alphabet, k=k))  # noqa: E731
        alnum = string.ascii_letters + string.digits
        self.hostname = (f"{r.choice(['web', 'api', 'db', 'vpn', 'nas', 'ci'])}-"
                         f"{r.choice(['prod', 'stg', 'int'])}{r.randint(1, 9):02d}")
        self.kernel = r.choice(["5.4.0-169-generic", "5.15.0-91-generic", "6.1.0-17-amd64"])
        self.boot = time.time() - r.randint(3, 400) * 86400
        self.ip = f"10.{r.randint(0, 200)}.{r.randint(0, 254)}.{r.randint(2, 250)}"
        self.mac = ":".join(f"{r.randint(0, 255):02x}" for _ in range(6))
        self.cpus = r.choice([2, 4, 8])
        self.mem_kb = r.choice([4, 8, 16]) * 1024 * 1024
        self.aws_key = "AKIA" + pick(string.ascii_uppercase + string.digits, 16)
        self.aws_secret = pick(alnum + "+/", 40)
        self.db_pass = pick(alnum, 14)
        self.shadow_hash = "$6$" + pick(alnum, 8) + "$" + pick(alnum + "./", 86)
        blob = pick(alnum + "+/", 70 * 7)
        self.priv_key = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                         + "\n".join(blob[i:i + 70] for i in range(0, len(blob), 70))
                         + "\n-----END OPENSSH PRIVATE KEY-----\n")


def default_fs(i: Identity) -> dict[str, str | None]:
    """path -> None (directory) or str (file contents)."""
    dirs = ["/", "/root", "/root/.ssh", "/root/.aws", "/etc", "/home", "/home/deploy", "/tmp",
            "/var", "/var/log", "/var/www", "/usr", "/usr/bin", "/bin", "/opt", "/proc", "/dev"]
    fs: dict[str, str | None] = {d: None for d in dirs}
    cpuinfo = "".join(
        f"processor\t: {n}\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        f"cpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\n\n" for n in range(i.cpus))
    fs.update({
        "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:"
                        "/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                        "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
                        "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n"),
        "/etc/shadow": f"root:{i.shadow_hash}:19650:0:99999:7:::\ndeploy:{i.shadow_hash}:19650:0:99999:7:::\n",
        "/etc/hostname": i.hostname + "\n",
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n',
        "/proc/cpuinfo": cpuinfo,
        "/proc/version": f"Linux version {i.kernel} (buildd@lcy02) (gcc 11.4.0) #1 SMP\n",
        "/proc/meminfo": f"MemTotal:       {i.mem_kb} kB\nMemFree:        {i.mem_kb // 3} kB\n",
        "/root/.bash_history": "apt update\nsystemctl restart nginx\ncd /var/www\nvim /home/deploy/.env\n"
                               "docker ps\ntail -f /var/log/syslog\n",
        "/root/.aws/credentials": (f"[default]\naws_access_key_id = {i.aws_key}\n"
                                   f"aws_secret_access_key = {i.aws_secret}\n"),
        "/root/.ssh/id_rsa": i.priv_key,
        "/root/backup.sql": f"-- MySQL dump\n-- Host: localhost  Database: app\nCREATE USER 'app'@'%' IDENTIFIED BY '{i.db_pass}';\n",
        "/home/deploy/.env": f"DB_HOST=10.0.0.5\nDB_USER=app\nDB_PASS={i.db_pass}\nAPP_ENV=production\n",
        "/var/log/syslog": "",
    })
    return fs


class Shell:
    def __init__(self, ident: Identity, emit: Emit):
        self.id, self.emit = ident, emit
        self.fs = default_fs(ident)
        self.cwd, self.user, self.closed = "/root", "root", False
        self.history: list[str] = []
        self.env = {"HOME": "/root", "USER": "root", "SHELL": "/bin/bash", "PWD": "/root",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

    # ---- public ---------------------------------------------------------------
    @property
    def prompt(self) -> str:
        here = "~" if self.cwd == "/root" else self.cwd
        return f"root@{self.id.hostname}:{here}# "

    def run(self, line: str, depth: int = 0) -> str:
        line = line.strip()
        if not line or line.startswith("#") or depth > 3:
            return ""
        if depth == 0:
            self.history.append(line)
        try:
            lex = shlex.shlex(line, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            toks = list(lex)
        except ValueError:
            return "bash: unexpected EOF while looking for matching quote\n"
        segs, ops, cur = [], [], []
        for t in toks:
            if t in (";", "&&", "||"):
                segs.append(cur)
                ops.append(t)
                cur = []
            else:
                cur.append(t)
        segs.append(cur)
        out, status = [], 0
        for n, seg in enumerate(segs):
            if n and ((ops[n - 1] == "&&" and status) or (ops[n - 1] == "||" and not status)):
                continue
            if seg:
                o, status = self._pipeline(seg, depth)
                out.append(o)
            if self.closed:
                break
        return "".join(out)[:MAX_OUT]

    # ---- internals ------------------------------------------------------------
    def _abs(self, p: str) -> str:
        if p == "~" or p.startswith("~/"):
            p = "/root" + p[1:]
        return posixpath.normpath(p if p.startswith("/") else posixpath.join(self.cwd, p))

    def _children(self, d: str) -> list[str]:
        return sorted(posixpath.basename(p) for p in self.fs if p != d and posixpath.dirname(p) == d)

    def _pipeline(self, toks: list[str], depth: int) -> tuple[str, int]:
        cmds: list[list[str]] = [[]]
        for t in toks:
            if t == "|":
                cmds.append([])
            else:
                cmds[-1].append(t)
        names = [c[0] for c in cmds if c]
        if len(cmds) > 1 and any(n in ("curl", "wget") for n in names[:-1]) \
                and names[-1] in ("sh", "bash", "dash", "python", "python3", "perl"):
            self.emit("pipe_to_shell", command=" ".join(toks)[:500], sev=4)
        out, status = "", 0
        for c in cmds:
            if c:
                out, status = self._exec(c, out, depth)
        return out, status

    def _exec(self, argv: list[str], stdin: str, depth: int) -> tuple[str, int]:
        argv = [re.sub(r"\$\{?(\w+)\}?", lambda m: self.env.get(m.group(1), ""), a) for a in argv]
        redir = None
        for i, t in enumerate(argv):
            if t in (">", ">>") and i + 1 < len(argv):
                redir, argv = (t, argv[i + 1]), argv[:i] + argv[i + 2:]
                break
        if not argv:
            return "", 0
        if re.fullmatch(r"\w+=.*", argv[0]):
            k, _, v = argv[0].partition("=")
            self.env[k] = v
            return "", 0
        name, args = argv[0], argv[1:]
        if name == "sudo" and args:
            name, args = args[0], args[1:]
        if "/" in name and posixpath.basename(name) not in self._builtin_names():
            return self._run_path(name)
        fn = getattr(self, "cmd_" + re.sub(r"\W", "_", posixpath.basename(name)), None)
        if fn is None:
            out, status = f"bash: {name}: command not found\n", 127
        else:
            out, status = fn(args, stdin, depth)
        if redir:
            return self._write(redir[0], redir[1], out), 0
        return out, status

    def _builtin_names(self) -> set[str]:
        return {n[4:] for n in dir(self) if n.startswith("cmd_")}

    def _run_path(self, name: str) -> tuple[str, int]:
        path = self._abs(name)
        content = self.fs.get(path)
        if content is None:
            msg = "Is a directory" if path in self.fs else "No such file or directory"
            return f"bash: {name}: {msg}\n", 126 if path in self.fs else 127
        self.emit("exec_dropped", path=path, size=len(content), head=content[:120], sev=4)
        return "", 0

    def _write(self, op: str, target: str, text: str) -> str:
        path = self._abs(target)
        if posixpath.dirname(path) not in self.fs or self.fs.get(path, "") is None:
            return f"bash: {target}: No such file or directory\n"
        base = self.fs.get(path) or ""
        self.fs[path] = ((base if op == ">>" else "") + text)[:MAX_FILE]
        self.emit("file_write", path=path, mode=op, content=text[:400])
        return ""

    # ---- commands -------------------------------------------------------------
    def cmd_pwd(self, a, stdin, d):
        return self.cwd + "\n", 0
    def cmd_whoami(self, a, stdin, d):
        return "root\n", 0
    def cmd_hostname(self, a, stdin, d):
        return self.id.hostname + "\n", 0
    def cmd_id(self, a, stdin, d):
        return "uid=0(root) gid=0(root) groups=0(root)\n", 0
    def cmd_nproc(self, a, stdin, d):
        return f"{self.id.cpus}\n", 0
    def cmd_clear(self, a, stdin, d):
        return "\x1b[H\x1b[2J", 0
    def cmd_sleep(self, a, stdin, d):
        return "", 0
    def cmd_chown(self, a, stdin, d):
        return "", 0
    def cmd_logout(self, a, stdin, d):
        self.closed = True
        return "logout\n", 0
    def cmd_exit(self, a, stdin, d):
        self.closed = True
        return "", 0
    def cmd_history(self, a, stdin, d):
        return "".join(f"{n:5d}  {h}\n" for n, h in enumerate(self.history, 1)), 0

    def cmd_uname(self, a, stdin, d):
        i, f = self.id, "".join(a)
        if "a" in f:
            return f"Linux {i.hostname} {i.kernel} #1 SMP x86_64 x86_64 x86_64 GNU/Linux\n", 0
        if "r" in f:
            return i.kernel + "\n", 0
        if "m" in f or "p" in f:
            return "x86_64\n", 0
        if "n" in f:
            return i.hostname + "\n", 0
        return "Linux\n", 0

    def cmd_uptime(self, a, stdin, d):
        days = int((time.time() - self.id.boot) // 86400)
        return f" {time.strftime('%H:%M:%S')} up {days} days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n", 0

    def cmd_free(self, a, stdin, d):
        t = self.id.mem_kb
        return (f"              total        used        free\nMem:    {t:>12}{t // 4:>12}{t // 2:>12}\n"
                f"Swap:             0           0           0\n"), 0

    def cmd_df(self, a, stdin, d):
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        80G   31G   45G  41% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n"), 0

    def cmd_ps(self, a, stdin, d):
        return ("USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\n"
                "root       612  0.0  0.2 /usr/sbin/sshd -D\nroot       701  0.0  0.1 /usr/sbin/cron -f\n"
                "www-data   844  0.1  0.5 nginx: worker process\nroot      1203  0.0  0.1 -bash\n"), 0

    def cmd_w(self, a, stdin, d):
        return (f" {time.strftime('%H:%M:%S')} up 1 day,  1 user\nUSER     TTY      FROM    LOGIN@   WHAT\n"
                "root     pts/0    -       now      w\n"), 0

    def cmd_ifconfig(self, a, stdin, d):
        i = self.id
        return (f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet {i.ip}  "
                f"netmask 255.255.255.0\n        ether {i.mac}  txqueuelen 1000  (Ethernet)\n"), 0

    def cmd_ip(self, a, stdin, d):
        i = self.id
        return (f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    link/ether {i.mac}\n"
                f"    inet {i.ip}/24 brd {i.ip.rsplit('.', 1)[0]}.255 scope global eth0\n"), 0

    def cmd_lscpu(self, a, stdin, d):
        return f"Architecture: x86_64\nCPU(s): {self.id.cpus}\nModel name: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n", 0

    def cmd_echo(self, a, stdin, d):
        nl = "-n" not in a[:1]
        text = " ".join(x for x in a if x not in ("-n", "-e"))
        text = text.replace("\\n", "\n").replace("\\t", "\t")
        return text + ("\n" if nl else ""), 0

    def cmd_cd(self, a, stdin, d):
        tgt = self._abs(a[0] if a else "~")
        if tgt in self.fs and self.fs[tgt] is None:
            self.cwd = tgt
            return "", 0
        return f"bash: cd: {a[0] if a else ''}: No such file or directory\n", 1

    def cmd_ls(self, a, stdin, d):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        paths = [x for x in a if not x.startswith("-")] or ["."]
        out, status = "", 0
        for p in paths:
            ap = self._abs(p)
            if ap not in self.fs:
                out += f"ls: cannot access '{p}': No such file or directory\n"
                status = 2
                continue
            names = [posixpath.basename(ap)] if self.fs[ap] is not None else self._children(ap)
            base = posixpath.dirname(ap) if self.fs[ap] is not None else ap
            if "a" not in flags:
                names = [n for n in names if not n.startswith(".")]
            if "l" in flags:
                for n in names:
                    c = self.fs.get(posixpath.join(base, n))
                    kind, mode, size = ("d", "rwxr-xr-x", 4096) if c is None else ("-", "rw-r--r--", len(c))
                    out += f"{kind}{mode} 1 root root {size:>6} Oct  3 09:12 {n}\n"
            elif names:
                out += "  ".join(names) + "\n"
        return out, status

    def cmd_cat(self, a, stdin, d):
        if not a:
            return stdin, 0
        out, status = "", 0
        for p in a:
            ap = self._abs(p)
            c = self.fs.get(ap, False)
            if c is False:
                out += f"cat: {p}: No such file or directory\n"
                status = 1
            elif c is None:
                out += f"cat: {p}: Is a directory\n"
                status = 1
            else:
                out += c
                if ap in TRIPWIRES:
                    self.emit("tripwire", path=ap, cwd=self.cwd)
        return out, status

    def cmd_mkdir(self, a, stdin, d):
        out, flags = "", [x for x in a if x.startswith("-")]
        for p in (x for x in a if not x.startswith("-")):
            ap, parts = self._abs(p), []
            while ap not in self.fs and ap != "/":
                parts.append(ap)
                ap = posixpath.dirname(ap)
            if len(parts) > 1 and "-p" not in flags:
                out += f"mkdir: cannot create directory '{p}': No such file or directory\n"
            elif not parts:
                out += f"mkdir: cannot create directory '{p}': File exists\n"
            else:
                for q in parts:
                    self.fs[q] = None
        return out, 1 if out else 0

    def cmd_touch(self, a, stdin, d):
        for p in a:
            ap = self._abs(p)
            if posixpath.dirname(ap) in self.fs:
                self.fs.setdefault(ap, "")
        return "", 0

    def cmd_chmod(self, a, stdin, d):
        files = [x for x in a[1:] if not x.startswith("-")]
        out = "".join(f"chmod: cannot access '{f}': No such file or directory\n"
                      for f in files if self._abs(f) not in self.fs)
        return out, 1 if out else 0

    def cmd_rm(self, a, stdin, d):
        out = ""
        for p in (x for x in a if not x.startswith("-")):
            ap = self._abs(p)
            if ap == "/":
                return "rm: it is dangerous to operate recursively on '/'\n", 1
            if ap not in self.fs:
                out += f"rm: cannot remove '{p}': No such file or directory\n"
                continue
            for k in [k for k in self.fs if k == ap or k.startswith(ap + "/")]:
                del self.fs[k]
        return out, 1 if out else 0

    def _cp(self, a, move: bool):
        args = [x for x in a if not x.startswith("-")]
        if len(args) < 2:
            return "cp: missing file operand\n", 1
        src, dst = self._abs(args[0]), self._abs(args[-1])
        if self.fs.get(src, False) in (False, None):
            return f"cp: cannot stat '{args[0]}': No such file or directory\n", 1
        if self.fs.get(dst, False) is None:
            dst = posixpath.join(dst, posixpath.basename(src))
        self.fs[dst] = self.fs[src]
        if move:
            del self.fs[src]
        return "", 0

    def cmd_cp(self, a, stdin, d):
        return self._cp(a, False)
    def cmd_mv(self, a, stdin, d):
        return self._cp(a, True)

    def cmd_export(self, a, stdin, d):
        for x in a:
            k, _, v = x.partition("=")
            if _:
                self.env[k] = v
        return "", 0

    def cmd_which(self, a, stdin, d):
        known = self._builtin_names()
        out = "".join(f"/usr/bin/{x}\n" for x in a if x in known)
        return out, 0 if out else 1

    def cmd_crontab(self, a, stdin, d):
        return ("no crontab for root\n", 1) if "-l" in a else ("", 0)

    def cmd_grep(self, a, stdin, d):
        flags = [x for x in a if x.startswith("-")]
        rest = [x for x in a if not x.startswith("-")]
        if not rest:
            return "", 2
        text = stdin
        if len(rest) > 1:
            text = self.fs.get(self._abs(rest[1])) or ""
        try:
            rx = re.compile(rest[0], re.I if "-i" in flags else 0)
        except re.error:
            return "grep: Invalid regular expression\n", 2
        inv = "-v" in flags
        hits = [ln for ln in text.splitlines() if bool(rx.search(ln)) != inv]
        return "".join(h + "\n" for h in hits), 0 if hits else 1

    def cmd_head(self, a, stdin, d):
        n = 10
        for i, x in enumerate(a):
            if x == "-n" and i + 1 < len(a) and a[i + 1].isdigit():
                n = int(a[i + 1])
        return "".join(ln + "\n" for ln in stdin.splitlines()[:n]), 0

    def cmd_wc(self, a, stdin, d):
        return (f"{len(stdin.splitlines())}\n" if "-l" in a else
                f"{len(stdin.splitlines())} {len(stdin.split())} {len(stdin)}\n"), 0

    def _shell(self, a, stdin, depth):
        if a and a[0] == "-c" and len(a) > 1:
            return self.run(a[1], depth + 1), 0
        if stdin.strip():
            return self.run(stdin.replace("\n", ";"), depth + 1), 0
        return "", 0
    cmd_sh = cmd_bash = cmd_dash = _shell

    def cmd_wget(self, a, stdin, d):
        return self._fetch("wget", a)

    def cmd_curl(self, a, stdin, d):
        return self._fetch("curl", a)

    def _fetch(self, tool: str, a: list[str]) -> tuple[str, int]:
        urls = [x for x in a if "://" in x]
        if not urls:
            return f"{tool}: missing URL\n", 1
        out_name = None
        for i, x in enumerate(a):
            if x in ("-O", "-o") and i + 1 < len(a) and not (tool == "curl" and x == "-O"):
                out_name = a[i + 1]
        out = ""
        for u in urls:
            self.emit("download_attempt", tool=tool, url=u, cwd=self.cwd, sev=3)
            p = urlparse(u)
            name = out_name or posixpath.basename(p.path) or "index.html"
            if tool == "curl" and "-O" not in a and not out_name:
                continue  # curl without -o writes to stdout; nothing to show or store
            size = 1024 + (sum(map(ord, u)) % 4000)
            dest = self._abs(name)
            if posixpath.dirname(dest) in self.fs and self.fs.get(dest, "") is not None:
                self.fs[dest] = "\0" * size
            if tool == "wget":
                out += (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {u}\nResolving {p.hostname}... done.\n"
                        f"Connecting to {p.hostname}|{p.hostname}|:{p.port or 80}... connected.\n"
                        f"HTTP request sent, awaiting response... 200 OK\nLength: {size} "
                        f"[application/octet-stream]\nSaving to: '{name}'\n\n"
                        f"{name}  100%[=========>] {size / 1024:.2f}K  --.-KB/s    in 0s\n\n"
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} - '{name}' saved [{size}/{size}]\n\n")
        return out, 0
