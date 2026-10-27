"""sentinel-report: verify the hash chain and summarise what the sensor saw."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .events import verify


def _top(title: str, counter: Counter, n: int) -> None:
    print(f"\n== {title}")
    for key, count in counter.most_common(n):
        print(f"{count:>7}  {key}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log", type=Path, nargs="?", default=Path("data/events.jsonl"))
    ap.add_argument("--verify", action="store_true", help="only verify chain integrity")
    ap.add_argument("-n", type=int, default=10, help="rows per table")
    args = ap.parse_args()

    ok, count, bad = verify(args.log)
    print(f"{count} records, chain {'OK' if ok else f'BROKEN at line {bad}'}")
    if args.verify:
        return 0 if ok else 2

    ips, users, pwds, cmds, tags, attack, urls = (Counter() for _ in range(7))
    kinds, sessions = Counter(), set()
    with args.log.open(encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            kinds[e["kind"]] += 1
            if "src_ip" in e:
                ips[e["src_ip"]] += 1
            if e["kind"] in ("ssh_auth", "login_attempt"):
                users[e.get("username", "")] += 1
                pwds[e.get("password", "")] += 1
            if e["kind"] == "ssh_command":
                cmds[e["command"][:80]] += 1
                sessions.add(e["sid"])
            tags.update(e.get("tags", []))
            attack.update(e.get("attack", []))
            urls.update(e.get("iocs", {}).get("urls", []))
            if e["kind"] == "download_attempt":
                urls[e["url"]] += 1
    _top("events by kind", kinds, args.n)
    _top("top source IPs", ips, args.n)
    _top("usernames tried", users, args.n)
    _top("passwords tried", pwds, args.n)
    _top("commands", cmds, args.n)
    _top("behaviour tags", tags, args.n)
    _top("MITRE ATT&CK techniques", attack, args.n)
    _top("payload URLs (IOCs)", urls, args.n)
    print(f"\nsessions with commands: {len(sessions)}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
