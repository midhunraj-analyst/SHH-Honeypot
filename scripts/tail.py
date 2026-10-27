"""Colourised live view:  tail -F data/events.jsonl | python scripts/tail.py"""
import json
import sys

COLOUR = {1: "\033[90m", 2: "\033[0m", 3: "\033[33m", 4: "\033[1;31m"}

for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    detail = e.get("command") or e.get("url") or e.get("path") or e.get("username") or ""
    if e["kind"] == "ssh_auth":
        detail = f"{e.get('username')}:{e.get('password')} {'OK' if e.get('success') else 'x'}"
    tags = ",".join(e.get("tags", []))
    print(f"{COLOUR.get(e['sev'], '')}{e['ts'][11:19]} s{e['sev']} {e['kind']:<19} "
          f"{e.get('src_ip', '-'):<15} {str(detail)[:80]:<80} {tags}\033[0m", flush=True)
