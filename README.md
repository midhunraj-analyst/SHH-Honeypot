# sentinel

A low-interaction honeypot written from scratch: SSH + HTTP decoys, a pure-Python
shell emulator, ATT&CK-tagged telemetry, and a tamper-evident log. Nothing an
attacker types is ever executed; downloads are recorded, never fetched.

```
 attacker ──► :22  asyncssh server ─┐
                                    ├─► Shell emulator ─► classify (ATT&CK, IOCs)
 attacker ──► :80  asyncio HTTP ────┘            │
                                                 ▼
                         EventLog (hash-chained JSONL) ─► Alerter (dedupe + rate cap)
```

| Module | Job |
|---|---|
| `shell.py` | In-memory filesystem + ~40 commands, per-sensor fake identity, tripwire files |
| `ssh_service.py` | Auth policy (lets an IP "crack in" after 2-5 tries), pubkey fingerprints, forwarding logged+refused |
| `http_service.py` | Hand-rolled HTTP: fake WP login, `.env`, `.git/config`, logs full requests |
| `enrich.py` | Regex rules -> behaviour tags + MITRE ATT&CK IDs + extracted URLs/IPs |
| `events.py` | Each line embeds SHA-256 of the previous one; `verify()` finds edits/deletions |
| `alerts.py` | Slack/Discord webhook, per-(IP,kind,tags) dedupe, 30/hour cap |
| `report.py` | `sentinel-report`: verify chain, top IPs/creds/commands/techniques/IOC URLs |

## Local run (VS Code)

1. Open the folder (or "Reopen in Container"). Run task **Install dev deps**.
2. `F5` -> *Run sensor (local, high ports)*.
3. Tasks: **Live event feed**, then **Attack it: SSH** (try `root` / `123456`) and **Attack it: web probes**.
4. Tasks: **Test**, **Report**, **Verify log chain**.

## Deploy (GitHub Actions -> your server)

One-time, on a **throwaway VPS with nothing else on it**:

1. Move real sshd to another port (e.g. 2200). Confirm you can log in on it *before* closing your session.
2. Install Docker + compose plugin. Create user `deploy` in the `docker` group.
3. `ssh-keygen -t ed25519 -f deploy_key`; put `deploy_key.pub` in `~deploy/.ssh/authorized_keys`.
4. Allow exactly one privileged command: `echo 'deploy ALL=(root) NOPASSWD: /home/deploy/sentinel/deploy/egress-lockdown.sh' | sudo tee /etc/sudoers.d/sentinel`
5. Repo secrets: `SSH_PRIVATE_KEY`, `SSH_KNOWN_HOSTS` (from `ssh-keyscan -p 2200 IP`), `SSH_HOST`, `SSH_PORT`, `SSH_USER`, `SENSOR_ID`, optional `ALERT_WEBHOOK`.
6. Create a `production` environment (add yourself as required reviewer for a manual gate).
7. Push to `main`: CI (ruff, pytest, pip-audit, container healthcheck) -> image built on the runner,
   streamed to the server over SSH (no registry) -> `compose up` -> egress lockdown -> health check.

If the webhook needs it, set `ALLOW_EGRESS` / `ALLOW_DNS` for the lockdown script on the server (see the script header).
`integrity.yml` runs daily: verifies the log chain (a break fails the run and emails you) and posts a digest.

Rollback: `ssh host 'cd ~/sentinel && TAG=<old-sha> docker compose up -d'` (images are kept 7 days).

## Safety model

- Shell emulation only: no subprocess, no real file I/O, no outbound requests from attacker input.
- Container: non-root, read-only rootfs, all caps dropped, no-new-privileges, CPU/mem/pids limits.
- Network: container egress dropped at the host firewall; per-IP and global connection caps; session time/idle/command caps.
- Port forwarding refused (logged as `tcp_forward_attempt`).
- Only run on infrastructure you own. Check your provider's terms of service allow honeypots.

## Tuning and ideas

- Per-sensor persona comes from `SENSOR_ID`; run several with different IDs so they don't share a fingerprint.
- Replace the tripwire creds in `shell.py` with real canary tokens (e.g. canarytokens.org AWS keys): then a stolen file being *used* elsewhere alerts you too.
- Ship `events.jsonl` off-host (Loki/Vector/Filebeat). The hash chain proves edits, not truncation of the tail.
- Next steps: HASSH client fingerprinting, GeoIP/ASN enrichment, a sandboxed (no-egress) payload detonator, Telnet/Redis/MySQL decoys, STIX export of IOCs.

## Known limits

Low interaction means a careful attacker can fingerprint it (no real processes, `/proc` is thin, commands are a subset).
That is the trade-off for safety. `SSH_BANNER` must be a single token (e.g. `OpenSSH_8.9p1`); asyncssh may reject spaces.
