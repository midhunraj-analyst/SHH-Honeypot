#!/usr/bin/env bash
# Drop every NEW outbound connection originating from the honeypot network.
# Replies to attackers (ESTABLISHED/RELATED) still flow. A compromised honeypot
# therefore cannot scan, spam or attack anyone else.
#
#   ALLOW_EGRESS="203.0.113.10 hooks.example.com-ip"   # webhook IPs (tcp/443)
#   ALLOW_DNS="1.1.1.1"                                # only if the webhook needs name resolution
#
# Idempotent. Rules live in memory: re-run after reboot (the deploy workflow does).
set -euo pipefail

SUBNET="${SUBNET:-172.29.0.0/24}"
CHAIN=SENTINEL-EGRESS

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for dst in ${ALLOW_EGRESS:-}; do
  iptables -A "$CHAIN" -d "$dst" -p tcp --dport 443 -j RETURN
done
for dns in ${ALLOW_DNS:-}; do
  iptables -A "$CHAIN" -d "$dns" -p udp --dport 53 -j RETURN
  iptables -A "$CHAIN" -d "$dns" -p tcp --dport 53 -j RETURN
done
iptables -A "$CHAIN" -m limit --limit 5/min -j LOG --log-prefix "SENTINEL-EGRESS-DROP " --log-level 4
iptables -A "$CHAIN" -j DROP

iptables -C DOCKER-USER -s "$SUBNET" -j "$CHAIN" 2>/dev/null \
  || iptables -I DOCKER-USER 1 -s "$SUBNET" -j "$CHAIN"
echo "egress lockdown active for $SUBNET (allow: ${ALLOW_EGRESS:-none})"
