"""Connection limits. A honeypot must not become free infrastructure for attackers."""
from __future__ import annotations

from collections import defaultdict


class ConnLimiter:
    def __init__(self, per_ip: int, total: int):
        self.per_ip, self.total = per_ip, total
        self._by_ip: defaultdict[str, int] = defaultdict(int)
        self._n = 0

    def acquire(self, ip: str) -> bool:
        if self._n >= self.total or self._by_ip[ip] >= self.per_ip:
            return False
        self._by_ip[ip] += 1
        self._n += 1
        return True

    def release(self, ip: str) -> None:
        if self._by_ip[ip] > 0:
            self._by_ip[ip] -= 1
            self._n -= 1
            if not self._by_ip[ip]:
                del self._by_ip[ip]
