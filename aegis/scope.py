"""Scope & authorization gate — the legal-use enforcement layer.

Nothing executes against a host unless it matches the engagement scope in
`authorization.json` and the authorization window is still valid. Out-of-scope
attempts are refused *and* written to the audit log.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
import time
from pathlib import Path


class ScopeError(Exception):
    pass


class ScopeGate:
    def __init__(self, authorization_path: str | Path):
        self.path = Path(authorization_path)
        if not self.path.exists():
            raise ScopeError(
                f"No authorization file at {self.path}. "
                "Create one from authorization.example.json — Aegis refuses to "
                "operate without a declared, authorized scope."
            )
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.engagement = data.get("engagement", "unnamed")
        self.scope: list[str] = data.get("scope", [])
        self.exclusions: list[str] = data.get("exclusions", [])
        self.valid_from = data.get("valid_from", "1970-01-01")
        self.valid_until = data.get("valid_until", "9999-12-31")
        # Rules of engagement (bug-bounty / client contract constraints)
        self.roe: dict = {
            "prohibited_techniques": data.get("prohibited_techniques", []),
            "max_requests_per_second": data.get("max_requests_per_second", 0),
            "testing_hours": data.get("testing_hours", ""),
        }
        if not self.scope:
            raise ScopeError("authorization.json has an empty scope.")
        self._check_window()

    def add_to_scope(self, entry: str) -> None:
        """Add a host/CIDR to authorization.json and reload in-memory scope.

        This edits the operator's own scope document at the operator's
        explicit request (dashboard/CLI). Every change is audit-logged by
        the caller; the file write is atomic (write tmp + replace).
        """
        entry = entry.strip()
        if not entry:
            raise ScopeError("empty scope entry")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        scope_list = data.setdefault("scope", [])
        if entry not in scope_list:
            scope_list.append(entry)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        if entry not in self.scope:
            self.scope.append(entry)

    def _check_window(self) -> None:
        today = time.strftime("%Y-%m-%d")
        if not (self.valid_from <= today <= self.valid_until):
            raise ScopeError(
                f"Authorization window expired/not started "
                f"({self.valid_from} → {self.valid_until}, today {today})."
            )

    def _resolve(self, host: str) -> str:
        """Return an IP for domain names so CIDR scope entries can match."""
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except OSError:
            return ""

    def is_in_scope(self, host: str) -> bool:
        host = host.strip().lower()
        for ex in self.exclusions:
            if self._matches(host, ex):
                return False
        return any(self._matches(host, entry) for entry in self.scope)

    def _matches(self, host: str, entry: str) -> bool:
        entry = entry.strip().lower()
        # CIDR
        if "/" in entry:
            ip = host if self._is_ip(host) else self._resolve(host)
            if not ip:
                return False
            try:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False)
            except ValueError:
                return False
        # single IP
        if self._is_ip(entry):
            return host == entry or self._resolve(host) == entry
        # wildcard / plain domain
        if entry.startswith("*."):
            return host == entry[2:] or fnmatch.fnmatch(host, entry)
        return host == entry or fnmatch.fnmatch(host, entry)

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def check(self, host: str) -> None:
        """Raise ScopeError if host is out of scope."""
        self._check_window()
        if not self.is_in_scope(host):
            raise ScopeError(
                f"'{host}' is NOT in the authorized scope for engagement "
                f"'{self.engagement}'. Refusing to act. Add it to "
                f"authorization.json only if you have written authorization."
            )
