"""Metasploit RPC integration (msfrpcd over HTTP/msgpack).

Requires: msfrpcd -P <password> -S -a 127.0.0.1 running on Kali,
and `pip install msgpack`. Used for validated exploitation and session
management instead of one-shot msfconsole scripts.
"""

from __future__ import annotations

import requests

try:
    import msgpack
    _HAS_MSGPACK = True
except ImportError:
    _HAS_MSGPACK = False


class MsfError(Exception):
    pass


class MetasploitRPC:
    def __init__(self, config: dict):
        import os
        mc = config.get("msf", {})
        self.host = mc.get("host", "127.0.0.1")
        self.port = int(mc.get("port", 55553))
        self.user = mc.get("user", "msf")
        # secrets come from the environment, never plaintext config
        self.password = os.environ.get("AEGIS_MSF_PASSWORD", "")
        self.ssl = bool(mc.get("ssl", False))
        self.token: str | None = None

    @property
    def url(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/"

    def available(self) -> bool:
        if not _HAS_MSGPACK:
            return False
        try:
            r = requests.post(self.url, data=msgpack.packb(["core.version"]),
                              headers={"Content-Type": "binary/message-pack"},
                              timeout=5, verify=False)
            return r.ok
        except requests.RequestException:
            return False

    def _call(self, method: str, *args):
        if not _HAS_MSGPACK:
            raise MsfError("msgpack not installed — pip install msgpack")
        payload = [method, self.token, *args] if self.token else [method, *args]
        r = requests.post(self.url, data=msgpack.packb(payload),
                          headers={"Content-Type": "binary/message-pack"},
                          timeout=30, verify=False)
        r.raise_for_status()
        resp = msgpack.unpackb(r.content, raw=False)
        if isinstance(resp, dict) and resp.get("error"):
            raise MsfError(f"msfrpc {method}: {resp.get('error_message')}")
        return resp

    def login(self) -> None:
        resp = self._call("auth.login", self.user, self.password)
        if resp.get("result") != "success":
            raise MsfError("msfrpc login failed")
        self.token = resp["token"]

    def run_exploit(self, module: str, rhost: str, payload: str = "",
                    options: dict | None = None) -> dict:
        """Execute an exploit module against an in-scope rhost."""
        if not self.token:
            self.login()
        opts = {"RHOSTS": rhost, **(options or {})}
        if payload:
            opts["PAYLOAD"] = payload
        return self._call("module.execute", "exploit", module, opts)

    def run_auxiliary(self, module: str, rhost: str,
                      options: dict | None = None) -> dict:
        if not self.token:
            self.login()
        opts = {"RHOSTS": rhost, **(options or {})}
        return self._call("module.execute", "auxiliary", module, opts)

    def sessions(self) -> dict:
        if not self.token:
            self.login()
        return self._call("session.list")
