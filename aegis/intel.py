"""Target intelligence extraction — turns raw tool output into structured
knowledge about the target (services, versions, web stack, OS) and hunts
flags/secrets in everything we capture.

All extraction is deterministic regex work: no LLM, no hallucination.
Stored in the `intel` table; feeds the dashboard command center, the
planner's memory, and the playbook's attack hints.
"""

from __future__ import annotations

import re

# ---- service / version extraction ------------------------------------------

# nmap -sV style: "80/tcp open  http    Apache httpd 2.4.49 ((Unix))"
NMAP_SVC_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(\S.*?)\s*$", re.M)
NMAP_OS_RE = re.compile(
    r"(?:OS details|Running|Aggressive OS guesses):\s*(.+)", re.I)

# HTTP headers as printed by curl -I, nmap http-headers, nikto, etc.
HDR_SERVER_RE = re.compile(r"^Server:\s*(.+?)\s*$", re.M | re.I)
HDR_POWERED_RE = re.compile(r"^X-Powered-By:\s*(.+?)\s*$", re.M | re.I)

# whatweb bracket plugins: Apache[2.4.41], PHP[7.4.3], WordPress[5.8]
WHATWEB_PLUGIN_RE = re.compile(
    r"(Apache|nginx|Microsoft-IIS|IIS|PHP|WordPress|Drupal|Joomla|Tomcat|"
    r"LiteSpeed|OpenResty|jQuery|Bootstrap|ASP\.NET)"
    r"(?:\[([^\[\]]+)\])?", re.I)


def extract_intel(tool: str, command: str, output: str) -> list[dict]:
    """Return intel items: {kind, key, value}. kind: service|web|os|tech."""
    items: list[dict] = []
    if not output:
        return items

    for port, proto, svc, ver in NMAP_SVC_RE.findall(output):
        items.append({"kind": "service", "key": f"{port}/{proto}",
                      "value": f"{svc} {ver}".strip()})
    for m in NMAP_OS_RE.finditer(output):
        os_guess = m.group(1).split(",")[0].strip()
        if os_guess:
            items.append({"kind": "os", "key": "os", "value": os_guess})
    for m in HDR_SERVER_RE.finditer(output):
        items.append({"kind": "web", "key": "server", "value": m.group(1)})
    for m in HDR_POWERED_RE.finditer(output):
        items.append({"kind": "web", "key": "x-powered-by",
                      "value": m.group(1)})
    if tool == "whatweb":
        for name, ver in WHATWEB_PLUGIN_RE.findall(output):
            items.append({"kind": "tech", "key": name.lower(),
                          "value": f"{name} {ver}".strip()})
    return items


# ---- flag / secret hunting ---------------------------------------------------

FLAG_RES = [
    re.compile(r"THM\{[^\}\s]{1,80}\}", re.I),
    re.compile(r"HTB\{[^\}\s]{1,80}\}", re.I),
    re.compile(r"(?:flag|ctf)[_-]?\{[^\}\s]{1,80}\}", re.I),
]
HEX32_RE = re.compile(r"\b[0-9a-f]{32}\b")          # bare HTB-style flags
PRIVKEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def hunt_flags(output: str) -> list[dict]:
    """Scan captured output for flags and secrets. Returns loot dicts."""
    if not output:
        return []
    found: list[dict] = []
    seen: set[str] = set()

    def add(kind, title, value):
        if value and value not in seen:
            seen.add(value)
            found.append({"kind": kind, "title": title, "value": value})

    for rx in FLAG_RES:
        for m in rx.finditer(output):
            add("flag", "flag captured in output", m.group(0))
    if PRIVKEY_RE.search(output):
        # capture the whole key block
        block = re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
                          r"-----END [A-Z ]*PRIVATE KEY-----",
                          output, re.S)
        add("credential", "private key captured",
            block.group(0) if block else "(private key present)")
    for m in HEX32_RE.finditer(output):
        # only when the surrounding text suggests a flag context
        ctx = output[max(0, m.start() - 40):m.end() + 40].lower()
        if "flag" in ctx or "root" in ctx or "user.txt" in ctx:
            add("flag", "possible 32-hex flag", m.group(0))
    return found
