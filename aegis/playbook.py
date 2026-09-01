"""Engagement playbook — data-driven service→attack knowledge base.

Hint data lives in JSON, not code:
  - bundled defaults: aegis/playbook.json   (ships with the tool)
  - your overlay:     playbook.custom.json  (in the engagement workspace)

Custom rules are checked FIRST and the KB is re-read on every planning step,
so a rule added from the War Room mid-engagement is used by the very next
agent decision — no restart, no code edits.

Hint priority (planner sees highest-value first):
  1. version-specific named exploits  2. service-level playbooks
  3. port fallbacks                   4. web enumeration chain
  5. domain recon chain               6. credential reuse
  7. generic version→searchsploit research fallback

Every hint names tools from the allowlist and paths that exist on disk.
Callers replace the literal TARGET placeholder with the engagement host.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DEFAULT_KB = Path(__file__).resolve().parent / "playbook.json"
CUSTOM_KB_NAME = "playbook.custom.json"

KB_GROUPS = ("version_hints", "service_hints", "port_hints")

WEB_PORTS = {"80", "443", "8080", "8000", "8443", "8888", "3000", "5000"}

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
                       re.I)
VERSION_PROD_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]{2,25})[/ ]v?"
                             r"(\d+\.\d+(?:\.\d+)?)")
PORT_KEY_RE = re.compile(r"\d{1,5}(/(tcp|udp))?")


# ---- KB loading & overlay ----------------------------------------------------

def load_kb(workspace: str | Path = ".") -> dict:
    """Bundled defaults overlaid with workspace custom rules.
    Custom hints are prepended (they win); dicts merge with custom winning.
    Re-read on every call = hot reload."""
    kb = json.loads(_DEFAULT_KB.read_text(encoding="utf-8"))
    custom_path = Path(workspace) / CUSTOM_KB_NAME
    if custom_path.exists():
        try:
            custom = json.loads(custom_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            from .diag import get_logger
            get_logger("playbook").error(
                "corrupt %s — ignoring custom rules", custom_path)
            return kb
        for group in ("version_hints", "service_hints"):
            kb[group] = list(custom.get(group, [])) + kb[group]
        for group in ("port_hints", "wordlists"):
            merged = dict(kb.get(group, {}))
            merged.update(custom.get(group, {}))
            kb[group] = merged
    return kb


def list_custom_rules(workspace: str | Path = ".") -> dict:
    path = Path(workspace) / CUSTOM_KB_NAME
    if not path.exists():
        return {"version_hints": [], "service_hints": [], "port_hints": {},
                "drafts": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version_hints": [], "service_hints": [], "port_hints": {},
                "drafts": []}
    data.setdefault("drafts", [])
    return data


def _write_custom(workspace: str | Path, data: dict) -> None:
    path = Path(workspace) / CUSTOM_KB_NAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)


def add_custom_rule(workspace: str | Path, group: str, pattern: str,
                    hint: str) -> None:
    """Validate and append a rule to playbook.custom.json (atomic write).
    Duplicates are a no-op. Raises ValueError on invalid input."""
    if group not in KB_GROUPS:
        raise ValueError(f"group must be one of {KB_GROUPS}")
    pattern, hint = pattern.strip(), hint.strip()
    if not pattern or not hint:
        raise ValueError("pattern and hint are required")
    if len(hint) > 500 or len(pattern) > 200:
        raise ValueError("pattern ≤200 chars, hint ≤500 chars")
    if "TARGET" not in hint:
        hint += "  (note: no TARGET placeholder in hint)"
    if group == "port_hints":
        if not PORT_KEY_RE.fullmatch(pattern):
            raise ValueError(f"port pattern must look like '6379' or '161/udp', "
                             f"got '{pattern}'")
    else:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex '{pattern}': {exc}") from exc

    path = Path(workspace) / CUSTOM_KB_NAME
    data = list_custom_rules(workspace)
    for g in KB_GROUPS:
        data.setdefault(g, {} if g == "port_hints" else [])
    if group == "port_hints":
        data[group][pattern] = hint
    else:
        if [pattern, hint] not in data[group]:
            data[group].append([pattern, hint])
    _write_custom(workspace, data)


# ---- learning loop: success → reviewed rule ---------------------------------

def _match_service(services: list[dict], vector: str, command: str,
                   tool: str) -> dict | None:
    """Find the intel service an attempt most plausibly hit."""
    port = None
    m = re.search(r"(?:tcp|udp)/(\d{1,5})", vector or "")
    if not m:
        m = re.search(r"[:\s](\d{2,5})\b", vector or "")
    if not m:
        m = re.search(r"://[^/\s]*?:(\d{2,5})", command or "")
    if m:
        port = m.group(1)
    if port:
        for s in services:
            if s["key"].split("/")[0] == port:
                return s
    words = set(re.findall(r"[a-z]{3,}", f"{vector or ''} {tool}".lower()))
    for s in services:
        if any(w in s["value"].lower() for w in words):
            return s
    return None


def learn_from_success(db, target_id: int, technique: str, vector: str,
                       tool: str, command: str, host: str,
                       workspace: str | Path = ".") -> dict | None:
    """A successful attack step → draft KB rule for operator review.

    Drafts are NOT live until promoted. Skipped when a version-specific rule
    already covers the service, when no service context exists, or when an
    identical draft is already pending."""
    services = [dict(r) for r in db.intel_for(target_id)
                if r["kind"] == "service"]
    if not services:
        return None
    svc = _match_service(services, vector or technique, command, tool)
    if not svc:
        return None
    text = svc["value"].lower()
    kb = load_kb(workspace)
    for pattern, _hint in kb["version_hints"]:
        try:
            if re.search(pattern, text):
                return None  # already known at version precision
        except re.error:
            continue

    command_tpl = (command or "").replace(host, "TARGET")[:240]
    m = VERSION_PROD_RE.search(svc["value"])
    if m:
        product, version = m.group(1), m.group(2)
        majmin = ".".join(version.split(".")[:2])
        pattern = re.escape(product.lower()) + r".*" + re.escape(majmin)
        group = "version_hints"
        hint = (f"{product} {version} → learned from a successful engagement "
                f"on this exact version: {technique} via {tool}: "
                f"{command_tpl}")
    else:
        product = svc["value"].split()[0]
        pattern = "^" + re.escape(product.lower())
        group = "service_hints"
        hint = (f"{product} → learned from a successful engagement: "
                f"{technique} via {tool}: {command_tpl}")

    data = list_custom_rules(workspace)
    drafts = data.setdefault("drafts", [])
    if any(d.get("pattern") == pattern and d.get("group") == group
           for d in drafts):
        return None
    # not already a live custom rule either
    if group != "port_hints" and [pattern, hint] in data.get(group, []):
        return None
    import time as _t
    drafts.append({"group": group, "pattern": pattern, "hint": hint,
                   "source": (command or "")[:200],
                   "ts": _t.strftime("%Y-%m-%d %H:%M:%S")})
    _write_custom(workspace, data)
    return {"group": group, "pattern": pattern, "hint": hint}


def promote_draft(workspace: str | Path, index: int) -> dict:
    """Move a reviewed draft into the live rules."""
    data = list_custom_rules(workspace)
    drafts = data.get("drafts", [])
    if not 0 <= index < len(drafts):
        raise ValueError(f"no draft #{index}")
    d = drafts.pop(index)
    data["drafts"] = drafts
    _write_custom(workspace, data)
    add_custom_rule(workspace, d["group"], d["pattern"], d["hint"])
    return d


def dismiss_draft(workspace: str | Path, index: int) -> dict:
    """Drop a draft the operator rejects."""
    data = list_custom_rules(workspace)
    drafts = data.get("drafts", [])
    if not 0 <= index < len(drafts):
        raise ValueError(f"no draft #{index}")
    d = drafts.pop(index)
    data["drafts"] = drafts
    _write_custom(workspace, data)
    return d


# ---- wordlists ---------------------------------------------------------------

def available_wordlists(workspace: str | Path = ".") -> dict[str, str]:
    """kind -> first wordlist path that actually exists on this machine."""
    out: dict[str, str] = {}
    for kind, cands in load_kb(workspace).get("wordlists", {}).items():
        for c in cands:
            if Path(c).exists():
                out[kind] = c
                break
    return out


# ---- hint generation -----------------------------------------------------------

def hints_for(intel_items: list[dict], loot: list[dict] | None = None,
              target: str = "", workspace: str | Path = ".") -> list[str]:
    """Concrete attack hints derived from extracted intel (+ optional loot).
    Priority-ordered, deduped, capped. 'TARGET' is a placeholder."""
    kb = load_kb(workspace)
    services = [i for i in intel_items if i["kind"] == "service"]
    version_hints: list[str] = []
    service_hints: list[str] = []
    port_hints: list[str] = []

    for svc in services:
        text = svc["value"].lower()
        for pattern, hint in kb["version_hints"]:
            if re.search(pattern, text):
                version_hints.append(hint)
        matched_service = False
        for pattern, hint in kb["service_hints"]:
            if re.search(pattern, text):
                service_hints.append(hint)
                matched_service = True
        if not matched_service:
            port = svc["key"].split("/")[0]
            if port in kb["port_hints"]:
                port_hints.append(kb["port_hints"][port])

    # 4. web enumeration chain (real-world + bug bounty checks)
    web_hints: list[str] = []
    web_ports = {s["key"].split("/")[0] for s in services
                 if re.search(r"http|ssl|www", s["value"].lower())}
    web_ports |= {s["key"].split("/")[0] for s in services
                  if s["key"].split("/")[0] in WEB_PORTS}
    if web_ports:
        wl = available_wordlists(workspace).get("web-dirs")
        chain = (f"HTTP on port(s) {sorted(web_ports)} → enum chain: "
                 "whatweb http://TARGET; curl -sI http://TARGET (server/"
                 "powered-by headers); check /robots.txt /.git/HEAD /.env "
                 "/.well-known/security.txt /sitemap.xml /backup.zip; "
                 "nikto -h http://TARGET; nuclei -u http://TARGET")
        if wl:
            chain += (f"; directory brute: gobuster dir -u http://TARGET "
                      f"-w {wl} (exists on disk)")
        chain += ("; CORS check: curl -sI -H 'Origin: https://evil.example' "
                  "http://TARGET — a reflected origin + credentials:true is "
                  "a bounty finding")
        web_hints.append(chain)

    # 5. domain recon chain (bug bounty) — only for domain targets
    domain_hints: list[str] = []
    if target and DOMAIN_RE.match(target):
        sub_wl = available_wordlists(workspace).get("subdomains")
        chain = (f"'{target}' is a domain → recon chain: sublist3r -d {target}; "
                 "amass enum -passive -d TARGET (OSINT collector already pulls "
                 "crt.sh + DNS); IMPORTANT: verify every discovered subdomain "
                 "against authorization.json scope before touching it")
        if sub_wl:
            chain += (f"; vhost fuzz: ffuf -u http://TARGET -H 'Host: "
                      f"FUZZ.{target}' -w {sub_wl}")
        domain_hints.append(chain)

    # 6. credential reuse — #1 real-world escalation path
    reuse_hints: list[str] = []
    creds = [l for l in (loot or []) if l.get("kind") == "credential"]
    if creds:
        login_svcs = sorted({s["value"].split()[0] for s in services
                             if re.search(r"ssh|ftp|mysql|mssql|postgres|"
                                          r"smb|rdp|telnet|vnc|pop3|imap",
                                          s["value"].lower())})
        svc_txt = ", ".join(login_svcs) if login_svcs else "any login service"
        reuse_hints.append(
            f"{len(creds)} credential(s) in loot → stuff them across every "
            f"discovered login service ({svc_txt}): hydra -l <user> -p <pass> "
            "TARGET <svc>; also try web login forms — password reuse is the "
            "most common real-world escalation")
        reuse_hints.append(
            "Creds available → after any shell: /privesc TARGET for kernel/"
            "service exploit research; manually check sudo -l, SUID binaries, "
            "cron jobs, writable paths")

    # 7. generic version research fallback
    fallback: list[str] = []
    products = []
    for svc in services:
        m = VERSION_PROD_RE.search(svc["value"])
        if m:
            products.append(f"{m.group(1)} {m.group(2)}")
    if products:
        fallback.append("Version research: searchsploit " +
                        " / searchsploit ".join(f'"{p}"' for p in products[:5]) +
                        " (or run /privesc TARGET which does this for you)")

    # assemble in priority order, dedupe, cap
    seen, out = set(), []
    for h in (version_hints + service_hints + port_hints + web_hints +
              domain_hints + reuse_hints + fallback):
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:15]
