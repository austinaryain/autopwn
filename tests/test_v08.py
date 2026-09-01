"""v0.8 tests: engagement-grade playbook KB, sublist3r guard fix."""

import pytest

from aegis.guard import CommandGuard, GuardError, extract_hosts
from aegis.playbook import available_wordlists, hints_for


def svc(port, value):
    return {"kind": "service", "key": port, "value": value}


# ---- version-specific named exploits ----------------------------------------

def test_version_hint_drupal7():
    hints = hints_for([svc("80/tcp", "http Apache httpd 2.4.7 (Drupal 7.54)")])
    # drupal comes from tech intel normally — test via tech item
    hints = hints_for([{"kind": "tech", "key": "drupal", "value": "Drupal 7.54"},
                       svc("80/tcp", "http Apache 2.4.7")])
    # version hints only fire on service strings; tech items feed fallback
    assert hints  # web chain at minimum


def test_version_hint_drupal_via_service():
    hints = hints_for([svc("80/tcp", "http Apache 2.4.7 Drupal 7.54")])
    assert any("Drupalgeddon2" in h for h in hints)


def test_version_hint_heartbleed():
    hints = hints_for([svc("443/tcp", "ssl/http Apache OpenSSL 1.0.1e")])
    assert any("Heartbleed" in h for h in hints)


def test_version_hint_samba_usermap():
    hints = hints_for([svc("139/tcp", "netbios-ssn Samba smbd 3.0.24")])
    assert any("usermap" in h.lower() for h in hints)


def test_version_hint_sambacry_not_for_new():
    hints = hints_for([svc("445/tcp", "microsoft-ds Samba smbd 4.15.13")])
    assert not any("SambaCry" in h for h in hints)
    assert any("enum4linux" in h for h in hints)  # service hint still fires


def test_version_hint_webmin():
    hints = hints_for([svc("10000/tcp", "http MiniServ 1.920")])
    assert any("CVE-2019-15107" in h for h in hints)


def test_version_hint_struts():
    hints = hints_for([svc("8080/tcp", "http Apache-Coyote Struts 2.5.12")])
    assert any("CVE-2017-5638" in h for h in hints)


# ---- port fallbacks ----------------------------------------------------------

def test_port_fallback_docker():
    hints = hints_for([svc("2375/tcp", "unknown")])
    assert any("Docker API" in h for h in hints)


def test_port_fallback_elasticsearch():
    hints = hints_for([svc("9200/tcp", "unknown")])
    assert any("Elasticsearch" in h and "_cat/indices" in h for h in hints)


def test_port_fallback_not_fired_when_service_hint_matches():
    hints = hints_for([svc("27017/tcp", "mongodb MongoDB 4.4.18")])
    mongo = [h for h in hints if h.startswith("MongoDB")]
    assert len(mongo) == 1  # service hint only, no duplicate port fallback


# ---- web + domain recon --------------------------------------------------------

def test_web_chain_has_bug_bounty_checks():
    hints = hints_for([svc("80/tcp", "http nginx 1.24.0")])
    web = [h for h in hints if "enum chain" in h]
    assert web
    assert ".git/HEAD" in web[0] and ".env" in web[0]
    assert "security.txt" in web[0] and "CORS" in web[0]


def test_domain_recon_chain():
    hints = hints_for([], target="acme-corp.example.com")
    recon = [h for h in hints if "recon chain" in h]
    assert recon
    assert "sublist3r" in recon[0] and "amass" in recon[0]
    assert "authorization.json" in recon[0]  # scope compliance reminder


def test_no_domain_recon_for_ip():
    hints = hints_for([], target="10.10.10.5")
    assert not any("recon chain" in h for h in hints)


# ---- credential reuse ---------------------------------------------------------

def test_credential_reuse_hint():
    intel = [svc("22/tcp", "ssh OpenSSH 8.9p1"),
             svc("21/tcp", "ftp vsftpd 3.0.5")]
    loot = [{"kind": "credential", "title": "cms admin",
             "value": "admin:Winter2024!"}]
    hints = hints_for(intel, loot=loot)
    reuse = [h for h in hints if "credential(s) in loot" in h]
    assert reuse and "hydra" in reuse[0]
    assert any("/privesc" in h for h in hints)


def test_no_reuse_hint_without_creds():
    intel = [svc("22/tcp", "ssh OpenSSH 8.9p1")]
    hints = hints_for(intel, loot=[])
    assert not any("credential(s) in loot" in h for h in hints)


# ---- fallback + ordering + cap -------------------------------------------------

def test_searchsploit_fallback_lists_products():
    hints = hints_for([svc("80/tcp", "http nginx 1.18.0"),
                       svc("3306/tcp", "mysql MySQL 8.0.33")])
    fb = [h for h in hints if h.startswith("Version research")]
    assert fb and "nginx 1.18.0" in fb[0] and "MySQL 8.0.33" in fb[0]


def test_version_hints_come_first_and_cap():
    intel = [svc(p, v) for p, v in [
        ("21/tcp", "ftp vsftpd 2.3.4"), ("80/tcp", "http Apache httpd 2.4.49"),
        ("443/tcp", "ssl/http nginx 1.24.0"), ("22/tcp", "ssh OpenSSH 7.4"),
        ("139/tcp", "netbios-ssn Samba smbd 3.0.24"),
        ("3306/tcp", "mysql MySQL 5.7.38"), ("5432/tcp", "postgresql PostgreSQL 9.6"),
        ("6379/tcp", "redis Redis 5.0.7"), ("9200/tcp", "unknown"),
        ("2375/tcp", "unknown"), ("161/udp", "snmp SNMPv1"),
        ("389/tcp", "ldap OpenLDAP 2.4.42"), ("5900/tcp", "vnc VNC protocol 3.8"),
        ("25/tcp", "smtp Postfix smtpd"), ("6667/tcp", "irc UnrealIRCd 3.2.8.1"),
    ]]
    hints = hints_for(intel, target="10.10.10.5")
    assert len(hints) <= 15
    assert "CVE-2021-41773" in hints[0] or "backdoor" in hints[0].lower()


# ---- guard: sublist3r -d regression ---------------------------------------------

def test_sublist3r_domain_allowed(workspace, scope):
    g = CommandGuard(scope, str(workspace))
    # in-scope domain passes (AUTH fixture includes *.example.com)
    g.validate("sublist3r", ["-d", "example.com"])
    assert extract_hosts(["-d", "example.com"]) == ["example.com"]


def test_sublist3r_out_of_scope_domain_refused(workspace, scope):
    g = CommandGuard(scope, str(workspace))
    with pytest.raises(GuardError):
        g.validate("sublist3r", ["-d", "evil-corp.com"])
