from aegis.parsers import evaluate

NMAP_OUT = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.5
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache httpd 2.4.49
Service detection performed.
"""

HYDRA_OUT = """
Hydra v9.5 starting
[22][ssh] host: 10.10.10.5   login: admin   password: S3cur3!
1 of 1 target successfully completed, 1 valid password found
"""

NIKTO_OUT = """
+ Target IP: 10.10.10.5
+ Server: Apache/2.4.49
+ /admin/: Admin login page found
+ OSVDB-3092: /backup.zip: Potentially interesting file
"""


def test_nmap_success():
    v = evaluate("nmap", NMAP_OUT)
    assert v is not None and v.success
    assert "22/tcp ssh" in v.summary


def test_nmap_host_down():
    v = evaluate("nmap", "Nmap done: 0 hosts up")
    assert v is not None and not v.success


def test_hydra_credentials_to_loot():
    v = evaluate("hydra", HYDRA_OUT)
    assert v is not None and v.success
    assert v.loot and v.loot[0]["value"] == "admin:S3cur3!"
    assert v.loot[0]["kind"] == "credential"


def test_hydra_failure():
    v = evaluate("hydra", "0 valid passwords found")
    assert v is not None and not v.success


def test_nikto_findings():
    v = evaluate("nikto", NIKTO_OUT)
    assert v is not None and v.success
    assert any("OSVDB" in f["title"] for f in v.findings)


def test_unknown_tool_inconclusive():
    assert evaluate("someunknown", "output") is None
