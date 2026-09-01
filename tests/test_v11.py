"""v1.1 tests: intel profiles + knowledge base in the pentest report."""

import json

from aegis.db import EngagementDB
from aegis.playbook import add_custom_rule, learn_from_success
from aegis.report import ReportGenerator


def _db(workspace):
    return EngagementDB(str(workspace / "eng.db"))


def test_report_includes_infrastructure_profile(workspace):
    db = _db(workspace)
    tid = db.add_target("10.10.10.5", "THM box")
    db.record_intel(tid, "service", "22/tcp", "ssh OpenSSH 8.9p1 Ubuntu")
    db.record_intel(tid, "service", "80/tcp", "http Apache httpd 2.4.49")
    db.record_intel(tid, "web", "server", "Apache/2.4.49 (Unix)")
    db.record_intel(tid, "web", "x-powered-by", "PHP/7.4.21")
    db.record_intel(tid, "os", "os", "Linux 4.15 - 5.6")
    db.record_intel(tid, "tech", "wordpress", "WordPress 5.8")

    md_path = ReportGenerator(db, "test-eng", workspace / "reports",
                              workspace=workspace).build_markdown()
    text = md_path.read_text(encoding="utf-8")
    assert "**Infrastructure:**" in text
    assert "| `22/tcp` | ssh OpenSSH 8.9p1 Ubuntu |" in text
    assert "Apache httpd 2.4.49" in text
    assert "x-powered-by: `PHP/7.4.21`" in text
    assert "**OS:** `Linux 4.15 - 5.6`" in text
    assert "`WordPress 5.8`" in text


def test_report_flags_in_loot_summary(workspace):
    db = _db(workspace)
    tid = db.add_target("10.10.10.5")
    db.record_loot(tid, "flag", "user flag", value="THM{r3p0rt_m3}")
    text = ReportGenerator(db, "t", workspace / "reports",
                           workspace=workspace).build_markdown() \
        .read_text(encoding="utf-8")
    assert "Flags captured: **1**" in text
    assert "THM{r3p0rt_m3}" in text  # flags shown in full


def test_report_kb_section(workspace):
    db = _db(workspace)
    db.add_target("10.10.10.5")
    add_custom_rule(workspace, "service_hints", "zimbra",
                    "Zimbra → check /service/soap on TARGET")
    tid = 1
    db.record_intel(tid, "service", "10000/tcp", "http MiniServ 1.990")
    learn_from_success(db, tid, "rce", "tcp/10000", "curl",
                       "curl http://10.10.10.5:10000/x", "10.10.10.5",
                       workspace=workspace)
    text = ReportGenerator(db, "t", workspace / "reports",
                           workspace=workspace).build_markdown() \
        .read_text(encoding="utf-8")
    assert "## Engagement Knowledge Base" in text
    assert "**live** (service) `zimbra`" in text
    assert "**pending review** (version_hints) `miniserv.*1" in text.replace("\\", "")


def test_report_without_intel_or_kb_still_works(workspace):
    db = _db(workspace)
    db.add_target("10.10.10.5")
    text = ReportGenerator(db, "t", workspace / "reports",
                           workspace=workspace).build_markdown() \
        .read_text(encoding="utf-8")
    assert "Engagement Knowledge Base" not in text
    assert "## Targets Detail" in text


def test_html_renders_tables(workspace):
    db = _db(workspace)
    tid = db.add_target("10.10.10.5")
    db.record_intel(tid, "service", "80/tcp", "http Apache httpd 2.4.49")
    gen = ReportGenerator(db, "t", workspace / "reports", workspace=workspace)
    md = gen.build_markdown()
    html_path = gen.build_html(md)
    page = html_path.read_text(encoding="utf-8")
    assert "<table>" in page
    assert "<td>`80/tcp`</td>" in page or "80/tcp" in page
    assert "Apache httpd 2.4.49" in page
