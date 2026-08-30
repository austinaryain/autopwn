from aegis.audit import AuditLog


def test_chain_integrity(tmp_path):
    log = AuditLog(tmp_path / "logs")
    for i in range(10):
        log.log("tester", "test", f"a{i}", {"i": i})
    ok, msg = AuditLog.verify(log.path)
    assert ok, msg


def test_tamper_detected(tmp_path):
    log = AuditLog(tmp_path / "logs")
    for i in range(5):
        log.log("tester", "test", f"a{i}", {"i": i})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert '"i": 2' in lines[2]
    lines[2] = lines[2].replace('"i": 2', '"i": 99')
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("\n".join(lines), encoding="utf-8")
    ok, _ = AuditLog.verify(tampered)
    assert not ok


def test_deletion_detected(tmp_path):
    log = AuditLog(tmp_path / "logs")
    for i in range(5):
        log.log("tester", "test", f"a{i}", {"i": i})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    del lines[2]  # remove an entry — chain must break
    tampered = tmp_path / "deleted.jsonl"
    tampered.write_text("\n".join(lines), encoding="utf-8")
    ok, _ = AuditLog.verify(tampered)
    assert not ok
