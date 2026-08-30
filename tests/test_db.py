import threading

from aegis.crypto import LootCipher
from aegis.db import EngagementDB


def test_loot_encrypted_at_rest(workspace):
    db = EngagementDB("eng.db")
    db.cipher = LootCipher(".")
    assert db.cipher.active
    tid = db.add_target("10.10.10.5")
    db.record_loot(tid, "credential", "ssh admin", "admin:S3cur3!")
    # raw DB value must NOT be plaintext
    raw = db.conn.execute("SELECT value FROM loot").fetchone()["value"]
    assert "S3cur3" not in raw
    assert raw.startswith("enc:v1:")
    # API view must decrypt transparently
    assert db.loot_for(tid)[0]["value"] == "admin:S3cur3!"


def test_memory_summary_includes_loot(workspace):
    db = EngagementDB("eng.db")
    db.cipher = LootCipher(".")
    tid = db.add_target("10.10.10.5")
    db.record_loot(tid, "credential", "ssh admin", "admin:S3cur3!")
    assert "ssh admin" in db.memory_summary(tid)


def test_concurrent_writes(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    errors = []

    def hammer(tag):
        try:
            for i in range(30):
                db.record_attempt(tid, f"t{tag}", "v", f"p{i}", "r", i % 2 == 0)
        except Exception as exc:  # pragma: no cover
            errors.append(str(exc))

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(db.attempts_for(tid)) == 120


def test_migrations_idempotent(workspace):
    db1 = EngagementDB("eng.db")
    db1.close()
    db2 = EngagementDB("eng.db")  # reopen — migrations must not fail
    cols = {r["name"] for r in db2.conn.execute(
        "PRAGMA table_info(findings)").fetchall()}
    assert {"cvss", "remediation", "attack_id"} <= cols
