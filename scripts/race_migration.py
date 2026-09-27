"""Regression harness: cross-policy migration after pending-share loss (v1.5).

Run (needs a reachable PostgreSQL; the docker compose ``demo`` profile wires
it automatically):

    KEYVAULT_DATABASE_URL=postgresql://keyvault:keyvault@localhost:5432/keyvault \
    KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_migration

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and reproduces the deadlock that previously stranded
cross-policy migrations once the in-memory pending shares were lost:

  * custodian A's share is committed (db count 1 of 2);
  * the API process restarts (whole ``PendingShareStore`` replaced) or the
    pool evicts the session (``clear``) — the verified share bytes are gone;
  * custodian B's submit brings the db count to the source threshold, but
    reconstruction cannot find enough in-memory shares.

Old behavior: ``THRESHOLD_NOT_MET`` rolled back only B's submission. A's
committed row, the spent nonce and ``UNIQUE(migration_id, custodian_id)``
kept A from ever resubmitting, while the still-``open`` session held both
partial unique indexes — a fresh idempotency key only got
``MIGRATION_CONFLICT`` until the TTL expired. The migration was dead.

Fixed behavior asserted here:

  M1  restart: the threshold-reaching submit fails the session atomically —
      B's share is retracted (memory token + submission row + nonce spend)
      while the row lock is still held, the session is **committed** to the
      queryable terminal state ``failed`` (``migration.failed`` audit), the
      open placeholder is released, and every later request on the old
      session is rejected with ``MIGRATION_FAILED``.
  M2  a submit queued on the session row lock while the failure is being
      committed can never complete the migration afterwards.
  M3  a fresh idempotency key re-initiates from the source record and
      completes exactly once — no duplicate new custody; the failed session
      keeps ``new_custody_id`` NULL; a third key is ``MIGRATION_CONFLICT``.
  M4  same-key replay returns the failed session (200, idempotent); the same
      key with a different body is ``IDEMPOTENCY_CONFLICT``.
  M5  pool-eviction variant (``clear`` instead of restart): identical
      terminal semantics, and a fresh key re-initiates immediately.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys

# The gates must be armed before app construction reads settings.
os.environ.setdefault("KEYVAULT_FAULT_INJECTION", "1")

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.db import Database, wait_for_database
from app.main import app
from app.pending import PendingShareStore
from app.seed import seed, demo_credentials

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail and not ok else ""))


def body_of(r) -> dict:
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {}


def sign(priv_hex: str, message: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        message.encode()
    ).hex()


@contextlib.asynccontextmanager
async def server():
    settings = get_settings()
    await wait_for_database(settings.database_url)
    await seed()
    database = Database(settings.database_url)
    await database.connect()
    app.state.db = database
    app.state.pending = PendingShareStore()
    app.state.fault_enabled = True
    from app.faults import FaultBoard
    board = FaultBoard()
    app.state.fault_board = board
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        try:
            yield http, database.pool, board
        finally:
            await database.close()


def restart_api_process() -> None:
    """Simulate an API process restart: the whole in-memory pending-share
    store is lost; the database (committed submissions, spent nonces, the
    open session and its unique placeholders) survives untouched."""
    app.state.pending = PendingShareStore()


async def wait_lock_waiters(pool, expect: int, timeout: float = 10.0) -> int:
    """Wait until ``expect`` backends hold an ungranted row lock on a migration."""
    sql = """
        SELECT count(*)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'transactionid'
          AND NOT l.granted
          AND a.query LIKE '%migration_sessions%FOR UPDATE%'
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        seen = await pool.fetchval(sql)
        if seen >= expect:
            return seen
        await asyncio.sleep(0.05)
    return seen


class Harness:
    def __init__(self, http, pool, creds):
        self.http = http
        self.pool = pool
        self.tenant_key = creds["tenant"]["api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.suffix = os.urandom(4).hex()
        self.secret = b"migration-restart-regression-secret-0123456789"

    def t(self) -> dict:
        return {"X-API-Key": self.tenant_key}

    def h(self, name: str) -> dict:
        return {"X-API-Key": self.cust[name]["api_key"]}

    async def setup(self) -> tuple[str, dict]:
        """Fresh source policy (2-of-3) + target policy + source custody."""
        src = f"pol_msrc_{self.suffix}_{os.urandom(3).hex()}"
        tgt = f"pol_mtgt_{self.suffix}_{os.urandom(3).hex()}"
        epoch = {"valid_from": "2026-01-01T00:00:00Z",
                 "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}
        for pid in (src, tgt):
            r = await self.http.post("/policies", headers=self.t(), json={
                "policy_id": pid, "threshold": 2,
                "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                "epoch": epoch,
            })
            assert r.status_code == 201, r.text
        r = await self.http.post("/custodies", headers=self.t(), json={
            "policy_id": src, "expected_version": 1, "secret_hex": self.secret.hex(),
        })
        assert r.status_code == 201, r.text
        custody_id = r.json()["custody_id"]
        body = {"source_custody_id": custody_id,
                "target_policy_id": tgt, "target_version": 1}
        return custody_id, body

    async def start(self, body: dict, idem_key: str):
        return await self.http.post(
            "/migrations", headers={**self.t(), "Idempotency-Key": idem_key}, json=body
        )

    async def prep(self, name: str, mid: str) -> dict:
        h = self.h(name)
        r = await self.http.post("/migrations/nonces", headers=h, json={"migration_id": mid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/migrations/shards/claim", headers=h,
                                 json={"migration_id": mid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {
            "headers": h,
            "json": {"migration_id": mid, "nonce": nonce, "point_x": c["point_x"],
                     "shard_hex": c["shard_hex"],
                     "signature": sign(self.cust[name]["signing_private_key"],
                                       c["signing_message"])},
        }

    async def submit(self, prepped: dict, extra_headers: dict | None = None):
        headers = {**prepped["headers"], **(extra_headers or {})}
        return await self.http.post("/migrations/shares", headers=headers,
                                    json=prepped["json"])

    async def session_row(self, mid: str) -> dict:
        return dict(await self.pool.fetchrow(
            "SELECT (SELECT count(*) FROM migration_share_submissions"
            "            WHERE migration_id=$1) AS subs,"
            "       (SELECT status FROM migration_sessions WHERE id=$1) AS st,"
            "       (SELECT new_custody_id FROM migration_sessions WHERE id=$1) AS nc",
            mid,
        ))


async def scenario_m1(hs: Harness) -> tuple[str, dict, str, str]:
    """Restart loses the pending shares -> threshold submit commits the
    session to the queryable terminal state 'failed' and releases the open
    placeholder; the triggering submit is retracted as if never made."""
    label = "M1(restart->failed-terminal)"
    custody_id, body = await hs.setup()
    k1 = f"mig-m1-{hs.suffix}"
    r = await hs.start(body, k1)
    assert r.status_code == 201, r.text
    mid = body_of(r)["migration_id"]

    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    check(f"{label}: alice share committed (1/2)",
          r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)

    # API 进程重启：整个待累计分片池丢失；数据库计数/已花费 nonce 保留。
    restart_api_process()

    pb = await hs.prep("bob", mid)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: threshold submit after restart -> THRESHOLD_NOT_MET",
          r.status_code == 409
          and b.get("error", {}).get("code") == "THRESHOLD_NOT_MET"
          and b.get("error", {}).get("basis", {}).get("reason") == "pending_shares_unavailable",
          f"HTTP {r.status_code}: {r.text[:200]}")

    # 会话被提交为可查询的 failed 终态（不再停在 open 占住唯一索引）。
    g = body_of(await hs.http.get(f"/migrations/{mid}", headers=hs.t()))
    check(f"{label}: session committed to queryable 'failed' terminal state",
          g.get("status") == "failed" and g.get("shares_received") == 1
          and g.get("new_custody_id") is None, json.dumps(g))

    # 本次（触发门限的）提交被整体撤销：bob 的提交行不存在、nonce 恢复未
    # 花费；首名托管人的历史提交保留。
    row = dict(await hs.pool.fetchrow(
        "SELECT (SELECT count(*) FROM migration_share_submissions"
        "            WHERE migration_id=$1 AND custodian_id='cus_demo_bob') AS bob_subs,"
        "       (SELECT spent FROM migration_nonces"
        "            WHERE migration_id=$1 AND custodian_id='cus_demo_bob') AS bob_spent",
        mid,
    ))
    sess = await hs.session_row(mid)
    check(f"{label}: triggering submit retracted (row+nonce), history kept",
          row["bob_subs"] == 0 and row["bob_spent"] is False
          and sess["subs"] == 1 and sess["st"] == "failed" and sess["nc"] is None,
          f"{row} {sess}")

    # 旧会话上的一切后续请求（nonce/claim/submit）一律 MIGRATION_FAILED，
    # 绝不可能再完成迁移。
    r = await hs.http.post("/migrations/nonces", headers=hs.h("carol"),
                           json={"migration_id": mid})
    check(f"{label}: nonce on failed session -> MIGRATION_FAILED",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED", r.text)
    r = await hs.http.post("/migrations/shards/claim", headers=hs.h("bob"),
                           json={"migration_id": mid, "nonce": pb["json"]["nonce"]})
    check(f"{label}: claim on failed session -> MIGRATION_FAILED",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED", r.text)
    r = await hs.submit(pa)  # alice 的 nonce 已花费，但 failed 判定先于 nonce 判定
    check(f"{label}: resubmit on failed session -> MIGRATION_FAILED",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "MIGRATION_FAILED", r.text)

    # 无明文审计：migration.failed 入链、哈希链保持有效、不含任何分片明文。
    chain = body_of(await hs.http.get("/audit/replay", headers=hs.t()))
    actions = [e["action"] for e in chain.get("entries", [])]
    check(f"{label}: migration.failed audited, hash chain valid",
          chain.get("valid") is True and "migration.failed" in actions,
          str(actions[-6:]))
    raw = json.dumps(chain)
    check(f"{label}: audit leaks no shard plaintext",
          pa["json"]["shard_hex"] not in raw and pb["json"]["shard_hex"] not in raw)
    return custody_id, body, k1, mid


async def scenario_m2(hs: Harness, board) -> None:
    """A submit queued on the session row lock while the failure is being
    committed must never complete the migration once it acquires the lock."""
    label = "M2(lock-waiter-cannot-complete)"
    custody_id, body = await hs.setup()
    r = await hs.start(body, f"mig-m2-{hs.suffix}")
    assert r.status_code == 201, r.text
    mid = body_of(r)["migration_id"]

    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text

    # 重启：alice 的已计数分片在内存丢失。
    restart_api_process()

    pb = await hs.prep("bob", mid)
    pc = await hs.prep("carol", mid)

    # bob 的提交在分片入池后、行锁仍持有时 park；carol 的提交随后排队等锁。
    bob_task = asyncio.create_task(hs.submit(pb, {
        "X-Fault-Key": label, "X-Fault-Gate": "migration.after_add"}))
    await board.wait_reached(f"migration.after_add:{label}")
    carol_task = asyncio.create_task(hs.submit(pc))
    queued = await wait_lock_waiters(hs.pool, 1)
    check(f"{label}: waiter queued on session row lock while failure unwinds",
          queued == 1, f"waiters={queued}")

    # 放行 bob：重组缺片 -> 协调提交 failed 终态 -> 释放行锁；
    # carol 拿锁时只能看到 failed，绝不可能再完成迁移。
    await board.release_gate(f"migration.after_add:{label}")
    rb = await bob_task
    rc = await carol_task
    check(f"{label}: triggering submit -> THRESHOLD_NOT_MET",
          rb.status_code == 409
          and body_of(rb).get("error", {}).get("basis", {}).get("reason")
          == "pending_shares_unavailable",
          f"HTTP {rb.status_code}: {rb.text[:200]}")
    check(f"{label}: queued request can never complete the migration",
          rc.status_code == 409
          and body_of(rc).get("error", {}).get("code") == "MIGRATION_FAILED",
          f"HTTP {rc.status_code}: {rc.text[:200]}")
    sess = await hs.session_row(mid)
    check(f"{label}: no waiter row written; session failed without new custody",
          sess["subs"] == 1 and sess["st"] == "failed" and sess["nc"] is None,
          str(sess))


async def scenario_m3_m4(hs: Harness, custody_id: str, body: dict,
                         k1: str, mid1: str) -> None:
    """Same-key replay of a failed session; fresh-key re-initiation that
    completes exactly once without a duplicate new custody."""
    label4 = "M4(same-key-replay)"
    label3 = "M3(fresh-key-reinitiates)"

    # 同键同请求重放：幂等返回 failed 会话（200，不新建）。
    r = await hs.start(body, k1)
    b = body_of(r)
    check(f"{label4}: same-key replay returns failed session (200, same id)",
          r.status_code == 200 and b.get("migration_id") == mid1
          and b.get("status") == "failed", f"HTTP {r.status_code}: {r.text[:200]}")
    # 同键不同请求体 -> IDEMPOTENCY_CONFLICT。
    r = await hs.start({**body, "target_version": 2}, k1)
    check(f"{label4}: same key different body -> IDEMPOTENCY_CONFLICT",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT",
          r.text)

    # 新幂等键：立即从源记录重新发起（源记录全程 active，无需等 TTL）。
    r = await hs.start(body, f"mig-m3-{hs.suffix}")
    m2 = body_of(r)
    check(f"{label3}: fresh idempotency key re-initiates from source record",
          r.status_code == 201 and m2.get("status") == "open"
          and m2.get("migration_id") != mid1, r.text)
    mid2 = m2["migration_id"]

    # 原托管人在新会话重新走 nonce -> claim -> sign -> submit，迁移完成。
    pa2 = await hs.prep("alice", mid2)
    pb2 = await hs.prep("bob", mid2)
    r = await hs.submit(pa2)
    check(f"{label3}: first custodian re-submits in the new session",
          r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)
    r = await hs.submit(pb2)
    mc = body_of(r)
    check(f"{label3}: retried migration completes with a new custody",
          r.status_code == 200 and mc.get("completed") and mc.get("new_custody_id"),
          r.text)
    new_cid = mc.get("new_custody_id")

    # 不产生重复的新托管记录：该源 custody 全局恰有一个 completed 迁移；
    # failed 会话的 new_custody_id 恒为 NULL。
    row = dict(await hs.pool.fetchrow(
        "SELECT (SELECT count(*) FROM migration_sessions"
        "            WHERE source_custody_id=$1 AND new_custody_id IS NOT NULL) AS done,"
        "       (SELECT count(*) FROM migration_sessions"
        "            WHERE source_custody_id=$1 AND status='failed') AS failed,"
        "       (SELECT count(*) FROM key_custodies k JOIN migration_sessions m"
        "            ON m.new_custody_id = k.id"
        "            WHERE m.source_custody_id=$1) AS new_custodies",
        custody_id,
    ))
    check(f"{label3}: exactly one completed migration / one new custody",
          row["done"] == 1 and row["failed"] == 1 and row["new_custodies"] == 1,
          str(row))
    dg = dict(await hs.pool.fetchrow(
        "SELECT (SELECT secret_digest FROM key_custodies WHERE id=$1) AS src,"
        "       (SELECT secret_digest FROM key_custodies WHERE id=$2) AS dst,"
        "       (SELECT status FROM key_custodies WHERE id=$1) AS src_status",
        custody_id, new_cid,
    ))
    check(f"{label3}: new custody carries same secret digest; source stays active",
          dg["src"] == dg["dst"] and dg["src_status"] == "active", str(dg))

    # 第三个幂等键：已迁移完成 -> MIGRATION_CONFLICT（不得重复迁移）。
    r = await hs.start(body, f"mig-m3b-{hs.suffix}")
    check(f"{label3}: third key after completion -> MIGRATION_CONFLICT",
          r.status_code == 409
          and body_of(r).get("error", {}).get("code") == "MIGRATION_CONFLICT"
          and body_of(r).get("error", {}).get("basis", {}).get("reason")
          == "custody_already_migrated", r.text)


async def scenario_m5(hs: Harness) -> None:
    """Pool eviction (``clear``) instead of a restart: identical terminal
    semantics; a fresh key re-initiates immediately."""
    label = "M5(pool-eviction->failed)"
    custody_id, body = await hs.setup()
    r = await hs.start(body, f"mig-m5-{hs.suffix}")
    assert r.status_code == 201, r.text
    mid = body_of(r)["migration_id"]

    pa = await hs.prep("alice", mid)
    r = await hs.submit(pa)
    assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text

    # 内存池淘汰该会话（sweep/evict）：等价于该会话待累计分片丢失。
    app.state.pending.clear(mid)

    pb = await hs.prep("bob", mid)
    r = await hs.submit(pb)
    b = body_of(r)
    check(f"{label}: threshold submit after eviction -> THRESHOLD_NOT_MET",
          r.status_code == 409
          and b.get("error", {}).get("basis", {}).get("reason")
          == "pending_shares_unavailable",
          f"HTTP {r.status_code}: {r.text[:200]}")
    g = body_of(await hs.http.get(f"/migrations/{mid}", headers=hs.t()))
    check(f"{label}: session failed and queryable after eviction",
          g.get("status") == "failed" and g.get("shares_received") == 1,
          json.dumps(g))
    # open 占位已释放：新幂等键可立即重建（不必等 TTL）。
    r = await hs.start(body, f"mig-m5b-{hs.suffix}")
    check(f"{label}: fresh key re-initiates immediately (no TTL wait)",
          r.status_code == 201 and body_of(r).get("status") == "open", r.text)


async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        custody_id, body, k1, mid1 = await scenario_m1(hs)
        await scenario_m2(hs, board)
        await scenario_m3_m4(hs, custody_id, body, k1, mid1)
        await scenario_m5(hs)
        # 全部场景结束后审计哈希链仍然完整。
        chain = body_of(await http.get("/audit/replay", headers=hs.t()))
        check("final: audit hash chain valid across all scenarios",
              chain.get("valid") is True, json.dumps(chain)[:200])

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} migration-restart checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("MIGRATION RESTART REGRESSION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
