"""Cross-policy key migration sessions.

Flow (mirrors the recovery protocol, minus the one-time wrap):

1. Tenant creates a migration session for a still-valid custody record, naming
   another valid policy version, supplying an **idempotency key** header. The
   session binds both the source and the target policy-version **digests**.
2. Source-policy custodians obtain a one-time nonce, claim their own source
   shard (plaintext appears only in that response), sign the migration
   canonical message and submit shard + signature.
3. When the source threshold is reached the server reconstructs the secret
   **in request memory only** from verified submitted shards, immediately
   re-shards under the target policy, and writes the new custody + encrypted
   shard rows in the **same transaction**; the source record is never touched.

Plaintext (secret / submitted shard / nonce) never appears in responses beyond
the existing claim channel, never in the database (only digests) and never in
audit rows. Revoked/expired versions, cross-tenant references, concurrent and
repeated migrations are rejected; distinct idempotency keys can never migrate
the same custody twice; deterministic failures are safe retries.
"""
from __future__ import annotations

from fastapi import APIRouter, Header, Request, Response

from .. import audit, crypto, deps, faults, repo
from ..config import get_settings
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_BAD_SIGNATURE,
    E_CROSS_POLICY_SHARE,
    E_DUPLICATE_SHARE,
    E_EPOCH_EXPIRED,
    E_EPOCH_REVOKED,
    E_FORBIDDEN,
    E_IDEMPOTENCY_CONFLICT,
    E_INTEGRITY,
    E_MIGRATION_COMPLETED,
    E_MIGRATION_CONFLICT,
    E_MIGRATION_DIGEST_MISMATCH,
    E_MIGRATION_SOURCE_INVALID,
    E_MIGRATION_TARGET_INVALID,
    E_NONCE_USED,
    E_NOT_FOUND,
    E_SESSION_EXPIRED,
    E_SHARE_DIGEST,
    E_SHARE_POINT,
    E_THRESHOLD_NOT_MET,
)
from ..schemas import (
    MigrationNonceOut,
    MigrationNonceRequestIn,
    MigrationSessionOut,
    MigrationShardClaimIn,
    MigrationShardClaimOut,
    MigrationShareSubmitIn,
    MigrationShareSubmitOut,
    MigrationStartIn,
)

router = APIRouter(tags=["migrations"])


def _digest_of_policy(p) -> str:
    """Digest of an immutable policy version row (timestamps canonicalized)."""
    return crypto.policy_version_digest(
        policy_id=p["id"],
        version=p["version"],
        tenant_id=p["tenant_id"],
        threshold=p["threshold"],
        custodian_ids=list(p["custodian_ids"]),
        epoch_index=p["epoch_index"],
        epoch_valid_from=audit.canon_ts(p["epoch_valid_from"]),
        epoch_valid_until=audit.canon_ts(p["epoch_valid_until"]),
        rotation_interval=p["rotation_interval"],
    )


def _session_out(mig, shares_received: int, source_threshold: int,
                 new_shard_count: int | None = None,
                 new_shard_digests: list[str] | None = None) -> MigrationSessionOut:
    return MigrationSessionOut(
        migration_id=mig["id"],
        source_custody_id=mig["source_custody_id"],
        source_policy_id=mig["source_policy_id"],
        source_version=mig["source_version"],
        source_digest=mig["source_digest"],
        target_policy_id=mig["target_policy_id"],
        target_version=mig["target_version"],
        target_digest=mig["target_digest"],
        status=mig["status"],
        valid_until=mig["valid_until"],
        shares_received=shares_received,
        threshold=source_threshold,
        new_custody_id=mig["new_custody_id"],
        new_shard_count=new_shard_count,
        new_shard_digests=new_shard_digests,
    )


async def _source_shard(conn, custody_id: str, custodian_id: str):
    return await conn.fetchrow(
        "SELECT id, point_x, ciphertext, shard_digest FROM shards "
        "WHERE custody_id=$1 AND custodian_id=$2",
        custody_id, custodian_id,
    )


async def _resolve_nonce(conn, migration_id: str, nonce_hex: str, custodian_id: str):
    try:
        nonce_hash = crypto.sha256_hex(bytes.fromhex(nonce_hex))
    except ValueError:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_malformed"})
    nonce_row = await conn.fetchrow(
        "SELECT * FROM migration_nonces WHERE nonce_hash=$1 FOR UPDATE", nonce_hash
    )
    if nonce_row is None:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_unknown"})
    if nonce_row["migration_id"] != migration_id or nonce_row["custodian_id"] != custodian_id:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"reason": "nonce_binding_mismatch", "migration_id": migration_id,
                   "custodian_id": custodian_id},
        )
    return nonce_row


def _check_digests(mig, source_policy, target_policy) -> None:
    """Re-verify the bound source/target version digests against immutable rows."""
    source_digest = _digest_of_policy(source_policy)
    if not crypto.constant_time_hex_equal(source_digest, mig["source_digest"]):
        raise ApiError(
            E_MIGRATION_DIGEST_MISMATCH,
            basis={"which": "source", "policy_id": mig["source_policy_id"],
                   "version": mig["source_version"], "bound_digest": mig["source_digest"],
                   "actual_digest": source_digest},
        )
    target_digest = _digest_of_policy(target_policy)
    if not crypto.constant_time_hex_equal(target_digest, mig["target_digest"]):
        raise ApiError(
            E_MIGRATION_DIGEST_MISMATCH,
            basis={"which": "target", "policy_id": mig["target_policy_id"],
                   "version": mig["target_version"], "bound_digest": mig["target_digest"],
                   "actual_digest": target_digest},
        )


async def _guard_migration(conn, mig, source_policy, target_policy, now,
                           custodian_id: str | None) -> None:
    """Gates shared by nonce issue / shard claim / share submit."""
    if mig["status"] == "completed":
        raise ApiError(E_MIGRATION_COMPLETED, basis={"migration_id": mig["id"]})
    if mig["status"] == "expired" or now >= mig["valid_until"]:
        raise ApiError(E_SESSION_EXPIRED,
                       basis={"valid_until": str(mig["valid_until"]), "now": str(now)})
    _check_digests(mig, source_policy, target_policy)
    # 迁移进行中源策略版本被撤销/过期：在途份额一律拒绝。
    if source_policy["status"] == "revoked":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["source_policy_id"], "version": mig["source_version"],
                   "epoch": source_policy["epoch_index"]},
        )
    if now >= source_policy["epoch_valid_until"]:
        raise ApiError(E_EPOCH_EXPIRED, basis={"epoch": source_policy["epoch_index"]})
    # 目标版本同样必须在迁移完成前保持有效（已撤销则迁移不再有意义）。
    if target_policy["status"] == "revoked":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["target_policy_id"], "version": mig["target_version"],
                   "epoch": target_policy["epoch_index"], "which": "target"},
        )
    if now >= target_policy["epoch_valid_until"]:
        raise ApiError(
            E_EPOCH_EXPIRED,
            basis={"epoch": target_policy["epoch_index"], "which": "target"},
        )
    if custodian_id is not None and custodian_id not in source_policy["custodian_ids"]:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"custodian_id": custodian_id, "policy_id": mig["source_policy_id"],
                   "policy_version": mig["source_version"],
                   "reason": "not_member_of_source_policy_version"},
        )


# ---------------------------------------------------------------------------
# Tenant endpoints
# ---------------------------------------------------------------------------

@router.post("/migrations", response_model=MigrationSessionOut, status_code=201)
async def start_migration(
    body: MigrationStartIn,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant=deps.Tenant,
):
    settings = get_settings()
    if not idempotency_key or not 1 <= len(idempotency_key) <= 200:
        raise ApiError(E_BAD_REQUEST,
                       basis={"reason": "missing_or_malformed_idempotency_key",
                              "header": "Idempotency-Key", "max_length": 200})
    idem_hash = crypto.sha256_hex(idempotency_key.encode())
    pool = request.app.state.db.pool
    ttl = body.ttl_seconds or settings.recovery_default_ttl
    ttl = min(ttl, settings.recovery_max_ttl)

    mig_row = None
    source_threshold = 0
    out_count = 0
    out_new_digests: list[str] | None = None
    replayed = False

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # 源托管记录行锁：同一 custody 的并发创建/迁移完全串行，
                # 消除“并发重复迁移”竞态（部分唯一索引再兜底）。
                custody = await conn.fetchrow(
                    "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", body.source_custody_id
                )
                if custody is None:
                    raise ApiError(E_NOT_FOUND, basis={"custody_id": body.source_custody_id})
                if custody["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN,
                                   basis={"reason": "custody_belongs_to_other_tenant"})
                # 惰性过期：超过 TTL、或源侧已失效（custody 被轮换/撤销、源策略
                # 版本被撤销/过期）的 open 会话在同源新事务（本事务随后提交）中
                # 置 expired，释放两条部分唯一索引——失败后可用同键或新键安全重试，
                # 且不会被一个“永远无法再完成”的 open 会话无限占位。
                await conn.execute(
                    """
                    UPDATE migration_sessions m SET status='expired'
                    FROM key_custodies kc
                    JOIN policies p ON p.id = kc.policy_id AND p.version = kc.policy_version
                    WHERE m.source_custody_id = $1 AND m.status = 'open'
                      AND kc.id = m.source_custody_id
                      AND (now() >= m.valid_until
                           OR kc.status <> 'active'
                           OR p.status = 'revoked'
                           OR now() >= p.epoch_valid_until)
                    """,
                    custody["id"],
                )
                source_policy = await repo.get_policy_version(
                    conn, custody["policy_id"], custody["policy_version"]
                )
                now = await conn.fetchval("SELECT now()")

                # 幂等重放优先：同键的已有会话（open/completed）原样返回；
                # expired 行不占位（唯一索引不含 expired），允许安全重试。
                existing = await conn.fetchrow(
                    "SELECT * FROM migration_sessions "
                    "WHERE tenant_id=$1 AND idempotency_key_hash=$2 AND status <> 'expired' "
                    "ORDER BY created_at DESC LIMIT 1",
                    tenant["id"], idem_hash,
                )
                if existing is not None:
                    if (
                        existing["source_custody_id"] != body.source_custody_id
                        or existing["target_policy_id"] != body.target_policy_id
                        or existing["target_version"] != body.target_version
                    ):
                        raise ApiError(
                            E_IDEMPOTENCY_CONFLICT,
                            basis={"reason": "key_bound_to_different_request",
                                   "idempotency_key_digest": idem_hash},
                        )
                    count = await conn.fetchval(
                        "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1",
                        existing["id"],
                    )
                    new_digests = None
                    if existing["new_custody_id"] is not None:
                        rows = await conn.fetch(
                            "SELECT shard_digest FROM shards "
                            "WHERE custody_id=$1 ORDER BY point_x",
                            existing["new_custody_id"],
                        )
                        new_digests = [r["shard_digest"] for r in rows]
                    mig_row = existing
                    out_count = count
                    out_new_digests = new_digests
                    replayed = True
                else:
                    # 先做确定性参数校验（源/目标有效性、跨租户、目标=源）：
                    # 即使该 custody 已有 open 会话，非法请求仍返回其真正的拒绝依据。
                    # 源必须仍有效：托管记录 active 且其策略版本未撤销/未过期。
                    if custody["status"] != "active" or source_policy["status"] == "revoked":
                        raise ApiError(
                            E_MIGRATION_SOURCE_INVALID,
                            basis={"custody_id": custody["id"],
                                   "custody_status": custody["status"],
                                   "policy_id": custody["policy_id"],
                                   "version": custody["policy_version"],
                                   "policy_status": source_policy["status"]},
                        )
                    if now >= source_policy["epoch_valid_until"]:
                        raise ApiError(
                            E_MIGRATION_SOURCE_INVALID,
                            basis={"reason": "source_epoch_expired",
                                   "valid_until": str(source_policy["epoch_valid_until"])},
                        )

                    # 目标必须是另一条有效策略版本，且属于同一租户。
                    if (
                        body.target_policy_id == custody["policy_id"]
                        and body.target_version == custody["policy_version"]
                    ):
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_identical_to_source",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version},
                        )
                    target_policy = await repo.get_policy_version(
                        conn, body.target_policy_id, body.target_version
                    )
                    if target_policy is None:
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_version_not_found",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version},
                        )
                    if target_policy["tenant_id"] != tenant["id"]:
                        raise ApiError(
                            E_FORBIDDEN,
                            basis={"reason": "target_policy_belongs_to_other_tenant"},
                        )
                    if target_policy["status"] != "active":
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_policy_revoked",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version,
                                   "status": target_policy["status"]},
                        )
                    if now >= target_policy["epoch_valid_until"]:
                        raise ApiError(
                            E_MIGRATION_TARGET_INVALID,
                            basis={"reason": "target_epoch_expired",
                                   "policy_id": body.target_policy_id,
                                   "version": body.target_version},
                        )

                    # 参数全部合法后再判“重复”：同 custody 的其他 open 会话，或已迁移完成。
                    # 不同幂等键不得重复迁移。
                    blocker = await conn.fetchrow(
                        "SELECT id, status, new_custody_id FROM migration_sessions "
                        "WHERE source_custody_id=$1 AND "
                        "(status='open' OR new_custody_id IS NOT NULL) "
                        "ORDER BY created_at DESC LIMIT 1",
                        custody["id"],
                    )
                    if blocker is not None:
                        if blocker["new_custody_id"] is not None:
                            raise ApiError(
                                E_MIGRATION_CONFLICT,
                                basis={"reason": "custody_already_migrated",
                                       "migration_id": blocker["id"],
                                       "source_custody_id": custody["id"]},
                            )
                        raise ApiError(
                            E_MIGRATION_CONFLICT,
                            basis={"reason": "open_migration_exists_for_custody",
                                   "migration_id": blocker["id"],
                                   "source_custody_id": custody["id"]},
                        )

                    source_digest = _digest_of_policy(source_policy)
                    target_digest = _digest_of_policy(target_policy)
                    migration_id = deps.new_id("mig")
                    # savepoint：唯一索引兜底命中后外层事务仍可用于留痕/返回。
                    try:
                        async with conn.transaction():
                            await conn.execute(
                                """
                                INSERT INTO migration_sessions
                                  (id, tenant_id, source_custody_id, source_policy_id,
                                   source_version, source_digest, target_policy_id,
                                   target_version, target_digest, idempotency_key_hash,
                                   status, valid_until)
                                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',
                                        now() + ($11 || ' seconds')::interval)
                                """,
                                migration_id, tenant["id"], custody["id"],
                                custody["policy_id"], custody["policy_version"], source_digest,
                                body.target_policy_id, body.target_version, target_digest,
                                idem_hash, str(ttl),
                            )
                    except Exception as exc:  # 并发兜底：同键 open / 同源 open / 同源已完成
                        if getattr(exc, "pgcode", None) != "23505":
                            raise
                        await _raise_unique_conflict(conn, tenant["id"], idem_hash, custody["id"])
                    await audit.append_audit(
                        conn, tenant_id=tenant["id"], actor_type="tenant",
                        actor_id=tenant["id"],
                        action="migration.start", resource=migration_id, result="ok",
                        basis={
                            "source_custody_id": custody["id"],
                            "source_policy_id": custody["policy_id"],
                            "source_version": custody["policy_version"],
                            "source_digest": source_digest,
                            "target_policy_id": body.target_policy_id,
                            "target_version": body.target_version,
                            "target_digest": target_digest,
                            "ttl_seconds": ttl,
                            "idempotency_key_digest": idem_hash,
                        },
                    )
                    mig_row = await conn.fetchrow(
                        "SELECT * FROM migration_sessions WHERE id=$1", migration_id
                    )
                    out_count, out_new_digests = 0, None
                source_threshold = source_policy["threshold"]
        except ApiError as exc:
            # 拒绝同样留痕（独立事务），形成可重放审计；不含任何秘密材料。
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="migration.start", resource=body.source_custody_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise

    out = _session_out(mig_row, out_count, source_threshold,
                       new_shard_digests=out_new_digests)
    if replayed:
        # 幂等重放返回同一份结果（200，不新建、不重复留痕）。
        response.status_code = 200
    return out


async def _raise_unique_conflict(conn, tenant_id: str, idem_hash: str,
                                 source_custody_id: str) -> None:
    """Translate a partial-unique-index hit into the deterministic reason."""
    other_open = await conn.fetchrow(
        "SELECT id FROM migration_sessions "
        "WHERE tenant_id=$1 AND idempotency_key_hash=$2 AND status='open' LIMIT 1",
        tenant_id, idem_hash,
    )
    if other_open is not None:
        raise ApiError(
            E_IDEMPOTENCY_CONFLICT,
            basis={"reason": "concurrent_open_with_same_idempotency_key",
                   "migration_id": other_open["id"]},
        )
    dup_open = await conn.fetchrow(
        "SELECT id FROM migration_sessions WHERE source_custody_id=$1 AND status='open' LIMIT 1",
        source_custody_id,
    )
    if dup_open is not None:
        raise ApiError(
            E_MIGRATION_CONFLICT,
            basis={"reason": "open_migration_exists_for_custody",
                   "migration_id": dup_open["id"], "source_custody_id": source_custody_id},
        )
    done = await conn.fetchrow(
        "SELECT id FROM migration_sessions "
        "WHERE source_custody_id=$1 AND new_custody_id IS NOT NULL LIMIT 1",
        source_custody_id,
    )
    if done is not None:
        raise ApiError(
            E_MIGRATION_CONFLICT,
            basis={"reason": "custody_already_migrated", "migration_id": done["id"],
                   "source_custody_id": source_custody_id},
        )
    raise ApiError(E_MIGRATION_CONFLICT, basis={"reason": "duplicate_migration"})


@router.get("/migrations/{migration_id}", response_model=MigrationSessionOut)
async def get_migration(migration_id: str, request: Request, tenant=deps.Tenant) -> MigrationSessionOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        mig = await conn.fetchrow("SELECT * FROM migration_sessions WHERE id=$1", migration_id)
        if mig is None:
            raise ApiError(E_NOT_FOUND, basis={"migration_id": migration_id})
        if mig["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "migration_belongs_to_other_tenant"})
        source_policy = await repo.get_policy_version(conn, mig["source_policy_id"], mig["source_version"])
        count = await conn.fetchval(
            "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1", migration_id
        )
        new_digests = None
        if mig["new_custody_id"] is not None:
            new_digests = [
                r["shard_digest"]
                for r in await conn.fetch(
                    "SELECT shard_digest FROM shards WHERE custody_id=$1 ORDER BY point_x",
                    mig["new_custody_id"],
                )
            ]
    return _session_out(mig, count, source_policy["threshold"],
                        new_shard_count=len(new_digests) if new_digests is not None else None,
                        new_shard_digests=new_digests)


# ---------------------------------------------------------------------------
# Custodian endpoints
# ---------------------------------------------------------------------------

@router.post("/migrations/nonces", response_model=MigrationNonceOut)
async def issue_nonce(body: MigrationNonceRequestIn, request: Request,
                      custodian=deps.Custodian) -> MigrationNonceOut:
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    nonce = nonce_id = ""
    point_x = 0
    shard_digest = ""
    mig_row = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            mig_row = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            if mig_row is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            sess_tenant = mig_row["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig_row["source_policy_id"], mig_row["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig_row["target_policy_id"], mig_row["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig_row, source_policy, target_policy, now,
                                   custodian["id"])

            shard = await _source_shard(conn, mig_row["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            point_x = shard["point_x"]
            shard_digest = shard["shard_digest"]

            existing = await conn.fetchrow(
                "SELECT * FROM migration_nonces WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if existing is not None:
                raise ApiError(
                    E_NONCE_USED,
                    basis={
                        "migration_id": body.migration_id,
                        "custodian_id": custodian["id"],
                        "spent": existing["spent"],
                        "reason": "nonce_already_issued" if not existing["spent"] else "nonce_spent",
                    },
                )
            nonce = deps.new_nonce()
            nonce_id = deps.new_id("non")
            await conn.execute(
                """
                INSERT INTO migration_nonces (id, migration_id, custodian_id, nonce_hash, spent)
                VALUES ($1,$2,$3,$4, FALSE)
                """,
                nonce_id, body.migration_id, custodian["id"],
                crypto.sha256_hex(bytes.fromhex(nonce)),
            )
            await audit.append_audit(
                conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.nonce.issue", resource=nonce_id, result="ok",
                basis={"migration_id": body.migration_id,
                       "source_version": mig_row["source_version"],
                       "point_x": point_x, "shard_digest": shard_digest},
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.nonce.issue", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return MigrationNonceOut(
        nonce_id=nonce_id, nonce=nonce, migration_id=body.migration_id,
        custodian_id=custodian["id"],
        source_policy_id=mig_row["source_policy_id"], source_version=mig_row["source_version"],
        source_digest=mig_row["source_digest"],
        target_policy_id=mig_row["target_policy_id"], target_version=mig_row["target_version"],
        target_digest=mig_row["target_digest"],
        point_x=point_x, shard_digest=shard_digest,
    )


@router.post("/migrations/shards/claim", response_model=MigrationShardClaimOut)
async def claim_shard(body: MigrationShardClaimIn, request: Request,
                      custodian=deps.Custodian) -> MigrationShardClaimOut:
    """Authenticated source-policy custodian claims its own source shard.

    Plaintext appears only in this response — never logged, audited or cached.
    """
    settings = get_settings()
    pool = request.app.state.db.pool
    sess_tenant: str | None = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            sess_tenant = mig["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig["source_policy_id"], mig["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig["target_policy_id"], mig["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig, source_policy, target_policy, now, custodian["id"])

            nonce_row = await _resolve_nonce(conn, body.migration_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"],
                                                    "reason": "nonce_spent"})

            shard = await _source_shard(conn, mig["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            try:
                blob = crypto.decrypt_shard(
                    settings.shard_master_key_bytes, shard["id"], bytes(shard["ciphertext"])
                )
            except Exception:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_decrypt_failed",
                           "custodian_id": custodian["id"]},
                )
            if not crypto.constant_time_hex_equal(crypto.sha256_hex(blob), shard["shard_digest"]):
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_digest_mismatch",
                           "custodian_id": custodian["id"]},
                )
            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                custodian_id=custodian["id"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
            )
            await audit.append_audit(
                conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id, result="ok",
                basis={"nonce_id": nonce_row["id"], "point_x": shard["point_x"],
                       "shard_digest": shard["shard_digest"]},
            )
            out = MigrationShardClaimOut(
                migration_id=body.migration_id,
                nonce_id=nonce_row["id"],
                custodian_id=custodian["id"],
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_custody_id=mig["source_custody_id"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
                shard_hex=blob.hex(),
                signing_message=message.decode(),
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return out


@router.post("/migrations/shares", response_model=MigrationShareSubmitOut)
async def submit_share(body: MigrationShareSubmitIn, request: Request,
                       custodian=deps.Custodian) -> MigrationShareSubmitOut:
    pool = request.app.state.db.pool
    pending = request.app.state.pending
    sess_tenant: str | None = None
    pending_token = None
    completed = False
    count = 0
    threshold = 0
    new_custody_id: str | None = None
    new_shard_count: int | None = None
    new_shard_digests: list[str] | None = None

    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()

        async def _undo() -> None:
            # 与恢复流程相同的双重撤销边界：行锁仍持有时先凭本次 token
            # 精确撤回内存分片，再回滚；等待者拿锁时内存与数据库已一致。
            nonlocal pending_token
            if pending_token is not None:
                pending.discard(pending_token)
                pending_token = None
            await tx.rollback()

        try:
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            await faults.maybe_park(request, "migration.after_lock")
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            sess_tenant = mig["tenant_id"]
            source_policy = await repo.get_policy_version(
                conn, mig["source_policy_id"], mig["source_version"]
            )
            target_policy = await repo.get_policy_version(
                conn, mig["target_policy_id"], mig["target_version"]
            )
            now = await conn.fetchval("SELECT now()")
            await _guard_migration(conn, mig, source_policy, target_policy, now, custodian["id"])

            nonce_row = await _resolve_nonce(conn, body.migration_id, body.nonce, custodian["id"])
            if nonce_row["spent"]:
                raise ApiError(E_NONCE_USED, basis={"nonce_id": nonce_row["id"]})

            dup = await conn.fetchrow(
                "SELECT 1 FROM migration_share_submissions WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if dup:
                raise ApiError(E_DUPLICATE_SHARE,
                               basis={"migration_id": body.migration_id,
                                      "custodian_id": custodian["id"]})

            shard = await _source_shard(conn, mig["source_custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )

            blob = bytes.fromhex(body.shard_hex)
            if len(blob) > 8192:
                raise ApiError(E_BAD_REQUEST, basis={"reason": "shard_too_large", "bytes": len(blob)})
            if body.point_x != shard["point_x"]:
                raise ApiError(
                    E_SHARE_POINT,
                    basis={"custodian_id": custodian["id"],
                           "submitted_point_x": body.point_x,
                           "expected_point_x": shard["point_x"]},
                )
            submitted_digest = crypto.sha256_hex(blob)
            if not crypto.constant_time_hex_equal(submitted_digest, shard["shard_digest"]):
                raise ApiError(
                    E_SHARE_DIGEST,
                    basis={"custodian_id": custodian["id"], "point_x": body.point_x,
                           "submitted_shard_digest": submitted_digest,
                           "expected_shard_digest": shard["shard_digest"]},
                )

            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                source_policy_id=mig["source_policy_id"],
                source_version=mig["source_version"],
                source_digest=mig["source_digest"],
                target_policy_id=mig["target_policy_id"],
                target_version=mig["target_version"],
                target_digest=mig["target_digest"],
                custodian_id=custodian["id"],
                point_x=body.point_x,
                shard_digest=shard["shard_digest"],
            )
            if not crypto.verify_signature(custodian["signing_pubkey"], message,
                                           bytes.fromhex(body.signature)):
                raise ApiError(
                    E_BAD_SIGNATURE,
                    basis={"custodian_id": custodian["id"], "reason": "ed25519_verify_failed",
                           "expected_signing_message": message.decode()},
                )

            await conn.execute(
                "UPDATE migration_nonces SET spent=TRUE WHERE id=$1", nonce_row["id"]
            )
            sub_id = deps.new_id("msub")
            try:
                await conn.execute(
                    """
                    INSERT INTO migration_share_submissions
                      (id, migration_id, custodian_id, nonce_id, point_x, shard_digest)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    sub_id, body.migration_id, custodian["id"], nonce_row["id"],
                    body.point_x, shard["shard_digest"],
                )
            except Exception as exc:
                if getattr(exc, "pgcode", None) == "23505":
                    raise ApiError(E_DUPLICATE_SHARE,
                                   basis={"migration_id": body.migration_id,
                                          "custodian_id": custodian["id"]})
                raise

            pending_token = pending.add(body.migration_id, custodian["id"], body.point_x, blob)
            await faults.maybe_park(request, "migration.after_add")
            await faults.maybe_raise(request, "migration.after_add")

            count = await conn.fetchval(
                "SELECT count(*) FROM migration_share_submissions WHERE migration_id=$1",
                body.migration_id,
            )
            threshold = source_policy["threshold"]

            if count >= threshold:
                await faults.maybe_park(request, "migration.before_resplit")
                completed, new_custody_id, new_shard_count, new_shard_digests = (
                    await _resplit(conn, pending, mig, source_policy, target_policy)
                )

            await audit.append_audit(
                conn, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.share.submit", resource=body.migration_id, result="ok",
                basis={"shares_after": count, "threshold": threshold, "completed": completed,
                       "point_x": body.point_x, "shard_digest": shard["shard_digest"]},
            )
            try:
                await tx.commit()
            except Exception:
                await _undo()
                raise
        except ApiError as exc:
            await _undo()
            await repo.audit_denied(
                pool, tenant_id=sess_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.share.submit", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
        except Exception:
            await _undo()
            raise

    if completed:
        # 事务提交成功后立即销毁内存中的源分片与重组秘密。
        pending.clear(body.migration_id)
    return MigrationShareSubmitOut(
        migration_id=body.migration_id,
        status="completed" if completed else "open",
        shares_received=count,
        threshold=threshold,
        completed=completed,
        new_custody_id=new_custody_id,
        new_shard_count=new_shard_count,
        new_shard_digests=new_shard_digests,
    )


async def _resplit(conn, pending, mig, source_policy, target_policy):
    """Reconstruct in memory from verified source shares, re-shard to target.

    Everything (new custody row + new encrypted shards + session completion +
    audit) happens in the caller's single transaction; the secret lives only on
    this request's stack and is dropped as soon as the new shards are encrypted.
    """
    settings = get_settings()
    points = sorted(pending.get_points(mig["id"]), key=lambda p: p[0])
    if len(points) < source_policy["threshold"]:
        # 进程重启等导致内存待累计分片丢失：绝不回退到解密库存分片。
        raise ApiError(
            E_THRESHOLD_NOT_MET,
            basis={"reason": "pending_shares_unavailable",
                   "pending_in_memory": len(points),
                   "threshold": source_policy["threshold"]},
        )
    points = points[: source_policy["threshold"]]
    source_custody = await conn.fetchrow(
        "SELECT * FROM key_custodies WHERE id=$1", mig["source_custody_id"]
    )
    try:
        secret = crypto.shamir_combine(points, source_custody["secret_length"])
    except ValueError as exc:
        raise ApiError(E_INTEGRITY, basis={"reason": "shamir_combine_failed", "detail": str(exc)})
    if not crypto.constant_time_hex_equal(
        crypto.sha256_hex(secret), source_custody["secret_digest"]
    ):
        raise ApiError(E_INTEGRITY,
                       basis={"reason": "secret_digest_mismatch_after_reconstruction"})

    target_custodian_ids = list(target_policy["custodian_ids"])
    new_points = crypto.shamir_split(secret, target_policy["threshold"], len(target_custodian_ids))
    # 秘密字节在重组作用域内即用即弃；新分片已生成，显式删除栈引用。
    del secret

    new_custody_id = deps.new_id("cus_secret")
    await conn.execute(
        """
        INSERT INTO key_custodies
          (id, tenant_id, policy_id, policy_version, secret_digest, secret_length,
           epoch_index, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'active')
        """,
        new_custody_id, mig["tenant_id"], mig["target_policy_id"], mig["target_version"],
        source_custody["secret_digest"], source_custody["secret_length"],
        target_policy["epoch_index"],
    )

    new_shard_digests: list[str] = []
    for (x, blob), custodian_id in zip(new_points, target_custodian_ids):
        shard_id = deps.new_id("shd")
        ct = crypto.encrypt_shard(settings.shard_master_key_bytes, shard_id, blob)
        shard_digest = crypto.sha256_hex(blob)
        new_shard_digests.append(shard_digest)
        await conn.execute(
            """
            INSERT INTO shards (id, custody_id, custodian_id, point_x, ciphertext, shard_digest)
            VALUES ($1,$2,$3,$4,$5,$6)
            """,
            shard_id, new_custody_id, custodian_id, x, ct, shard_digest,
        )

    await conn.execute(
        """
        UPDATE migration_sessions
           SET status='completed', new_custody_id=$2, completed_at=now()
         WHERE id=$1
        """,
        mig["id"], new_custody_id,
    )
    await audit.append_audit(
        conn, tenant_id=mig["tenant_id"], actor_type="system", actor_id=None,
        action="migration.complete", resource=mig["id"], result="ok",
        basis={
            "source_custody_id": mig["source_custody_id"],
            "source_policy_id": mig["source_policy_id"],
            "source_version": mig["source_version"],
            "source_digest": mig["source_digest"],
            "target_policy_id": mig["target_policy_id"],
            "target_version": mig["target_version"],
            "target_digest": mig["target_digest"],
            "new_custody_id": new_custody_id,
            "new_shard_count": len(target_custodian_ids),
            "new_shard_digests": new_shard_digests,
        },
    )
    return True, new_custody_id, len(target_custodian_ids), new_shard_digests
