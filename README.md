# 多方密钥分片托管、门限恢复与跨策略迁移 API

租户把待托管密钥交给服务后，服务按 **Shamir 门限秘密分享 (n-of-m)** 切成多份，每份独立加密落盘，
任何单一托管人（甚至数据库运维）都无法还原秘密。恢复时托管人须**先经身份验证领取本人分片**，
再对**一次性 nonce + 会话 + 策略版本 + 托管人 + 分片点位 + 分片摘要**签名，连同**自己的分片字节**
一并提交；服务校验**分片归属、点位与库存摘要**通过后才花费 nonce 并计数。达到门限后，秘密**只由
这些已验签的提交分片在请求内存中重组**（服务端不再解密自己的库存分片来凑数），并用恢复方临时公钥
包装成**一次性密文**返回。

v1.4 新增**跨策略密钥迁移**：租户对仍有效的托管记录指定另一条有效策略版本、携带**幂等键**创建
迁移会话（会话固化源/目标**策略版本摘要**）；旧策略托管人按一次性挑战值领取并提交本人分片及签名，
达到**源门限**后秘密仅在内存重组、**立即按目标策略重新分片**，在**同一事务**写入新托管记录并返回
其标识——**源记录保持不变**；响应、数据库与审计全程无明文。

技术栈：Python 3.12 · FastAPI · PostgreSQL 16 · `cryptography` · Docker Compose。

> **新功能（v1.4）跨策略密钥迁移**：在不改写、不删除源托管记录的前提下，把一份托管秘密迁移到
> **另一条有效策略版本**（可同时更换托管人集合与门限）。租户 `POST /migrations`（必须带
> `Idempotency-Key` 头）创建会话，响应固化 `source_digest/target_digest`（不可变策略版本行的
> 规范化 SHA256）。旧策略托管人走与恢复同构的 **nonce → claim → sign → submit** 流程，但签名报文
> 换成迁移专用的 `keyvault.migration.v1`，逐行绑定
> 迁移会话/源版本摘要/目标版本摘要/nonce/托管人/点位/分片摘要。达到源门限的那一次提交：
> ① 秘密**只由已验签提交分片**在请求内存中插值重组（服务端不碰库存分片），校验 `secret_digest`；
> ② **立即**按目标策略 `shamir_split` 并逐片 AES-GCM 加密；③ 新 `key_custodies` + 新 `shards`、
> 会话置 `completed`、审计 `migration.complete` **同一事务**提交，源 custody/shards 一行不改。
> 幂等与并发：幂等键只存 `sha256`；同键同请求重放返回同一会话（200，完成态含同一新 custody），
> 同键不同请求 `IDEMPOTENCY_CONFLICT`；不同键迁移同一 custody 一律 `MIGRATION_CONFLICT`
> （`open_migration_exists_for_custody` / `custody_already_migrated`），由源 custody 行锁 +
> 部分唯一索引兜底，**不同幂等键绝不可能把同一记录迁移两次**。源/目标被撤销或过期、跨租户、
> 目标=源均被拒；会话 TTL 或源侧失效后旧 open 会话惰性置 `expired`，调用方可安全重试。
> 确定性拒绝（验签/点位/摘要/nonce/成员）不花费 nonce；入池后的失败沿用 v1.3 的双重撤销边界
> （行锁释放前先凭 token 撤回内存分片再回滚）。端到端与存储层断言见 `scripts/demo.py`
> （108 项，迁移用例覆盖正常流程、每类拒绝依据、并发重复、TTL 安全重试与存储层无明文）。

> **修复要点（v1.3）**：修复 `/recoveries/shares` 在“分片**已入内存池之后**异常回滚”时的交错竞态
> （重组失败、审计写入失败、连接中止等）。旧代码在异常路径上**先 `ROLLBACK` 释放会话行锁、
> 再移除本次内存分片**：① 同会话正在锁队列里等待的请求可能在这一瞬间读到未提交分片；
> ② 同一托管人重试先成功入池时，旧请求随后的无条件 `remove(custodian)` 会**误删掉新分片**——
> 数据库计数保留、内存缺片，后续门限满足时报 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现划定双重撤销边界：
> 1. **顺序**：异常路径在事务仍打开（行锁仍持有）时先撤回本次内存分片，再 `ROLLBACK`——
>    等待者拿锁时内存池与数据库已重新一致，绝不可能读到未提交分片；
> 2. **凭证**：`pending.add()` 返回仅属于本次插入的 token，回滚只能 `discard(本 token)`，
>    即使撤销顺序被任何改动意外打破，旧请求也无法删除同托管人成功重试产生的新分片。
>
> 由此保证：并发重试后重组**只使用已提交且验签通过的分片**（服务端绝不拿库存分片凑数），
> 门限达成只发生一次，**一次性密文只下发一次**；确定性校验拒绝（验签/点位/摘要/nonce 等）
> 全发生在入池之前，异常路径根本不触碰内存池。可精确钉住该交错的回归验证见
> `scripts/race_recovery.py`（38 项断言，`regression/R1·R2·R4·R5/U1`），
> 与原有 `scripts/demo.py` 一起由 demo 容器一键执行。
>
> **修复要点（v1.2）**：修复 `/recoveries/shares` 的跨请求状态损坏。旧实现的拒绝路径无条件
> 从内存分片池移除“本托管人”的分片：未达门限的会话已接受某托管人的有效分片后，该托管人重放
> 已花费 nonce（返回 `NONCE_ALREADY_USED`）会把**先前已验签的内存分片**一并删掉，而数据库提交
> 计数保留——随后其他托管人补足门限时内存分片不足，得到 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现明确提交事务与进程内分片池的撤销边界：**校验拒绝发生在分片入池之前，绝不触碰已提交分片；
> 事务回滚只撤回本次请求新增的分片**。并发重放与合法提交交错时，数据库计数与内存内容始终对应，
> 门限满足时仅用已验签分片重组、密文只下发一次。同批修正若干拒绝路径上 `ApiError` 的位置参数
> 调用（会把确定性 4xx 拒绝变成 500）。回归验证见 `scripts/demo.py` 中 `regression:` 前缀用例。
>
> **修复要点（v1.1）**：旧实现里托管人取得 nonce 后只交签名、不交分片也会计入份额，凑满门限即由
> 服务端解密库存分片重组——托管人无需真正持有自己的分片即可“代表”本人。现改为**凭本人已领取分片
> 的点位与字节提交**，签名绑定该分片摘要；归属/点位/库存摘要校验全部通过后才花费 nonce 计数，
> 待累计分片只在内存中保存、绝不明文落盘。

---

## 1. 一键启动

```bash
docker compose up --build
```

- API：<http://localhost:8000>
- Swagger 交互文档：<http://localhost:8000/docs>
- OpenAPI JSON：<http://localhost:8000/openapi.json>
- 健康检查：<http://localhost:8000/health>
- PostgreSQL：`localhost:5432`（用户/库/密码均为 `keyvault`）

首次启动会自动建表并写入一组**演示身份**（1 个租户 + 3 个托管人，仅用于本地联调，密钥是确定性的，
**严禁用于生产**）。演示凭据可随时打印：

```bash
docker compose exec api python -m app.seed
```

生产部署通过环境变量覆盖（见 `.env.example`）：

| 变量 | 说明 |
| --- | --- |
| `KEYVAULT_DATABASE_URL` | PostgreSQL DSN |
| `KEYVAULT_SHARD_MASTER_KEY` | ≥32 字节字符串或 64 位 hex，用于 HKDF 派生分片加密密钥 |
| `KEYVAULT_ADMIN_API_KEY` | 管理端注册身份用的 API Key |
| `KEYVAULT_RECOVERY_DEFAULT_TTL` / `KEYVAULT_RECOVERY_MAX_TTL` | 恢复会话默认/上限 TTL（秒） |
| `KEYVAULT_FAULT_INJECTION` | 仅测试：`1` 开启并发交错故障注入闸门；默认 `0`（关闭时零开销，切勿在生产开启） |

---

## 2. 快速体验（端到端）

容器自带完整验收脚本，覆盖正常恢复、每一种拒绝依据、并发竞态、跨策略迁移与审计链重放：

```bash
# 1) 并发回滚竞态回归（scripts.race_recovery，38 项）
# 2) 端到端验收（scripts.demo，108 项）
docker compose --profile demo run --rm demo
```

期望依次输出 `RACE REGRESSION CHECKS PASSED` 与 `ALL CHECKS PASSED`。

`scripts.race_recovery.py` 在进程内以真实 ASGI + 真实 PostgreSQL 行锁运行，通过仅测试构建启用的
故障注入闸门（`KEYVAULT_FAULT_INJECTION=1`，API 服务默认关闭、关闭时零开销）精确钉住交错点：
一个请求的已验签分片已入内存池、行锁仍持有时注入重组/审计/连接类失败，另一个请求正排队等待行锁；
断言**未提交分片在行锁释放前撤回**、等待者读不到它、同托管人重试的新分片不会被旧回滚误删，
且门限只按已提交且验签的分片达成一次、密文只下发一次。本地单独运行：

```bash
KEYVAULT_FAULT_INJECTION=1 \
KEYVAULT_DATABASE_URL=postgresql://keyvault:keyvault@localhost:5432/keyvault \
python -m scripts.race_recovery
```

以下用 curl 走一遍核心流程（演示凭据见 `python -m app.seed` 输出）：

```bash
TENANT=tsec_01ea27eafbe8e5c6c1fb1c6a4f9c18b5ae9a3a4b6d7e8f9a0b1c2d3e4f506172   # 以实际输出为准
ADMIN=admin-dev-key

# 2.1 管理员创建托管人（已由 seed 预置 alice/bob/carol，也可新建）
curl -s -X POST localhost:8000/admin/custodians -H "X-API-Key: $ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"dave"}'
# -> custodian_id / api_key / signing_private_key(仅返回一次) / signing_public_key

# 2.2 创建不可变策略 2-of-3，带 epoch 有效期与轮换间隔
curl -s -X POST localhost:8000/policies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id": "pol_main",
  "threshold": 2,
  "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
  "epoch": {"valid_from":"2026-01-01T00:00:00Z","valid_until":"2030-01-01T00:00:00Z","rotation_interval":0}
}'

# 2.3 托管密钥（hex），服务立即 Shamir 分片 + AES-GCM 加密落盘
curl -s -X POST localhost:8000/custodies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id":"pol_main","expected_version":1,"secret_hex":"7468652d736563726574"}'
# -> custody_id、secret_digest、各分片 shard_digest（响应不含任何明文）

# 2.4 租户凭申请摘要 + 恢复方 X25519 公钥发起恢复会话（绑定策略版本，带过期时间）
curl -s -X POST localhost:8000/recoveries -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "custody_id":"cus_secret_...",
  "request_digest":"<sha256(ticket|purpose)>",
  "recovery_public_key":"<32B X25519 公钥 hex>",
  "ttl_seconds": 300
}'

# 2.5 托管人领取一次性 nonce（返回 nonce、本人分片点位与分片摘要；此时还没有签名报文）
curl -s -X POST localhost:8000/recoveries/nonces \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_..."}'
# -> nonce + point_x + shard_digest（绑定 custodian/policy/version/session）

# 2.6 托管人凭该 nonce 领取“本人分片”（明文仅在本次响应出现，服务端不落盘、不入审计）
curl -s -X POST localhost:8000/recoveries/shards/claim \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"..."}'
# -> point_x / shard_hex / shard_digest / signing_message
#    signing_message 绑定 nonce+会话+策略版本+托管人+点位+分片摘要

# 2.7 托管人用 Ed25519 私钥对 signing_message 签名，连同点位与分片字节提交；
#     归属/点位/库存摘要/验签全部通过才花费 nonce；达到门限的那一次返回一次性密文
curl -s -X POST localhost:8000/recoveries/shares \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"...","point_x":1,
       "shard_hex":"<领取到的本人分片 hex>","signature":"<64B ed25519 hex>"}'
# -> completed=true 时附带 wrap：X25519 临时 ECDH + HKDF-SHA256 + AES-256-GCM
```

客户端解包（Python 示例见 `scripts/demo.py` 的 `unwrap()`）：用本地 X25519 私钥与
`wrap.ephemeral_public_key` 做 ECDH，HKDF 的 info 为 `b"KWR1" + aad`，AAD 即响应中的 `aad`
（内含 session/policy/version/epoch/request_digest，防密文被挪用）。

### 2.8 托管人领取与提交分片（分步说明）

恢复不是“签个名就行”，托管人必须真正交出自己的分片，步骤固定为 **nonce → claim → sign → submit**：

1. **领 nonce**：`POST /recoveries/nonces`，仅会话成员、且会话处于 open 且未过期时可领。
   响应含 `nonce`、该托管人在此托管下的 `point_x` 与 `shard_digest`（每会话每人至多一张，明文仅此次下发）。
2. **领本人分片**：`POST /recoveries/shards/claim`，携带 `session_id + nonce`。
   服务端校验身份、会话状态、nonce 归属与未花费后，解密**该托管人名下**的库存分片，自检摘要自洽，
   返回 `shard_hex`（明文仅存在于这一次 HTTPS 响应）与待签名的 `signing_message`。
   - nonce 未花费前可重复领取（幂等，返回同一片）；nonce 一旦花费，领取返回 `NONCE_ALREADY_USED`。
   - 不属于该策略版本 / nonce 不属于本人或会话 / 会话已完成或过期，一律拒绝，拿不到分片。
3. **本地签名**：对 `signing_message`（`keyvault.share.v2`，逐行绑定
   custodian/policy/version/session/nonce/**point**/**shard_digest**）做 Ed25519 签名。
4. **提交分片**：`POST /recoveries/shares`，携带 `nonce + point_x + shard_hex + signature`。
   服务端依次校验：会话/epoch 状态 → nonce 归属与未花费 → 未重复提交 → **分片归属**（该托管人名下确有其片）
   → **点位一致** → **`sha256(shard_hex)` 与库存 `shard_digest` 一致** → Ed25519 验签；
   **全部通过才花费 nonce 并计数**。点位不符返回 `SHARE_POINT_MISMATCH`，字节被改返回
   `SHARE_DIGEST_MISMATCH`，验签失败返回 `BAD_SIGNATURE`——三者都**不花费 nonce**，basis 给出确定性事实。
5. **门限重组**：有效提交数达到门限时，服务端只用**这些已验签的提交分片**在内存中插值重组，
   校验 `secret_digest` 后包装成一次性密文；同事务把会话置 `completed`，并立即销毁内存中的待累计分片。
   重复提交、会话撤销/过期、并发双发都只会得到拒绝，密文**全局只下发一次**。

**异常与重试语义**（客户端可据此安全重试）：

- 验签/点位/摘要/nonce/重复/会话状态等**确定性拒绝**全部发生在花费 nonce 与分片入池**之前**：
  nonce 未花费、计数不变、内存池不被触碰，客户端修正后用同一 nonce 重试即可。
- 分片入池**之后**才可能失败的环节（门限重组、审计写入、连接中止）一律在**会话行锁仍持有时**
  先凭本次插入凭证撤回内存分片，再回滚事务释放锁：等待锁的并发请求拿锁时内存与数据库计数必然一致，
  读不到任何未提交分片；同托管人的重试即使先成功，旧请求的回滚也只能撤回自己的插入，**绝不会误删
  新分片**。因此任何 4xx/500 之后，调用方查询 `GET /recoveries/{id}` 看到的 `shares_received`
  就是内存中可用于重组的已验签分片数——重试只会得到干净结果，不会出现 `THRESHOLD_NOT_MET` 卡死。
- nonce 已花费后该 nonce 不可再用；需要继续补片时沿用已领取的其他 nonce，或另开恢复会话。
- 进程重启丢失内存待累计分片时，达到门限的提交返回确定性的 `THRESHOLD_NOT_MET`
  （basis.reason=`pending_shares_unavailable`），此时另开恢复会话重来。

> 待累计分片**只存进程内存**（`app/pending.py`），不写库、不写日志、不进审计；进程重启后内存清空，
> 已计数的会话无法继续重组，需另开恢复会话（提交接口此时返回 `THRESHOLD_NOT_MET`，basis.reason 为
> `pending_shares_unavailable`）。这是本演示基线在“明文不落盘”与“多副本部署”之间的明确取舍。
> 迁移会话的待累计源分片复用同一内存池（以 migration_id 为键），语义完全相同。

### 2.9 跨策略密钥迁移（curl 流程）

目标：把一份仍有效托管（源策略 `pol_main:v1`，2-of-3）迁移到**另一条有效策略版本**
（`pol_next:v1`，可换托管人集合/门限）。源记录全程保持 `active` 不变。

```bash
TENANT=tsec_...   # python -m app.seed 输出

# (1) 租户创建迁移会话：必须带 Idempotency-Key；绑定源 custody 与目标策略版本
curl -s -X POST localhost:8000/migrations -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: migrate-2026-09-26-0001' -d '{
    "source_custody_id":"cus_secret_...",
    "target_policy_id":"pol_next",
    "target_version":1,
    "ttl_seconds":300
  }'
# -> migration_id、source_digest/target_digest（不可变版本行摘要）、status=open、threshold(源门限)
#    同键同体重放返回 200 + 同一会话（不新建、不重复留痕）；首次创建为 201

# (2) 源策略托管人领取一次性挑战值（与恢复同构）
curl -s -X POST localhost:8000/migrations/nonces -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{"migration_id":"mig_..."}'
# -> nonce + point_x + shard_digest + source/target_digest

# (3) 托管人领取本人“源分片”（明文仅在本次响应出现，不落盘/不入审计）
curl -s -X POST localhost:8000/migrations/shards/claim -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{"migration_id":"mig_...","nonce":"..."}'
# -> shard_hex + signing_message（keyvault.migration.v1：逐行绑定
#    migration/source_digest/target_digest/nonce/custodian/point/shard_digest）

# (4) 托管人本地 Ed25519 签名后，提交本人源分片 + 签名
curl -s -X POST localhost:8000/migrations/shares -H "X-API-Key: $CUSTODIAN_KEY" \
  -H 'Content-Type: application/json' -d '{
    "migration_id":"mig_...","nonce":"...","point_x":1,
    "shard_hex":"<领取到的本人源分片 hex>","signature":"<64B ed25519 hex>"}'

# (5) 达到源门限的那一次（如 2-of-3 的第 2 份）：
# -> completed=true、new_custody_id、new_shard_count、new_shard_digests[]
#    服务端仅用已验签源分片在内存重组 -> 立即按目标策略重新分片 ->
#    新托管记录 + 新加密分片在同一事务写入；源 custody/shards 一行未改，
#    响应不含秘密或分片明文。新记录此后即可按目标策略正常 POST /recoveries。

# 查询迁移会话（幂等/排障）
curl -s localhost:8000/migrations/mig_... -H "X-API-Key: $TENANT"
# -> status(open|completed|expired)、shares_received、threshold、new_custody_id
```

**迁移的拒绝与重试语义**：

- 必须携带 `Idempotency-Key`（缺失/超长 → `BAD_REQUEST`）；幂等键与 nonce 都只存 SHA256 摘要。
- 同键不同请求体（换源 custody 或换目标版本）→ `IDEMPOTENCY_CONFLICT`；
  不同幂等键迁移同一 custody → `MIGRATION_CONFLICT`
 （`open_migration_exists_for_custody` / `custody_already_migrated`）——
  完成迁移的 custody 再用任何键发起都会被拒，**不同键不可能迁移两次**。
- 源 custody 非 active 或源版本已撤销/过期 → `MIGRATION_SOURCE_INVALID`；
  目标版本不存在、已撤销、已过期、属于别的租户、或与源完全相同 →
  `MIGRATION_TARGET_INVALID` / `FORBIDDEN`。
- 托管人侧拒绝码与恢复一致：非源策略成员 `CROSS_POLICY_SHARE`、验签失败 `BAD_SIGNATURE`、
  点位/摘要不符 `SHARE_POINT_MISMATCH`/`SHARE_DIGEST_MISMATCH`（均不花费 nonce）、
  nonce 重放 `NONCE_ALREADY_USED`、重复提交 `DUPLICATE_SHARE`、
  会话完成 `MIGRATION_COMPLETED`、会话 TTL 失效或源侧在途被撤销/过期
  `SESSION_EXPIRED` / `EPOCH_REVOKED` / `EPOCH_EXPIRED`。
- 每次 nonce/claim/submit 都重新校验源/目标**版本摘要**与会话绑定一致，
  若不可变版本行与固化摘要不符 → `MIGRATION_DIGEST_MISMATCH`（完整性兜底）。
- 会话超过 TTL、或源侧在途失效后，旧 open 会话在该 custody 下一次请求时被惰性置 `expired`，
  随后可用同一幂等键（也可用新键）安全重试；确定性 4xx 不花费 nonce，可直接用原 nonce 重领重试。
- 并发创建由源 custody 行锁串行化 + 部分唯一索引兜底：同键并发恰有一次 201、另一次重放 200；
  不同键并发恰有一次 201、另一次 `MIGRATION_CONFLICT`。

轮换 / 撤销：

```bash
# 原子推进到 v2（乐观锁 expected_version；可同时改托管集合/门限/epoch）
curl -s -X POST localhost:8000/policies/pol_main/rotate -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' \
  -d '{"expected_version":1,"epoch":{"valid_from":"2027-01-01T00:00:00Z",
        "valid_until":"2031-01-01T00:00:00Z","rotation_interval":0}}'

# 撤销当前 epoch（原子；之后新托管/恢复一律 EPOCH_REVOKED）
curl -s -X POST localhost:8000/policies/pol_main/revoke -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -d '{"expected_version":2}'

# 审计哈希链按序重放并自校验
curl -s localhost:8000/audit/replay -H "X-API-Key: $TENANT"
```

---

## 3. API 总览

| 方法 & 路径 | 调用方 | 说明 |
| --- | --- | --- |
| `POST /admin/tenants` | admin | 注册租户，返回 API Key（仅一次） |
| `POST /admin/custodians` | admin | 注册托管人，返回 API Key 与 Ed25519 签名私钥（仅一次） |
| `POST /policies` | 租户 | 创建不可变策略 v1：n-of-m、epoch、轮换间隔 |
| `GET /policies/{id}?version=` | 租户 | 读取头版本或任意历史版本（版本永不修改） |
| `POST /policies/{id}/rotate` | 租户 | 原子推进版本（写入新版本 + 旧版本置 revoked + 头指针前移） |
| `POST /policies/{id}/revoke` | 租户 | 原子撤销当前 epoch |
| `POST /custodies` | 租户 | 提交待托管密钥，返回 custody_id 与各分片摘要 |
| `POST /recoveries` | 租户 | 创建恢复会话（绑定策略版本 + 申请摘要 + TTL） |
| `GET /recoveries/{id}` | 租户 | 查询会话状态与已收份额数 |
| `POST /recoveries/nonces` | 托管人 | 领取一次性 nonce（含本人分片点位与摘要） |
| `POST /recoveries/shards/claim` | 托管人 | 验身份后领取**本人分片**明文 + 待签名报文（绑定 nonce） |
| `POST /recoveries/shares` | 托管人 | 提交**本人分片点位+字节**与 Ed25519 签名；门限满足时返回一次性密文 |
| `POST /migrations` | 租户 | 携带 `Idempotency-Key` 创建跨策略迁移会话（绑定源/目标策略版本摘要） |
| `GET /migrations/{id}` | 租户 | 查询迁移状态、已收源分片数、完成后的新托管记录标识 |
| `POST /migrations/nonces` | 托管人 | 领取迁移一次性挑战值 nonce（仅源策略成员） |
| `POST /migrations/shards/claim` | 托管人 | 验身份后领取**本人源分片**明文 + 迁移待签名报文 |
| `POST /migrations/shares` | 托管人 | 提交本人源分片+签名；源门限满足时同事务按目标策略重新分片并返回新 custody |
| `GET /audit/replay` | 租户 | 重放哈希链并验证完整性 |

所有拒绝响应结构统一且确定性：

```json
{"error": {"code": "NONCE_ALREADY_USED",
           "message": "nonce has already been spent",
           "basis": {"nonce_id": "non_...", "...": "机器可判定的事实依据"}}}
```

调用方应依据 `code`（稳定）而非 `message`（可读）做分支。

| code | 含义 |
| --- | --- |
| `VALIDATION_FAILED` / `BAD_REQUEST` | 报文格式/取值非法（basis.fields 给出字段级原因） |
| `UNAUTHORIZED` / `FORBIDDEN` | 缺 Key、Key 无效或资源属于其他租户 |
| `NOT_FOUND` | 资源不存在 |
| `POLICY_PARAMS_INVALID` | 不满足 1 ≤ threshold ≤ 托管人数 |
| `VERSION_CONFLICT` | `expected_version` 与当前头版本不符（乐观锁） |
| `POLICY_INACTIVE` | 头版本已撤销，不能再轮换 |
| `EPOCH_REVOKED` / `EPOCH_EXPIRED` | epoch 已撤销 / 已过 `valid_until` |
| `NONCE_ALREADY_USED` | nonce 重复领取、已花费或持已花费 nonce 再领片（一次性） |
| `BAD_SIGNATURE` | Ed25519 验签失败（验签失败不花费 nonce） |
| `SHARE_POINT_MISMATCH` | 提交分片的点位不是该托管人在该托管下被分配的点位（不花费 nonce） |
| `SHARE_DIGEST_MISMATCH` | `sha256(提交分片)` 与库存 `shard_digest` 不符，分片被改/非本人片（不花费 nonce） |
| `DUPLICATE_SHARE` | 同一托管人对同一会话重复提交 |
| `CROSS_POLICY_SHARE` | 托管人不属于该策略版本，或 nonce/领取/提交绑定的会话、托管人不匹配 |
| `SESSION_COMPLETED` / `SESSION_EXPIRED` | 会话已完成（密文只下发一次）/ 已过 TTL |
| `THRESHOLD_NOT_MET` / `INTEGRITY_CHECK_FAILED` | 有效分片不足（含重启后内存待累计分片丢失 `pending_shares_unavailable`）/ 重组结果摘要不匹配 |
| `IDEMPOTENCY_CONFLICT` | `Idempotency-Key` 已绑定另一个不同的迁移请求，或同键并发正在创建 |
| `MIGRATION_TARGET_INVALID` | 目标策略版本不存在、已撤销/已过期、属于其他租户，或与源版本相同 |
| `MIGRATION_SOURCE_INVALID` | 源托管记录非 active（已轮换/撤销）或源策略版本已撤销/过期，不能发起迁移 |
| `MIGRATION_DIGEST_MISMATCH` | 会话绑定的源/目标策略版本摘要与不可变版本行不符（完整性兜底） |
| `MIGRATION_CONFLICT` | 同一 custody 存在其他 open 迁移会话，或该 custody 已迁移完成（不同幂等键不得重复迁移） |
| `MIGRATION_COMPLETED` | 迁移会话已完成（新托管记录只生成一次） |

---

## 4. 安全设计要点

**不可变策略 + 版本/epoch 推进**
`policies` 以 `(policy_id, version)` 为复合主键，只 INSERT、永不 UPDATE 内容；
`policy_heads` 保存当前头指针。轮换与撤销在**单事务**内完成（行级 advisory lock + 头行 `FOR UPDATE`）：
插入新版本 → 旧版本置 `revoked`、其下 custody 置 `rotated/revoked` → 前移指针。
并发轮换只有一方成功，另一方得到 `VERSION_CONFLICT`。所有写入接口都要求 `expected_version` 乐观锁。

**Shamir 分片（GF(p)，p = 2²⁵⁶−2³²−977）**
秘密按 31 字节分块，每块构造独立的 `(threshold−1)` 次多项式；分片点 x 为托管人序号，
y 拼接编码。任意 ≥ threshold 个分片可插值还原，少于门限不提供任何信息（50 组随机参数性质测试见
`scripts/demo.py`）。每个分片以 `HKDF(master_key, shard_id)` 派生独立密钥，AES-256-GCM 加密落盘；
数据库同时保存 `secret_digest` 与各 `shard_digest`，重组后做常量时间比对。

**领取本人分片 + 一次性 nonce + 签名绑定实际分片**
nonce 是 32 字节随机数，库里只存 `sha256(nonce)`，且有 `UNIQUE(nonce_hash)` 与
`UNIQUE(session_id, custodian_id)` 两重约束。托管人**先用 nonce 领取本人分片**，
再对规范报文（`keyvault.share.v2`）签名，报文逐行绑定
`custodian / policy_id / policy_version / session_id / nonce / point_x / shard_digest`。
提交时必须同时给出 `point_x` 与 `shard_hex`，因此：

- 只拿到 nonce 就签名、不交自己的分片 → 无法计数（点位/摘要校验过不了），凑门限无从谈起；
- 提交别人的点位或被篡改的分片字节 → 分别得到 `SHARE_POINT_MISMATCH` / `SHARE_DIGEST_MISMATCH`；
- 同一 nonce 用两次 → 第二次 `NONCE_ALREADY_USED`；
- 把别的托管人/别的会话的 nonce 拿来用 → `CROSS_POLICY_SHARE`；
- 策略轮换后重放旧版本场景的 nonce → 版本不匹配，且会话侧直接 `EPOCH_REVOKED`；
- 归属、点位、摘要、验签任一失败都**不花费 nonce**（合法网络重试不会锁死托管人）；
  全部通过后才在同一事务内花费 nonce、写入计数。

**并发竞态**
nonce 签发、分片领取与份额提交都先对 `recovery_sessions` 行 `SELECT ... FOR UPDATE`，
同一会话完全串行化；重复提交再由唯一约束兜底。内存待累计分片在全部校验通过、数据库写入
完成后才入池，其撤销边界有双重保证：**校验拒绝发生在入池之前，回滚时绝不触碰已提交的内存分片；
入池后的任何失败（重组/审计写入/连接中止）都在行锁释放之前、凭本次插入的私有 token 精确撤回
本次新增**——token 不匹配（例如同托管人的成功重试已先把新分片放入池中）时撤销为安全 no-op。
因此即使在“失败回滚 × 锁等待者 × 同托管人重试”的交错下，数据库提交计数与内存内容始终对应，
等待者拿锁时绝不会读到未提交分片，旧请求也无法误删新分片；门限只按**已提交且验签**的分片
达成一次，重放已花费 nonce 等拒绝不会破坏进行中的会话。演示脚本用 `asyncio.gather` 双发验证：
同一份额并发提交恰好一次 200、一次 409，份额计数不重复；另有“重放 × 合法提交”交错用例，
验证合法分片补足门限恰好完成一次、密文只下发一次；`scripts/race_recovery.py` 进一步用故障注入
闸门钉住行锁等待与回滚的精确交错（38 项断言）。

**恢复会话与一次性密文**
会话绑定 `custody/policy_version/epoch_index/request_digest/valid_until`；提交时实时校验
会话未完成、未过期、epoch 未被撤销或过期——即使会话进行中租户突然轮换/撤销，在途份额也会被拒。
门限满足后秘密只存在于当前请求栈内存，且**只由托管人实际提交、并已通过归属/点位/摘要/验签的
分片**插值得到（服务端**不**解密自己的库存分片来凑数）→ 校验 `secret_digest` →
X25519 临时 ECDH + HKDF + AES-GCM 包装 → 同事务把会话置 `completed`，提交成功后立即清空内存待累计分片，
密文不再可获取（重复提交、撤销、并发下都只返回这一次）。
AAD 绑定会话全部要素，密文无法被挪到别的会话复用。待累计分片明文绝不落盘（见 `app/pending.py`）。

**跨策略密钥迁移（v1.4）**
迁移会话 `migration_sessions` 与恢复表结构同构（独立的 `migration_nonces` /
`migration_share_submissions`），额外固化 `source_digest/target_digest` 与只存摘要的
`idempotency_key_hash`。三重部分唯一约束保证“不重复迁移”：

- `UNIQUE(tenant_id, idempotency_key_hash) WHERE status='open'`：同键有效会话唯一；
- `UNIQUE(source_custody_id) WHERE status='open'`：同一 custody 至多一个进行中迁移；
- `UNIQUE(source_custody_id) WHERE new_custody_id IS NOT NULL`：已迁移 custody 全局唯一。

创建在源 custody 行 `FOR UPDATE` 锁内完成，并发被串行化，索引再兜底。每个关口（nonce/claim/submit）
都在迁移行锁内重新校验：会话未完成/未过期、绑定的源/目标**版本摘要**与不可变版本行逐字节一致、
源与目标版本均未撤销/未过期、提交者确属**源**策略成员。签名协议独立为 `keyvault.migration.v1`，
与恢复报文互不兼容，签名逐行绑定源/目标摘要，无法把迁移签名挪去恢复、也无法跨目标版本重放。

门限达成后的关键路径与恢复同样严格：秘密**只由已验签提交源分片在请求栈内存插值**得到
（绝不解密库存源分片凑数），校验 `secret_digest` 后**立即**按目标策略重新 `shamir_split`、
逐片以独立 HKDF 密钥 AES-GCM 加密；随后 **新 `key_custodies` + 新 `shards` + 会话置 completed +
`migration.complete` 审计** 在**同一事务**提交，重组秘密在作用域结束即丢弃。源 custody 与源 shards
**一行不改**（不 UPDATE 状态、不删除、不置 rotated）；迁移不改变源记录，源门限恢复仍可独立进行。
入池后失败沿用 v1.3 双重撤销边界；TTL 或源侧失效的 open 会话在同源下一次创建时惰性置 `expired`
以释放唯一索引，之后同键/新键均可安全重试。幂等重放（含完成态）返回 200 与同一新 custody 标识，
迁移全过程的响应、数据库与审计只出现 ID、版本摘要、点位和分片/秘密摘要，不出现任何明文。

**审计：按序、可重放、不泄密**
`audit_log` 仅追加，每条记录 `seq`（事务级 advisory lock 串行分配）与
`entry_hash = SHA256(规范字段 || prev_hash)`，形成哈希链；`GET /audit/replay`
逐条复算并报告首个断裂点。审计内容只含 ID、版本、epoch、**分片点位与摘要**、计数等事实，
写入口还会按字段名（secret/private/ciphertext/plaintext/share_blob/nonce/key…）二次过滤，
拒绝事件同样留痕（含 `migration.start/nonce.issue/shard.claim/share.submit/complete`
及其 denied 记录）。

---

## 5. 本地开发（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# 准备一个 PostgreSQL 16，设置 KEYVAULT_DATABASE_URL 后：
python -m app.seed                      # 建表 + 演示身份
uvicorn app.main:app --reload --port 8000
KEYVAULT_BASE_URL=http://localhost:8000 python -m scripts.demo       # 端到端验收（含跨策略迁移，108 项）
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_recovery           # 并发回滚竞态回归
```

## 6. 生产注意（本仓库为演示强化基线，上线前至少完成）

- 替换全部演示密钥；分片主密钥建议接入 KMS，进程只持有短期解封装后的密钥；
- 启用 TLS；为管理端与租户/托管人端分离网关与限流；
- `pgcrypto`/列级权限或独立加密服务进一步隔离分片；按租户评估分片落盘地域；
- 轮换主密钥时需要对分片做 rewrap（数据模型中 `shards.id` 即派生密钥标识，可据此迁移）。
