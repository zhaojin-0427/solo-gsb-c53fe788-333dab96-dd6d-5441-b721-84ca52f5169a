from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from .config import get_settings
from .db import Database, wait_for_database
from .errors import install_exception_handlers
from .faults import FaultBoard
from .pending import PendingShareStore
from .routers import admin, audit_log, custodies, migrations, policies, recovery


async def _pending_sweeper(app: FastAPI) -> None:
    # 周期清理已过期会话残留在内存的待累计分片（明文绝不落盘，进程退出即消失）
    while True:
        await asyncio.sleep(30)
        with suppress(Exception):
            app.state.pending.sweep()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    await wait_for_database(settings.database_url)
    database = Database(settings.database_url)
    await database.connect()
    app.state.db = database
    app.state.pending = PendingShareStore()
    # 故障注入默认关闭；仅 KEYVAULT_FAULT_INJECTION=1 的测试进程启用
    app.state.fault_enabled = settings.fault_injection
    app.state.fault_board = FaultBoard()
    sweeper = asyncio.create_task(_pending_sweeper(app))
    try:
        yield
    finally:
        sweeper.cancel()
        with suppress(asyncio.CancelledError):
            await sweeper
        await database.close()


app = FastAPI(
    title="多方密钥分片托管与门限恢复 API",
    version="1.4.0",
    description="不可变策略 + Shamir n-of-m 分片 + 门限恢复（提交本人分片，一次性密文）+ 跨策略密钥迁移",
    lifespan=lifespan,
)
install_exception_handlers(app)

app.include_router(admin.router)
app.include_router(policies.router)
app.include_router(custodies.router)
app.include_router(recovery.router)
app.include_router(migrations.router)
app.include_router(audit_log.router)


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok"}
