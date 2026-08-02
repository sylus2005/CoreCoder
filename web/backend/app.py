"""CoreCoder Security Agent — FastAPI 后端入口.

提供审计 API (路由定义在 routes.py 中):
- POST /api/audit              启动安全审计
- GET  /api/audit/{id}/stream   SSE 实时日志流
- GET  /api/audit/{id}/report   获取审计报告
- GET  /api/audit/{id}/status   审计状态
- GET  /api/audits               列出所有审计
- GET  /api/health               健康检查

启动方式:
    cd web/backend
    uvicorn app:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import router, set_audit_store

# ── 审计实例存储 (MVP 不用数据库) ──
_audits: dict[str, dict] = {}

# 注入存储到路由模块
set_audit_store(_audits)

# ── FastAPI 应用 ────────────────────────────────────────────

app = FastAPI(
    title="CoreCoder Security Agent",
    version="1.0.0-MVP",
    description="AI-powered cybersecurity audit agent — REST + SSE API",
)

# CORS — 允许前端跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(router)

# ── 启动入口 ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
