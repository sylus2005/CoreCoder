"""CoreCoder Security Agent — API 路由模块.

为审计请求提供专门的路由和处理函数:
- POST /api/audit           启动安全审计 → 调用 AuditPipeline
- POST /api/audit/upload     上传文件并返回目标路径
- GET  /api/audit/{id}/stream   SSE 实时日志流
- GET  /api/audit/{id}/report   获取审计报告
- GET  /api/audit/{id}/status   审计状态
- GET  /api/audits               列出所有审计

所有审计请求最终都通过 _run_audit() 调用 AuditPipeline 引擎。
"""

import json
import asyncio
import traceback
import os as _os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import StreamingResponse

from models import AuditRequest, AuditResponse, UploadResponse, ChatRequest, ChatResponse

# CoreCoder 安全引擎
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from corecoder.tools.security.pipeline import AuditPipeline, AuditConfig

router = APIRouter(prefix="/api", tags=["security-audit"])

# ── 内存中的审计实例存储 (MVP 不用数据库) ──
# 由 app.py 在启动时注入引用
_audits: dict[str, dict] = {}

# 上传文件存储根目录
_UPLOAD_ROOT = Path(tempfile.gettempdir()) / "corecoder-uploads"


def set_audit_store(store: dict):
    """注入审计存储（由 app.py 调用）。"""
    global _audits
    _audits = store


def _write_file(path: Path, content: bytes):
    """同步写入文件（在线程池中调用，避免阻塞事件循环）。"""
    with open(path, "wb") as f:
        f.write(content)


# ── 内部: 运行审计流水线 ─────────────────────────────────────

async def _run_audit(audit_id: str, req: AuditRequest):
    """在后台运行 AuditPipeline，将事件推送到队列.

    这是"监听特定审计请求并调用审计引擎"的核心逻辑。
    前端 POST /api/audit → 本函数被 asyncio.create_task 调度 →
    AuditPipeline.run() 驱动三阶段流水线 → 事件通过 SSE 推送前端。
    """
    audit = _audits.get(audit_id)
    if not audit:
        return
    q = audit["event_queue"]

    # 将相对路径解析为项目根目录下的绝对路径
    project_root = _os.path.abspath(
        _os.path.join(_os.path.dirname(__file__), "..", "..")
    )

    # 优先使用上传的绝对路径，否则解析相对路径
    target = req.target
    if not _os.path.isabs(target):
        target = _os.path.abspath(_os.path.join(project_root, target))

    print(f"[audit {audit_id}] target={target}, project_root={project_root}")
    print(f"[audit {audit_id}] tools={req.tools}")
    if req.requirements:
        print(f"[audit {audit_id}] requirements={req.requirements[:200]}")

    try:
        config = AuditConfig(
            target=target,
            tools=req.tools,
            model=req.model,
        )
        pipeline = AuditPipeline(config=config)

        async def event_handler(event):
            """SSE 事件处理器: 存储事件并推送到队列."""
            audit["events"].append(event)
            if event["type"] == "finding":
                audit["findings"].append(event)
            await q.put(event)

        pipeline.on_event(event_handler)

        # 如果有用户需求，先发送到日志
        if req.requirements:
            await q.put({
                "type": "log",
                "message": f"💬 用户需求: {req.requirements}",
            })

        print(f"[audit {audit_id}] pipeline starting...")
        async for event in pipeline.run(target):
            pass  # event_handler 已处理每个事件
        print(f"[audit {audit_id}] pipeline done, findings={len(audit['findings'])}")

        # 从最后一个 done 事件中提取报告
        for evt in reversed(audit["events"]):
            if evt["type"] == "done":
                audit["report"] = {
                    "summary": evt.get("summary", {}),
                    "report_md": evt.get("report_md", ""),
                }
                break

        audit["status"] = "completed"

    except Exception as e:
        print(f"[audit {audit_id}] ERROR: {e}")
        traceback.print_exc()
        audit["status"] = "error"
        await q.put({
            "type": "audit_error",
            "message": f"审计失败: {str(e)}",
        })
        await q.put({
            "type": "done",
            "summary": {
                "total": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            },
            "duration_seconds": 0,
        })


# ── API 路由 ─────────────────────────────────────────────────

@router.get("/health")
async def health():
    """健康检查."""
    return {"status": "ok", "service": "CoreCoder Security Agent"}


@router.post("/audit/upload", response_model=UploadResponse)
async def upload_files(
    files: list[UploadFile] = File(..., description="待上传的文件"),
    folder_name: str = Form("upload", description="上传文件夹名称"),
):
    """上传文件到临时目录，返回目标路径供审计使用.

    支持:
    - 单个文件: 直接上传，返回文件所在目录路径
    - 多个文件: 统一保存到同一个临时目录
    - 文件夹: 前端通过 webkitRelativePath 保留目录结构

    返回的 target_path 可直接用于 POST /api/audit。
    """
    # 创建带时间戳的上传目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_name = "".join(c for c in folder_name if c.isalnum() or c in "._-")[:50]
    upload_dir = _UPLOAD_ROOT / f"{timestamp}_{sanitized_name}"
    upload_dir.mkdir(parents=True, exist_ok=True)

    saved_files = []
    loop = asyncio.get_running_loop()
    for f in files:
        # 保留相对路径结构（支持文件夹上传）
        rel_path = f.filename or "unknown"
        # 安全处理路径分隔符和路径穿越
        rel_path = rel_path.replace("\\", "/")
        if rel_path.startswith("/"):
            rel_path = rel_path[1:]
        # 防止路径穿越攻击
        rel_path = _os.path.normpath(rel_path)
        if rel_path.startswith(".."):
            rel_path = rel_path.lstrip("./")

        dest_path = upload_dir / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # 异步读取
        content = await f.read()
        # ★ 在线程池中执行磁盘 I/O，避免阻塞事件循环
        await loop.run_in_executor(None, lambda p=dest_path, c=content: _write_file(p, c))
        saved_files.append(str(dest_path.relative_to(upload_dir)))

    return UploadResponse(
        target_path=str(upload_dir.resolve()),
        file_count=len(saved_files),
        files=saved_files,
    )


@router.post("/audit", response_model=AuditResponse)
async def start_audit(req: AuditRequest):
    """启动安全审计 — 这是审计请求的主入口.

    接收目标路径、工具配置和用户需求，创建后台任务调用 AuditPipeline，
    返回 audit_id 供前端建立 SSE 连接。

    支持:
    - 目录路径: 递归扫描目录下所有文件
    - 文件路径: 仅审计单个文件
    - 上传目录: 通过 POST /api/audit/upload 获取的 target_path
    """
    import uuid

    audit_id = f"audit-{uuid.uuid4().hex[:8]}"

    event_queue: asyncio.Queue = asyncio.Queue()
    _audits[audit_id] = {
        "id": audit_id,
        "status": "running",
        "target": req.target,
        "tools": req.tools,
        "requirements": req.requirements,
        "events": [],
        "findings": [],
        "report": None,
        "event_queue": event_queue,
        "start_time": None,
    }

    # 后台启动审计流水线 (不阻塞响应)
    asyncio.create_task(_run_audit(audit_id, req))

    return AuditResponse(audit_id=audit_id, status="running")


@router.get("/audit/{audit_id}/stream")
async def stream_audit(audit_id: str):
    """SSE 实时事件流 — 推送审计进度到前端.

    事件类型:
    - event: phase    阶段开始/完成
    - event: finding  新漏洞发现
    - event: log      日志消息
    - event: done     审计完成
    - event: audit_error  审计异常
    """
    audit = _audits.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    async def event_generator():
        q: asyncio.Queue = audit["event_queue"]
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                )
                if event["type"] == "done":
                    break
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/audit/{audit_id}/report")
async def get_report(audit_id: str):
    """获取完整审计报告 (findings.json + REPORT.md)."""
    audit = _audits.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit["status"] == "running":
        return {
            "status": "running",
            "findings_so_far": len(audit["findings"]),
            "findings": audit["findings"],
        }
    return {
        "audit_id": audit_id,
        "status": audit["status"],
        "target": audit["target"],
        "report": audit["report"],
        "findings": audit["findings"],
    }


@router.get("/audit/{audit_id}/status")
async def get_status(audit_id: str):
    """查询审计任务状态."""
    audit = _audits.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return {
        "audit_id": audit_id,
        "status": audit["status"],
        "target": audit["target"],
        "tools": audit.get("tools", []),
        "findings_count": len(audit["findings"]),
    }


@router.get("/audits")
async def list_audits():
    """列出所有审计记录 (历史)."""
    return [
        {
            "audit_id": a["id"],
            "status": a["status"],
            "target": a["target"],
            "tools": a.get("tools", []),
            "findings_count": len(a["findings"]),
        }
        for a in _audits.values()
    ]


# ── Chat 存储 ────────────────────────────────────────────────

_chats: dict[str, dict] = {}
_agents: dict[str, object] = {}  # session_id -> Agent 实例，用于多轮对话
_MAX_SESSIONS = 20  # 最多保留的会话数


def _cleanup_old_sessions():
    """清理最旧的会话，防止内存泄漏."""
    if len(_agents) > _MAX_SESSIONS:
        # 按创建时间排序，删除最旧的
        excess = len(_agents) - _MAX_SESSIONS
        old_keys = sorted(_agents.keys())[:excess]
        for k in old_keys:
            del _agents[k]
    if len(_chats) > _MAX_SESSIONS * 2:
        excess = len(_chats) - _MAX_SESSIONS * 2
        old_keys = sorted(_chats.keys())[:excess]
        for k in old_keys:
            del _chats[k]


# ── 内部: 运行 LLM Agent 对话 ──────────────────────────────

async def _run_chat(chat_id: str, message: str, target: str = "", session_id: str = ""):
    """在后台运行 CoreCoder Agent，将响应推送到 SSE 队列.

    核心设计:
    - ★ 智能预读: 从用户需求中提取文件名 → 在目标目录中找到并预读
    - ★ 多轮对话: 同一 session_id 复用 Agent 实例，保留上下文
    - ★ 内存保护: 自动清理超过 20 个会话的旧 Agent
    - ★ Token 批量推送: 50ms/20token 批次，减少跨线程调度开销
    - ★ 超时保护: asyncio.wait_for(timeout=120)
    """
    import re as _re

    chat = _chats.get(chat_id)
    if not chat:
        return
    q: asyncio.Queue = chat["event_queue"]

    # 确保 session_id 与 chat 关联
    actual_session_id = session_id or chat.get("session_id", "") or chat_id

    try:
        # ── 步骤1: 解析目标路径 ──
        project_root = Path(__file__).resolve().parents[2]
        abs_target_dir = None  # 绝对目标目录
        pre_read_contents = []  # [(relative_name, absolute_path, content), ...]
        remaining_files = []    # 未预读的文件名列表
        has_specific_files = False  # ★ 用户是否指定了特定文件（用于约束审计范围）

        if target:
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = (project_root / target_path).resolve()

            if target_path.is_file():
                # 单文件: 直接预读 → 用户精确指定了此文件
                abs_target_dir = target_path.parent
                has_specific_files = True
                try:
                    content = target_path.read_text(encoding="utf-8", errors="replace")
                    max_len = 12000
                    if len(content) > max_len:
                        content = content[:max_len] + "\n/* ... (文件截断) ... */"
                    pre_read_contents.append((
                        target_path.name,
                        str(target_path),
                        content,
                    ))
                    await q.put({
                        "type": "log",
                        "message": f"📄 已预读: {target_path.name} ({len(content)} 字符)",
                    })
                except Exception as e:
                    await q.put({
                        "type": "log",
                        "message": f"⚠️ 预读失败: {e}",
                    })

            elif target_path.is_dir():
                abs_target_dir = target_path
                # 收集目录中所有源文件
                code_extensions = {'.c', '.h', '.cpp', '.hpp', '.py', '.js', '.ts',
                                   '.jsx', '.tsx', '.java', '.go', '.rs', '.php',
                                   '.rb', '.swift', '.kt', '.yaml', '.yml', '.json',
                                   '.xml', '.toml', '.ini', '.cfg', '.conf', '.sh',
                                   '.bash', '.env', '.txt', '.md'}
                all_files = sorted(
                    f for f in target_path.rglob("*")
                    if f.is_file()
                    and not f.name.startswith(".")
                    and (f.suffix in code_extensions or not f.suffix)
                )

                # ── 智能预读: 从用户需求中提取提到的文件名 ──
                mentioned_names = set()
                for pattern in [r'\b([\w\-]+\.\w{1,10})\b']:
                    for m in _re.finditer(pattern, message):
                        mentioned_names.add(m.group(1).lower())

                # 分类: 提到的文件优先预读
                to_pre_read = []
                to_list = []
                for f in all_files:
                    if f.name.lower() in mentioned_names:
                        to_pre_read.append(f)
                    else:
                        to_list.append(f)

                # ★ 修复 Bug 2: 如果用户明确提到了特定文件，只预读这些文件，
                # 不要因为"目录很小"就预读所有文件
                has_specific_files = bool(mentioned_names and to_pre_read)
                if not has_specific_files:
                    # 没有指定文件 → 如果目录很小 (≤8 文件, <30KB)，直接全部预读
                    total_size = sum(f.stat().st_size for f in all_files)
                    if len(all_files) <= 8 and total_size < 30000:
                        to_pre_read = all_files
                        to_list = []

                # 预读文件内容
                for f in to_pre_read:
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        max_len = 10000
                        if len(content) > max_len:
                            content = content[:max_len] + "\n/* ... (截断) ... */"
                        pre_read_contents.append((
                            str(f.relative_to(target_path)),
                            str(f),
                            content,
                        ))
                    except Exception:
                        to_list.append(f)

                if pre_read_contents:
                    names = ", ".join(n for n, _, _ in pre_read_contents)
                    await q.put({
                        "type": "log",
                        "message": f"📄 已预读 {len(pre_read_contents)} 个文件: {names}",
                    })
                if to_list:
                    remaining_files = [str(f.relative_to(target_path)) for f in to_list]

        # ★ 增强提示：强调必须使用绝对路径，避免 CWD 依赖
        path_prefix_hint = ""
        if abs_target_dir:
            # 将 Path 对象转为规范化的绝对路径字符串（统一使用正斜杠）
            abs_dir_str = str(abs_target_dir).replace("\\", "/")
            path_prefix_hint = (
                f"\n> ⚠️ **重要**: 所有工具参数中的文件路径必须使用绝对路径。\n"
                f"> 工作目录: `{abs_dir_str}`\n"
                f"> 正确示例: `c_review(file_path=\"{abs_dir_str}/auth.c\")`\n"
                f"> 错误示例: `c_review(file_path=\"auth.c\")`\n"
            )

        # ── 步骤2: 构造消息 (根据实际预读内容决定指令) ──
        has_code = bool(pre_read_contents)

        # 构建代码块
        code_blocks = ""
        for rel_name, abs_path, content in pre_read_contents:
            code_blocks += (
                f"\n### 文件: {rel_name}\n"
                f"路径: {abs_path}\n"
                f"```\n{content}\n```\n"
            )

        # 构建剩余文件提示
        remaining_hint = ""
        if remaining_files:
            if len(remaining_files) <= 10:
                remaining_hint = (
                    f"\n> 目标目录内其他文件: {', '.join(remaining_files)}\n"
                    f"> 如需审查这些文件，请用 read_file 读取。\n"
                )
            else:
                remaining_hint = (
                    f"\n> 目标目录内还有 {len(remaining_files)} 个其他文件。\n"
                    f"> 如需审查，请用 read_file 读取。\n"
                )

        # 审计工具提示: 文件已在消息中时用绝对路径，否则让 Agent 自己读
        if has_code:
            # ★ 修复 Bug 2: 如果用户指定了特定文件，约束审计范围
            scope_constraint = ""
            if has_specific_files:
                mentioned = ", ".join(n for n, _, _ in pre_read_contents)
                scope_constraint = (
                    f"⚠️ **范围限制**: 用户仅要求审计 `{mentioned}`。"
                    f"请只对以上文件调用审计工具，不要审计其他文件。\n\n"
                )

            # ★ 修复 Bug 1: 添加意图→工具匹配提示（中文关键词映射）
            tool_match_hint = (
                f"🔧 **工具选择**: 请先分析用户需求中的关键词，只选择匹配的审计工具:\n"
                f"  - 默认配置/硬编码/调试模式/默认密码/配置问题 → 只需 **insecure_defaults**\n"
                f"  - 内存安全/缓冲区溢出/UAF/空指针/格式化字符串 → 只需 **c_review**\n"
                f"  - 注入/SQL注入/XSS/命令注入/路径穿越 → 只需 **injection_scanner**\n"
                f"  - 综合审计(无特定类型) → 可调用多个工具\n"
                f"  不要调用所有工具，只调用与用户需求匹配的工具。\n\n"
            )

            tool_hint = (
                f"目标根目录: {abs_target_dir}\n\n"
                f"{tool_match_hint}"
                f"{scope_constraint}"
                f"调用审计工具时请使用上面的绝对路径，例如:\n"
                f"  c_review(file_path=\"{pre_read_contents[0][1]}\")\n"
                f"  insecure_defaults(file_path=\"{pre_read_contents[0][1]}\")\n"
            )
            full_message = (
                f"## 审计任务\n\n"
                f"**用户需求**: {message}\n\n"
                f"**目标**: {target}\n"
                f"{tool_hint}\n"
                f"---\n"
                f"## 目标文件代码 (已预读，无需再调用 read_file)\n"
                f"{code_blocks}"
                f"{remaining_hint}"
                f"---\n"
                f"请分析以上代码，调用合适的审计工具进行安全检测，"
                f"然后给出综合审计结论、漏洞列表和修复建议。"
                f"{path_prefix_hint}"
            )
        elif abs_target_dir:
            # 没有预读到代码: 告诉 Agent 自己读
            file_list_str = "\n".join(f"  - {f}" for f in remaining_files[:20]) if remaining_files else "(空目录)"

            # ★ 修复 Bug 1: 添加意图→工具匹配提示
            tool_match_hint = (
                f"🔧 **工具选择**: 请先分析用户需求中的关键词，只选择匹配的审计工具:\n"
                f"  - 默认配置/硬编码/调试模式/默认密码/配置问题 → 只需 **insecure_defaults**\n"
                f"  - 内存安全/缓冲区溢出/UAF/空指针/格式化字符串 → 只需 **c_review**\n"
                f"  - 注入/SQL注入/XSS/命令注入/路径穿越 → 只需 **injection_scanner**\n"
                f"  - 综合审计(无特定类型) → 可调用多个工具\n"
                f"  不要调用所有工具，只调用与用户需求匹配的工具。\n\n"
            )

            # ★ 修复 Bug 2: 如果用户指定了特定文件，约束审计范围
            scope_constraint = ""
            if has_specific_files and remaining_files:
                mentioned_files = [f for f in remaining_files if any(
                    f.lower().endswith(name) for name in mentioned_names
                )] if 'mentioned_names' in dir() else []
                if mentioned_files:
                    scope_constraint = (
                        f"⚠️ **范围限制**: 用户仅要求审计 `{', '.join(mentioned_files)}`。"
                        f"请只读取和审计这些文件。\n\n"
                    )

            full_message = (
                f"## 审计任务\n\n"
                f"**用户需求**: {message}\n\n"
                f"**目标目录**: {abs_target_dir}\n"
                f"**目录内容**:\n{file_list_str}\n\n"
                f"{tool_match_hint}"
                f"{scope_constraint}"
                f"---\n"
                f"请首先使用 read_file 读取需要分析的文件（使用上面的绝对路径），"
                f"然后调用审计工具(c_review/insecure_defaults/injection_scanner)进行检测，"
                f"最后给出综合审计结论和修复建议。"
                f"{path_prefix_hint}"
            )
        else:
            full_message = message

        # ── 步骤3: 读取 LLM 配置 ──
        config = _load_llm_config()

        if not config["api_key"]:
            await q.put({
                "type": "chat_error",
                "message": "LLM API key not configured. Set OPENAI_API_KEY or CORECODER_API_KEY environment variable.",
            })
            await q.put({"type": "done", "content": ""})
            return

        from corecoder.llm import LLM
        from corecoder.agent import Agent

        # ★ 多轮对话: 同一 session 复用 Agent，保留消息历史
        use_existing = actual_session_id in _agents
        if use_existing:
            agent = _agents[actual_session_id]
            await q.put({
                "type": "log",
                "message": f"🤖 继续对话 (model: {config['model']}, session: {actual_session_id[:12]}...)",
            })
        else:
            llm = LLM(
                model=config["model"],
                api_key=config["api_key"],
                base_url=config.get("base_url"),
                max_tokens=config.get("max_tokens", 4096),
                temperature=config.get("temperature", 0.0),
            )
            agent = Agent(llm=llm, max_rounds=8)
            _agents[actual_session_id] = agent
            _cleanup_old_sessions()
            await q.put({
                "type": "log",
                "message": f"🤖 CoreCoder Agent 启动 (model: {config['model']})",
            })

        await q.put({
            "type": "log",
            "message": f"💬 {message[:200]}",
        })

        # ── 步骤4: 在线程中运行 agent.chat() ──
        main_loop = asyncio.get_running_loop()

        def _run_sync():
            import time as _time
            import os as _os_module

            # ★ 关键修复: 切换 CWD 到项目根目录
            # uvicorn 从 web/backend/ 启动，工具使用相对路径从 CWD 解析
            # 同一进程内所有线程都需要 project_root 作为 CWD
            # 不恢复旧 CWD，因为所有线程目标相同，不会有竞态
            _os_module.chdir(str(project_root))

            content_parts = []

            class _TokenBatcher:
                def __init__(self):
                    self.buffer = []
                    self.last_flush = _time.monotonic()

                def add(self, token: str):
                    self.buffer.append(token)
                    now = _time.monotonic()
                    if len(self.buffer) >= 20 or (now - self.last_flush) >= 0.05:
                        self._do_flush()
                        self.last_flush = now

                def _do_flush(self):
                    if self.buffer:
                        batch = "".join(self.buffer)
                        self.buffer.clear()
                        asyncio.run_coroutine_threadsafe(
                            q.put({"type": "token", "content": batch}),
                            main_loop,
                        )

                def flush(self):
                    self._do_flush()

            batcher = _TokenBatcher()

            def on_token(token: str):
                content_parts.append(token)
                batcher.add(token)

            def on_tool(tool_name: str, tool_args: dict):
                args_short = {k: str(v)[:100] for k, v in tool_args.items()}
                # ★ 关键: 当 Agent 调用 generate_docx_report 时，将 report content
                # 存储到 chat 字典中，供后续的下载/预览端点使用。
                # 如果不捕获，chat["content"] 只会是 Agent 的最终文本回复
                # （如 "✅ Word 报告已生成！"），而不是实际报告内容。
                if tool_name == "generate_docx_report" and "content" in tool_args:
                    report_content = tool_args["content"]
                    if report_content and len(report_content) > 50:
                        chat["report_content"] = report_content
                # 推送工具调用事件给前端展示
                asyncio.run_coroutine_threadsafe(
                    q.put({
                        "type": "tool_call",
                        "tool": tool_name,
                        "arguments": args_short,
                    }),
                    main_loop,
                )
                # 同时推送日志
                asyncio.run_coroutine_threadsafe(
                    q.put({
                        "type": "log",
                        "message": f"🔧 调用工具: {tool_name}({', '.join(f'{k}={v}' for k, v in args_short.items())})",
                    }),
                    main_loop,
                )

            try:
                result = agent.chat(full_message, on_token=on_token, on_tool=on_tool)
                batcher.flush()
                return result, "".join(content_parts)
            except Exception as e:
                import traceback
                traceback.print_exc()
                batcher.flush()
                return f"Error: {e}", "".join(content_parts)

        # 超时保护
        result_text, streamed_content = await asyncio.wait_for(
            asyncio.to_thread(_run_sync),
            timeout=120,
        )

        display_text = streamed_content or result_text
        # 存储最终内容供报告下载
        chat["content"] = display_text
        await q.put({
            "type": "log",
            "message": "✅ Agent 分析完成",
        })
        await q.put({
            "type": "done",
            "content": display_text,
        })

    except asyncio.TimeoutError:
        await q.put({
            "type": "chat_error",
            "message": "Agent 执行超时 (120s)，请尝试减少审计范围或简化需求。",
        })
        await q.put({"type": "done", "content": ""})
    except Exception as e:
        import traceback
        traceback.print_exc()
        await q.put({
            "type": "chat_error",
            "message": f"Agent 执行失败: {str(e)}",
        })
        await q.put({"type": "done", "content": ""})
    finally:
        chat["status"] = "completed"


def _load_llm_config() -> dict:
    """从环境变量加载 LLM 配置（含 .env 文件）。

    与 corecoder.config.Config.from_env() 保持一致，
    确保终端 CLI 和 Web 后端使用相同的 LLM 配置来源。
    """
    import os

    # ★ 关键: 加载 .env 文件 (终端 CLI 也这样做)
    try:
        from dotenv import load_dotenv
        from pathlib import Path as _Path
        env_path = _Path(".env")
        if not env_path.exists():
            cur = _Path.cwd()
            home = _Path.home()
            while cur != home and cur != cur.parent:
                candidate = cur / ".env"
                if candidate.exists():
                    env_path = candidate
                    break
                cur = cur.parent
        load_dotenv(env_path, override=False)
    except ImportError:
        pass

    return {
        "model": os.getenv("CORECODER_MODEL", "gpt-5.5"),
        "api_key": (
            os.getenv("CORECODER_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY")
            or ""
        ),
        "base_url": os.getenv("OPENAI_BASE_URL") or os.getenv("CORECODER_BASE_URL"),
        "max_tokens": int(os.getenv("CORECODER_MAX_TOKENS", "4096")),
        "temperature": float(os.getenv("CORECODER_TEMPERATURE", "0")),
    }


# ── Chat API 路由 ────────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse)
async def start_chat(req: ChatRequest):
    """启动 LLM Agent 对话 — 前端对话式审计入口.

    将用户自然语言消息发送给 CoreCoder Agent (LLM)，
    Agent 会自主决定调用哪些工具（read_file / c_review / insecure_defaults 等），
    结果通过 SSE 实时流式推送前端。

    支持多轮对话: 传入 session_id 可复用之前的 Agent 上下文。

    与 POST /api/audit (纯正则 Pipeline) 的区别:
    - /api/audit: 快速正则扫描，无 LLM 参与
    - /api/chat:  LLM Agent 理解意图 → 调用工具 → 分析代码 → 综合结论
    """
    import uuid

    chat_id = f"chat-{uuid.uuid4().hex[:8]}"
    session_id = req.session_id or chat_id  # 新会话用 chat_id 作为 session_id

    event_queue: asyncio.Queue = asyncio.Queue()
    _chats[chat_id] = {
        "id": chat_id,
        "status": "running",
        "message": req.message,
        "target": req.target,
        "session_id": session_id,
        "events": [],
        "event_queue": event_queue,
    }

    _cleanup_old_sessions()

    # 用 asyncio.create_task 在事件循环中调度 _run_chat
    asyncio.create_task(_run_chat(chat_id, req.message, req.target, session_id))

    return ChatResponse(chat_id=chat_id, status="running", session_id=session_id)


@router.get("/chat/{chat_id}/report")
async def get_chat_report(chat_id: str, format: str = "docx"):
    """获取 Agent 对话报告，支持 Word (.docx) 格式下载.

    用法:
        GET /api/chat/{chat_id}/report?format=docx

    ★ 报告内容优先级:
    1. chat["report_content"] — generate_docx_report 工具调用时捕获的实际报告内容
    2. chat["content"] — Agent 的最终文本回复（降级方案）

    如果只有 chat["content"]（Agent 的 "✅ Word 报告已生成！" 回复），
    则尝试在同 session 的其他 chat 中查找更早的分析报告内容。

    Args:
        chat_id: 对话 ID
        format: 输出格式 (docx | md)
    """
    chat = _chats.get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat session not found")

    # ★ 优先使用工具调用时捕获的报告内容，其次当前 chat 的文本回复
    content = chat.get("report_content", "") or chat.get("content", "")

    # ★ 降级方案: 如果当前 chat 内容太短（只是成功消息），
    # 在同 session 的其他 chat 中查找更长的分析报告内容
    session_id = chat.get("session_id", "")
    if (not content or len(content) < 200) and session_id:
        for cid, c in _chats.items():
            if cid == chat_id:
                continue
            if c.get("session_id") == session_id:
                alt_content = c.get("content", "")
                if len(alt_content) > len(content):
                    content = alt_content

    if not content:
        raise HTTPException(status_code=400, detail="No content available yet. Agent may still be running.")

    if format == "md":
        # 直接返回 Markdown 文本
        return StreamingResponse(
            iter([content.encode("utf-8")]),
            media_type="text/markdown",
            headers={
                "Content-Disposition": f"attachment; filename=SECURITY_REPORT_{chat_id}.md",
            },
        )

    # format == "docx": 生成 Word 文档
    import io as _io

    # ★ 在线程池中执行 docx 生成，避免阻塞事件循环
    # python-docx 的 XML 处理是 CPU 密集型操作，大报告可能需要数秒
    loop = asyncio.get_running_loop()
    try:
        docx_bytes = await loop.run_in_executor(
            None, _generate_security_report_docx, content, chat,
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate Word report: {str(e)}",
        )

    return StreamingResponse(
        _io.BytesIO(docx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f"attachment; filename=SECURITY_REPORT_{chat_id}.docx",
        },
    )


def _generate_security_report_docx(markdown_content: str, chat: dict) -> bytes:
    """将 Agent 响应的 Markdown 内容转换为 Word 文档.

    解析规则:
    - # 标题 → Heading 1 (报告标题)
    - ## 标题 → Heading 2 (章节标题)
    - ### 标题 → Heading 3 (子章节)
    - **粗体** → 粗体 inline
    - ```代码块``` → 等宽字体段落
    - | 表格 | → Word 表格
    - 普通段落 → 正文段落
    - --- → 分节线
    """
    import re
    from docx import Document
    from docx.shared import Pt, Inches, Cm, RGBColor
    from docx.enum.text import WD_PARAGRAPH_ALIGNMENT, WD_LINE_SPACING
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    doc = Document()

    # ── 页面设置 ──
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.left_margin = Cm(2.5)
    section.right_margin = Cm(2.5)
    section.top_margin = Cm(2.5)
    section.bottom_margin = Cm(2.5)

    # ── 默认样式（统一西文 + 东亚字体）──
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)
    style.paragraph_format.line_spacing_rule = WD_LINE_SPACING.MULTIPLE
    style.paragraph_format.line_spacing = 1.5
    # 为 Normal 样式设置东亚字体
    style_rPr = style.element.get_or_add_rPr()
    style_rFonts = style_rPr.find(qn('w:rFonts'))
    if style_rFonts is None:
        style_rFonts = OxmlElement('w:rFonts')
        style_rPr.insert(0, style_rFonts)
    style_rFonts.set(qn('w:ascii'), 'Calibri')
    style_rFonts.set(qn('w:hAnsi'), 'Calibri')
    style_rFonts.set(qn('w:eastAsia'), '微软雅黑')
    style_rFonts.set(qn('w:cs'), 'Calibri')

    def set_font(run, name="Calibri", size=11, bold=False, color=None, mono=False):
        """设置 run 字体属性（含西文 + 东亚字体一致性）."""
        western_font = "Consolas" if mono else name
        _set_run_rfonts(run, western_font)
        run.font.size = Pt(size)
        run.bold = bold
        if color:
            run.font.color.rgb = RGBColor(*color)

    def add_styled_paragraph(text, font_name="Calibri", size=11, bold=False, color=None,
                              alignment=None, space_after=6, mono=False):
        """添加带样式的段落."""
        para = doc.add_paragraph()
        run = para.add_run(text)
        set_font(run, font_name, size, bold, color, mono)
        if alignment is not None:
            para.alignment = alignment
        para.paragraph_format.space_after = Pt(space_after)
        return para

    # ── 解析 Markdown ──
    lines = markdown_content.split("\n")
    i = 0
    in_code_block = False
    code_lines = []
    code_lang = ""

    while i < len(lines):
        line = lines[i]

        # 代码块处理
        if line.strip().startswith("```"):
            if in_code_block:
                # 结束代码块
                code_text = "\n".join(code_lines)
                if code_text.strip():
                    # 添加代码块背景段落
                    para = doc.add_paragraph()
                    para.paragraph_format.space_before = Pt(6)
                    para.paragraph_format.space_after = Pt(6)
                    para.paragraph_format.left_indent = Cm(0.5)
                    run = para.add_run(code_text)
                    set_font(run, mono=True, size=9, color=(50, 50, 50))
                code_lines = []
                in_code_block = False
            else:
                # 开始代码块
                in_code_block = True
                code_lang = line.strip()[3:].strip()
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # 空行
        if not line.strip():
            i += 1
            continue

        stripped = line.strip()

        # ── 标题 ──
        if stripped.startswith("# ") and not stripped.startswith("## "):
            text = stripped[2:]
            add_styled_paragraph(text, size=22, bold=True, color=(30, 41, 59),
                                  alignment=WD_PARAGRAPH_ALIGNMENT.CENTER, space_after=12)
            # 标题下划线
            para = doc.add_paragraph()
            para.paragraph_format.space_after = Pt(16)
            run = para.add_run("─" * 50)
            set_font(run, size=8, color=(180, 180, 180))

        elif stripped.startswith("## "):
            text = stripped[3:]
            add_styled_paragraph(text, size=16, bold=True, color=(30, 41, 59), space_after=8)

        elif stripped.startswith("### "):
            text = stripped[4:]
            add_styled_paragraph(text, size=13, bold=True, color=(51, 65, 85), space_after=6)

        elif stripped.startswith("#### "):
            text = stripped[5:]
            add_styled_paragraph(text, size=12, bold=True, color=(71, 85, 105), space_after=4)

        # ── 水平线 ──
        elif stripped in ("---", "***", "___"):
            para = doc.add_paragraph()
            para.paragraph_format.space_before = Pt(8)
            para.paragraph_format.space_after = Pt(8)
            run = para.add_run("─" * 60)
            set_font(run, size=8, color=(200, 200, 200))

        # ── 表格 ──
        elif stripped.startswith("|") and stripped.endswith("|"):
            # 收集表格行
            table_rows = []
            while i < len(lines) and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
                row_line = lines[i].strip()
                # 跳过分隔行 (| --- | --- |)
                if not re.match(r'^\|[\s\-:]+\|', row_line):
                    cells = [c.strip() for c in row_line[1:-1].split("|")]
                    table_rows.append(cells)
                i += 1

            if table_rows:
                num_cols = max(len(r) for r in table_rows)
                table = doc.add_table(rows=len(table_rows), cols=num_cols)
                table.style = "Table Grid"
                table.alignment = WD_TABLE_ALIGNMENT.CENTER

                for r_idx, row_data in enumerate(table_rows):
                    for c_idx, cell_text in enumerate(row_data):
                        if c_idx < num_cols:
                            cell = table.rows[r_idx].cells[c_idx]
                            cell.text = ""
                            para = cell.paragraphs[0]
                            run = para.add_run(cell_text)
                            if r_idx == 0:
                                set_font(run, size=10, bold=True, color=(255, 255, 255))
                                # 表头背景色
                                shading = OxmlElement("w:shd")
                                shading.set(qn("w:fill"), "4472C4")
                                shading.set(qn("w:val"), "clear")
                                cell._tc.get_or_add_tcPr().append(shading)
                            else:
                                set_font(run, size=10)
                                if r_idx % 2 == 0:
                                    shading = OxmlElement("w:shd")
                                    shading.set(qn("w:fill"), "F2F6FC")
                                    shading.set(qn("w:val"), "clear")
                                    cell._tc.get_or_add_tcPr().append(shading)
                doc.add_paragraph()  # 表格后空行
            continue

        # ── 列表项 ──
        elif re.match(r'^[\s]*[\-\*\d+\.]\s', stripped):
            text = re.sub(r'^[\s]*[\-\*\d+\.]\s+', '', stripped)
            para = doc.add_paragraph()
            para.paragraph_format.left_indent = Cm(1.0)
            para.paragraph_format.space_after = Pt(3)
            # 解析 inline markdown
            _add_inline_markdown(para, text)
            i += 1
            continue

        # ── 引用块 ──
        elif stripped.startswith("> "):
            text = stripped[2:]
            para = doc.add_paragraph()
            para.paragraph_format.left_indent = Cm(1.0)
            para.paragraph_format.space_after = Pt(4)
            run = para.add_run(text)
            set_font(run, size=10, color=(100, 100, 100))
            i += 1
            continue

        # ── 普通段落 (支持 inline 粗体/斜体/代码) ──
        else:
            para = doc.add_paragraph()
            para.paragraph_format.space_after = Pt(6)
            _add_inline_markdown(para, stripped)
            i += 1

    # ── 页脚: 添加页码 ──
    for section in doc.sections:
        footer = section.footer
        footer.is_linked_to_previous = False
        para = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        para.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
        run = para.add_run("— ")
        set_font(run, size=9, color=(150, 150, 150))
        # 页码字段
        fld_char_begin = OxmlElement("w:fldChar")
        fld_char_begin.set(qn("w:fldCharType"), "begin")
        run._r.append(fld_char_begin)
        instr_text = OxmlElement("w:instrText")
        instr_text.set(qn("xml:space"), "preserve")
        instr_text.text = "PAGE"
        run._r.append(instr_text)
        fld_char_end = OxmlElement("w:fldChar")
        fld_char_end.set(qn("w:fldCharType"), "end")
        run._r.append(fld_char_end)
        run2 = para.add_run(" —")
        set_font(run2, size=9, color=(150, 150, 150))

    # ── 保存到内存 ──
    import io
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()


def _set_run_rfonts(run, western_font: str, ea_font: str = "微软雅黑"):
    """设置 docx Run 的西文和东亚字体（通过 w:rFonts XML 确保中英文一致）."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    rPr = run._r.get_or_add_rPr()
    rFonts = rPr.find(qn('w:rFonts'))
    if rFonts is None:
        rFonts = OxmlElement('w:rFonts')
        rPr.insert(0, rFonts)
    rFonts.set(qn('w:ascii'), western_font)
    rFonts.set(qn('w:hAnsi'), western_font)
    rFonts.set(qn('w:eastAsia'), ea_font)
    rFonts.set(qn('w:cs'), western_font)
    run.font.name = western_font


def _add_inline_markdown(para, text: str):
    """解析 inline markdown (粗体/斜体/代码) 并添加到段落."""
    import re
    from docx.shared import Pt

    # 匹配: **粗体**, *斜体*, `代码`
    pattern = re.compile(
        r'(\*\*(.+?)\*\*)|'       # **粗体**
        r'(\*(.+?)\*)|'           # *斜体*
        r'(`(.+?)`)'              # `代码`
    )

    last_end = 0
    for match in pattern.finditer(text):
        # 前面的普通文本
        prefix = text[last_end:match.start()]
        if prefix:
            run = para.add_run(prefix)
            run.font.size = Pt(11)
            _set_run_rfonts(run, "Calibri")

        if match.group(1):  # 粗体
            run = para.add_run(match.group(2))
            run.font.size = Pt(11)
            run.bold = True
            _set_run_rfonts(run, "Calibri")
        elif match.group(3):  # 斜体
            run = para.add_run(match.group(4))
            run.font.size = Pt(11)
            run.italic = True
            _set_run_rfonts(run, "Calibri")
        elif match.group(5):  # 代码
            run = para.add_run(match.group(6))
            run.font.size = Pt(9.5)
            _set_run_rfonts(run, "Consolas")

        last_end = match.end()

    # 剩余文本
    suffix = text[last_end:]
    if suffix:
        run = para.add_run(suffix)
        run.font.size = Pt(11)
        _set_run_rfonts(run, "Calibri")


# ── Chat Stream 路由 ──────────────────────────────────────────

@router.get("/chat/{chat_id}/stream")
async def stream_chat(chat_id: str):
    """SSE 实时流 — 推送 Agent 对话进度到前端.

    事件类型:
    - event: log       日志消息 (Agent 启动、进度等)
    - event: tool_call 工具调用 (tool + arguments)
    - event: token     LLM 生成的文本内容
    - event: done      对话完成
    - event: chat_error 对话异常
    """
    chat = _chats.get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat session not found")

    async def event_generator():
        q: asyncio.Queue = chat["event_queue"]
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                )
                if event["type"] == "done":
                    break
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
