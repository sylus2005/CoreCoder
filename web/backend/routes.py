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
    for f in files:
        # 保留相对路径结构（支持文件夹上传）
        rel_path = f.filename or "unknown"
        # 安全处理路径分隔符
        rel_path = rel_path.replace("\\", "/")
        if rel_path.startswith("/"):
            rel_path = rel_path[1:]

        dest_path = upload_dir / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # 异步读取并写入
        content = await f.read()
        with open(dest_path, "wb") as dest:
            dest.write(content)
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


# ── 内部: 运行 LLM Agent 对话 ──────────────────────────────

async def _run_chat(chat_id: str, message: str, target: str = ""):
    """在后台运行 CoreCoder Agent，将响应推送到 SSE 队列.

    核心设计:
    - ★ 智能预读: 从用户需求中提取文件名 → 在目标目录中找到并预读
    - ★ 小目录全预读: ≤8 文件且 <30KB 时全部预读，Agent 无需 read_file
    - ★ 绝对路径: 预读时使用绝对路径，解决 uvicorn CWD ≠ 项目根的问题
    - ★ 不撒谎: 只有真正预读了代码时才说"不需要 read_file"
    - ★ Token 批量推送: 50ms/20token 批次，减少跨线程调度开销
    - ★ 超时保护: asyncio.wait_for(timeout=120)
    """
    import re as _re

    chat = _chats.get(chat_id)
    if not chat:
        return
    q: asyncio.Queue = chat["event_queue"]

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

        await q.put({
            "type": "log",
            "message": f"🤖 CoreCoder Agent 启动 (model: {config['model']})",
        })

        from corecoder.llm import LLM
        from corecoder.agent import Agent

        llm = LLM(
            model=config["model"],
            api_key=config["api_key"],
            base_url=config.get("base_url"),
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.0),
        )

        agent = Agent(llm=llm, max_rounds=8)

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
            # uvicorn 从 web/backend/ 启动，CWD 是 web/backend/
            # 但工具 (read_file, c_review, insecure_defaults) 使用 open(file_path)
            # 相对路径从 CWD 解析 → 全部 404 → Agent 重试 → 超时
            _old_cwd = _os_module.getcwd()
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
            finally:
                # 恢复原始 CWD
                _os_module.chdir(_old_cwd)

        # 超时保护
        result_text, streamed_content = await asyncio.wait_for(
            asyncio.to_thread(_run_sync),
            timeout=120,
        )

        display_text = streamed_content or result_text
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

    与 POST /api/audit (纯正则 Pipeline) 的区别:
    - /api/audit: 快速正则扫描，无 LLM 参与
    - /api/chat:  LLM Agent 理解意图 → 调用工具 → 分析代码 → 综合结论
    """
    import uuid

    chat_id = f"chat-{uuid.uuid4().hex[:8]}"

    event_queue: asyncio.Queue = asyncio.Queue()
    _chats[chat_id] = {
        "id": chat_id,
        "status": "running",
        "message": req.message,
        "target": req.target,
        "session_id": req.session_id,
        "events": [],
        "event_queue": event_queue,
    }

    # 用 asyncio.create_task 在事件循环中调度 _run_chat
    # (_run_chat 内部会用 asyncio.to_thread 处理阻塞的 LLM 调用)
    asyncio.create_task(_run_chat(chat_id, req.message, req.target))

    return ChatResponse(chat_id=chat_id, status="running")


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
