"""三阶段安全审计流水线编排器.

简化自 Cloudflare security-audit-skill 的六阶段流水线:

    Phase 1 Recon ──→ Phase 2 Hunt ──→ Phase 3 Report
    (1 Agent 侦察)    (3 Agent 并行)   (1 Agent 报告)

设计原则 (来自 Cloudflare):
    - 只报告可利用的漏洞（有具体的攻击场景）
    - 严重性 = 可能性 × 影响
    - 多个 Agent 并行工作，结果汇总去重
    - SSE 事件流实时推送进度到前端

用法:
    import asyncio
    from corecoder.llm import LLM
    from corecoder.tools.security.pipeline import AuditPipeline

    llm = LLM(api_key="...", base_url="...", model="...")
    pipeline = AuditPipeline(llm=llm)

    async for event in pipeline.run("./demo/vulnerable-utils/"):
        print(event)  # 或推送到 SSE
"""

import asyncio
import json
import os
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field

from . import _reset_counter
from .schema import build_metadata
from .report import ReportGenerator


@dataclass
class AuditConfig:
    """审计配置."""

    target: str = "."
    tools: list[str] = field(
        default_factory=lambda: ["c_review", "insecure_defaults", "injection_scanner"]
    )
    file_extensions: list[str] = field(default_factory=lambda: [".c", ".h", ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb", ".yaml", ".yml", ".json", ".env", "Dockerfile", ".conf", ".cfg"])
    exclude_dirs: list[str] = field(default_factory=lambda: [".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist", ".claude", "skills"])
    model: str = ""


class AuditPipeline:
    """三阶段安全审计流水线.

    协调 Recon → Hunt → Report 三个阶段，通过 SSE 事件向前端推送实时进度.
    """

    def __init__(self, llm=None, config: AuditConfig | None = None):
        """
        Args:
            llm: CoreCoder LLM 实例 (可选，MVP 阶段正则规则不依赖 LLM)
            config: 审计配置
        """
        self.llm = llm
        self.config = config or AuditConfig()
        self.findings: list[dict] = []
        self._event_handlers: list[callable] = []
        self._start_time: float = 0.0

    def on_event(self, handler):
        """注册事件处理器."""
        self._event_handlers.append(handler)

    async def _emit(self, event_type: str, data: dict):
        """向所有注册的处理器发送事件."""
        event = {"type": event_type, **data}
        for handler in self._event_handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)
        return event

    async def run(self, target: str | None = None) -> AsyncGenerator[dict, None]:
        """执行完整的审计流水线.

        Args:
            target: 审计目标目录，覆盖配置中的 target

        Yields:
            每个 SSE 事件字典
        """
        if target:
            self.config.target = target

        _reset_counter()
        self.findings = []
        self._start_time = time.time()

        # === Phase 1: Recon ===
        yield await self._emit("phase", {
            "phase": "recon",
            "status": "started",
            "message": "🔍 Phase 1/3: 项目侦察...",
        })

        context = await self._phase_recon(self.config.target)

        yield await self._emit("phase", {
            "phase": "recon",
            "status": "done",
            "context": context,
            "message": self._format_recon_summary(context),
        })

        # === Phase 2: Hunt ===
        yield await self._emit("phase", {
            "phase": "hunt",
            "status": "started",
            "message": f"⚔️ Phase 2/3: 漏洞狩猎 (启用 {len(self.config.tools)} 个 Tool)...",
        })

        files = self._collect_files(self.config.target)
        yield await self._emit("log", {
            "message": f"发现 {len(files)} 个待扫描文件",
        })

        # 并行执行 3 个 Tool
        async for finding in self._phase_hunt(files):
            self.findings.append(finding)

        yield await self._emit("phase", {
            "phase": "hunt",
            "status": "done",
            "count": len(self.findings),
            "message": f"狩猎完成: 发现 {len(self.findings)} 个潜在漏洞",
        })

        # === Phase 3: Report ===
        yield await self._emit("phase", {
            "phase": "report",
            "status": "started",
            "message": "📝 Phase 3/3: 生成报告...",
        })

        duration = time.time() - self._start_time
        metadata = build_metadata(
            target=self.config.target,
            phases_run=["recon", "hunt", "report"],
            tools_used=self.config.tools,
            duration_seconds=duration,
            model=self.config.model,
        )

        report_gen = ReportGenerator()
        report = report_gen.generate(self.findings, metadata, context)

        yield await self._emit("phase", {
            "phase": "report",
            "status": "done",
            "report": report,
        })

        # === 完成 ===
        yield await self._emit("done", {
            "summary": report["summary"],
            "duration_seconds": round(duration, 1),
            "report_md": report.get("report_md", ""),
        })

    # ── Phase 1: Recon ──────────────────────────────────────

    async def _phase_recon(self, target_dir: str) -> dict:
        """单 Agent 侦察: 识别项目类型和关键文件."""
        files = self._collect_files(target_dir)
        languages = self._detect_languages(files)

        # 识别关键文件
        critical_files = []
        for f in files:
            basename = os.path.basename(f).lower()
            if any(kw in basename for kw in [
                "main", "auth", "login", "parser", "network", "config",
                "app", "server", "router", "middleware",
            ]):
                critical_files.append(f)
            elif any(kw in f.lower() for kw in [
                "/auth/", "/login/", "/api/", "/parser", "/network",
            ]):
                critical_files.append(f)

        # 识别配置文件
        config_files = [
            f for f in files
            if os.path.basename(f).lower() in (
                "config.h", "config.py", "settings.py", ".env",
                "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
                "nginx.conf", "app.config", "web.config",
            )
        ]

        recon_result = {
            "language": languages[0] if languages else "unknown",
            "languages": languages,
            "total_files": len(files),
            "critical_files": critical_files[:10],  # 取前 10 个
            "config_files": config_files,
            "entry_points": critical_files[:5],
            "target_dir": target_dir,
        }

        await self._emit("log", {
            "message": f"✓ 检测到项目类型: {recon_result['language']}",
        })
        await self._emit("log", {
            "message": f"✓ 关键文件: {len(critical_files)} 个",
        })
        await self._emit("log", {
            "message": f"✓ 配置文件: {len(config_files)} 个",
        })

        return recon_result

    # ── Phase 2: Hunt ───────────────────────────────────────

    async def _phase_hunt(self, files: list[str]):
        """3 个 Agent 并行狩猎 (使用 asyncio.to_thread 避免线程/异步冲突)."""
        from .c_review import CReviewTool
        from .insecure_defaults import InsecureDefaultsTool
        from .injection_scanner import InjectionScannerTool

        # Tool 名称 → (Tool 实例, 适用的文件扩展名)
        tool_registry = {
            "c_review": (CReviewTool(), [".c", ".h"]),
            "insecure_defaults": (InsecureDefaultsTool(), None),  # None = 所有文件
            "injection_scanner": (InjectionScannerTool(), [".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb"]),
        }

        # 筛选目标文件
        tool_tasks = []
        for tool_name in self.config.tools:
            if tool_name not in tool_registry:
                continue
            tool, extensions = tool_registry[tool_name]
            if extensions:
                target_files = [f for f in files if any(f.endswith(ext) for ext in extensions)]
            else:
                target_files = files
            if target_files:
                tool_tasks.append((tool_name, tool, target_files))
                await self._emit("log", {
                    "message": f"🐛 [{tool_name}] 启动 — 扫描 {len(target_files)} 个文件",
                })

        # 并行执行每个 Tool (在线程中运行以避免阻塞 event loop)
        async def _run_one_tool(tool_name, tool, target_files):
            findings = []
            for fp in target_files:
                try:
                    result_str = await asyncio.to_thread(tool.execute, file_path=fp)
                    result = json.loads(result_str)
                    file_findings = result.get("findings", [])
                    findings.extend(file_findings)
                    if file_findings:
                        await self._emit("log", {
                            "message": f"[{tool_name}] {os.path.basename(fp)}: {len(file_findings)} 个发现",
                        })
                    # 逐个发射 finding 事件给前端
                    for f in file_findings:
                        await self._emit("finding", f)
                except Exception:
                    continue
            return findings

        tasks = [
            _run_one_tool(tool_name, tool, target_files)
            for tool_name, tool, target_files in tool_tasks
        ]

        for coro in asyncio.as_completed(tasks):
            findings = await coro
            for f in findings:
                yield f

    # ── 文件收集 ────────────────────────────────────────────

    def _collect_files(self, target: str) -> list[str]:
        """递归收集目标目录（或单文件）中需要扫描的文件.

        支持两种模式:
        - 目录: 递归遍历，按扩展名筛选
        - 单文件: 直接返回该文件（如果扩展名匹配）
        """
        target = os.path.abspath(target)

        # 单文件模式
        if os.path.isfile(target):
            ext = os.path.splitext(target)[1].lower()
            fname = os.path.basename(target)
            if ext in self.config.file_extensions or fname in self.config.file_extensions:
                return [target]
            return []

        # 目录模式
        files = []
        for root, dirs, filenames in os.walk(target):
            # 排除目录
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs and not d.startswith(".")]

            for fname in filenames:
                fpath = os.path.join(root, fname)
                # 检查扩展名 或 文件名匹配
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.config.file_extensions or fname in self.config.file_extensions:
                    files.append(fpath)

        return sorted(files)

    def _detect_languages(self, files: list[str]) -> list[str]:
        """根据项目文件推断主要编程语言."""
        ext_map = {
            ".c": "C", ".h": "C",
            ".cpp": "C++", ".hpp": "C++", ".cc": "C++",
            ".py": "Python",
            ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".php": "PHP",
        }
        counts = {}
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            lang = ext_map.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1

        return sorted(counts, key=counts.get, reverse=True)

    @staticmethod
    def _format_recon_summary(context: dict) -> str:
        """格式化侦察摘要为可读字符串."""
        lang = context.get("language", "unknown")
        total = context.get("total_files", 0)
        critical = len(context.get("critical_files", []))
        config = len(context.get("config_files", []))
        return (
            f"侦察完成: 项目类型 {lang}, 共 {total} 个文件, "
            f"其中 {critical} 个关键文件, {config} 个配置文件"
        )
