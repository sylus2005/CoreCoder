"""安全审计编排 Tool —— LLM 可直接调用触发完整的 AuditPipeline.

这是 CoreCoder 安全智能体的核心入口工具。当用户请求安全审计时，
LLM 调用此工具的 execute() 方法，它会启动三阶段流水线并返回结构化结果。
"""

import asyncio
import json
import os
import time

from ..base import Tool


class AuditTool(Tool):
    """安全审计编排工具 —— 一键触发完整的安全审计流水线.

    当用户说"帮我审计这个项目"、"扫描安全漏洞"、"检查代码安全性"时，
    LLM 应使用此工具启动完整的 Recon → Hunt → Report 三阶段审计。

    与单独调用 c_review/insecure_defaults/injection_scanner 不同，
    AuditTool 会：
    1. 自动侦察项目类型和关键文件
    2. 根据项目类型选择合适的工具组合并行扫描
    3. 汇总所有发现，按严重性排序
    4. 生成 REPORT.md 和 findings.json
    """

    name = "run_security_audit"
    description = (
        "Run a complete security audit on a code directory. "
        "This triggers a 3-phase pipeline: Recon (project analysis) → "
        "Hunt (parallel vulnerability scanning with c_review, "
        "insecure_defaults, injection_scanner) → Report (findings summary). "
        "Use this when the user asks to audit, scan, or review code for "
        "security vulnerabilities. Do NOT use this for reading files or "
        "general code questions — only for security auditing."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": (
                    "The directory path to audit. Defaults to the current "
                    "working directory. Examples: './demo/vulnerable-utils/', "
                    "'./src/', '.'"
                ),
            },
            "tools": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["c_review", "insecure_defaults", "injection_scanner"],
                },
                "description": (
                    "Which security tools to use. By default all three are used. "
                    "c_review: C/C++ memory safety (buffer overflow, UAF, etc.). "
                    "insecure_defaults: hardcoded secrets, debug mode, weak configs. "
                    "injection_scanner: SQLi, XSS, command injection patterns."
                ),
            },
            "model": {
                "type": "string",
                "description": "Optional LLM model name for the audit agents.",
            },
        },
        "required": [],
    }

    def execute(
        self,
        target: str = ".",
        tools: list[str] | None = None,
        model: str = "",
    ) -> str:
        """执行完整的安全审计流水线.

        Args:
            target: 审计目标目录路径
            tools: 启用的安全工具列表，默认全部
            model: 可选的 LLM 模型名

        Returns:
            JSON 字符串，包含 summary + findings + report_md
        """
        from .pipeline import AuditPipeline, AuditConfig

        # 解析绝对路径
        if not os.path.isabs(target):
            target = os.path.abspath(target)

        if not os.path.isdir(target):
            return json.dumps({
                "error": True,
                "message": f"目标目录不存在: {target}",
                "findings": [],
                "summary": {"total": 0},
            }, ensure_ascii=False)

        tool_list = tools or ["c_review", "insecure_defaults", "injection_scanner"]

        config = AuditConfig(
            target=target,
            tools=tool_list,
            model=model,
        )

        pipeline = AuditPipeline(config=config)
        events = []
        findings = []
        report = None
        start_time = time.time()

        # 注册事件处理器以收集 findings
        # (findings 通过 _emit("finding", f) 推送到处理器，
        #  而不是通过 run() 的 async generator yield)
        def _on_event(event):
            nonlocal report, findings
            events.append(event)
            if event.get("type") == "finding":
                findings.append({
                    k: v for k, v in event.items()
                    if k not in ("type",)
                })
            if event.get("type") == "done":
                report = event

        pipeline.on_event(_on_event)

        # 同步运行异步流水线
        async def _collect():
            async for event in pipeline.run(target):
                pass  # 事件已由 _on_event 处理器收集

        # 检测是否在已有事件循环中运行
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        try:
            if running_loop is not None:
                # 在已有事件循环中（如 FastAPI 后台任务），
                # 使用线程池运行以避免冲突
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, _collect())
                    future.result(timeout=300)
            else:
                asyncio.run(_collect())
        except Exception as exc:
            import traceback
            traceback.print_exc()
            return json.dumps({
                "error": True,
                "message": f"审计执行失败: {str(exc)}",
                "findings": findings,
                "summary": {"total": len(findings)},
            }, ensure_ascii=False)

        duration = time.time() - start_time

        # 按严重性统计
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        result = {
            "success": True,
            "target": target,
            "tools_used": tool_list,
            "duration_seconds": round(duration, 1),
            "summary": {
                "total": len(findings),
                "high_count": by_severity.get("HIGH", 0) + by_severity.get("CRITICAL", 0),
                "medium_count": by_severity.get("MEDIUM", 0),
                "low_count": by_severity.get("LOW", 0) + by_severity.get("INFORMATIONAL", 0),
                "by_severity": by_severity,
            },
            "findings": findings,
            "report_md": report.get("report_md", "") if report else "",
            "phase_summary": _build_phase_summary(events),
        }

        # 返回给 LLM 的字符串（LLM 会阅读此内容并向用户报告）
        output_lines = [
            f"# Security Audit Complete",
            f"",
            f"**Target**: `{target}`",
            f"**Duration**: {duration:.1f}s",
            f"**Tools Used**: {', '.join(tool_list)}",
            f"",
            f"## Summary",
            f"- Total Findings: **{len(findings)}**",
            f"- HIGH/CRITICAL: **{by_severity.get('HIGH', 0) + by_severity.get('CRITICAL', 0)}**",
            f"- MEDIUM: **{by_severity.get('MEDIUM', 0)}**",
            f"- LOW: **{by_severity.get('LOW', 0) + by_severity.get('INFORMATIONAL', 0)}**",
            f"",
        ]

        if findings:
            output_lines.append("## Top Findings")
            output_lines.append("")
            output_lines.append("| # | Severity | CWE | File | Title |")
            output_lines.append("|---|----------|-----|------|-------|")
            for f in findings[:20]:  # 最多展示 20 条
                fid = f.get("id", "-")
                sev = f.get("severity", "-")
                cwe = f.get("cwe_id", "-")
                file = os.path.basename(f.get("file", "-"))
                title = f.get("title", "-")[:60]
                output_lines.append(f"| {fid} | {sev} | {cwe} | {file} | {title} |")

            if len(findings) > 20:
                output_lines.append(f"| ... | ... | ... | ... | (+{len(findings) - 20} more) |")

        output_lines.extend([
            "",
            "---",
            "",
            "Now I should summarize these findings to the user in natural language,",
            "highlighting the most critical vulnerabilities, their attack scenarios,",
            "and actionable fix suggestions.",
        ])

        return "\n".join(output_lines)


def _build_phase_summary(events: list[dict]) -> dict:
    """从事件列表中提取阶段摘要."""
    phases = {}
    for e in events:
        if e.get("type") == "phase":
            phase_name = e.get("phase", "")
            phases[phase_name] = {
                "status": e.get("status", "unknown"),
                "message": e.get("message", ""),
            }
    return phases
