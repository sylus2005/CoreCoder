"""安全审计报告生成器.

生成两种格式:
1. REPORT.md — 人类可读的 Markdown 报告
2. findings.json — 机器可读的结构化 JSON (符合 schema.py 中的 Schema)

模板参考自 Cloudflare security-audit-skill 的 VALIDATION-AND-REPORTING.md.
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """安全审计报告生成器."""

    def generate(
        self,
        findings: list[dict],
        metadata: dict,
        context: dict | None = None,
    ) -> dict:
        """生成完整审计报告.

        Args:
            findings: 所有安全发现列表
            metadata: build_metadata() 返回的元数据
            context: Phase 1 Recon 返回的项目上下文

        Returns:
            {
                "summary": {...},
                "findings": [...],
                "report_md": "...",   # REPORT.md 全文
                "metadata": {...},
            }
        """
        summary = self._build_summary(findings)
        report_md = self._render_report_md(findings, summary, metadata, context)

        return {
            "summary": summary,
            "findings": findings,
            "report_md": report_md,
            "metadata": metadata,
        }

    def _build_summary(self, findings: list[dict]) -> dict:
        """构建统计摘要."""
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        by_cwe: dict[str, int] = {}
        by_file: dict[str, int] = {}

        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in by_severity:
                by_severity[sev] += 1

            cwe = f.get("cwe_id", "UNKNOWN")
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

            file_path = f.get("file", "unknown")
            by_file[file_path] = by_file.get(file_path, 0) + 1

        return {
            "total": len(findings),
            "by_severity": by_severity,
            "top_cwes": sorted(by_cwe.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_files": sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:5],
            "critical_count": by_severity.get("CRITICAL", 0),
            "high_count": by_severity.get("HIGH", 0),
            "medium_count": by_severity.get("MEDIUM", 0),
            "low_count": by_severity.get("LOW", 0),
        }

    def _render_report_md(
        self,
        findings: list[dict],
        summary: dict,
        metadata: dict,
        context: dict | None,
    ) -> str:
        """渲染 Markdown 报告."""
        lines = []

        # 标题
        lines.append("# 🔒 安全审计报告")
        lines.append("")
        lines.append(f"**审计目标**: `{metadata.get('target', 'N/A')}`")
        lines.append(f"**审计时间**: {metadata.get('timestamp', 'N/A')}")
        lines.append(f"**耗时**: {metadata.get('duration_seconds', 0):.1f} 秒")
        lines.append(f"**启用工具**: {', '.join(metadata.get('tools_used', []))}")
        lines.append("")

        # 项目概况
        if context:
            lines.append("## 📋 项目概况")
            lines.append("")
            lines.append(f"- **主要语言**: {context.get('language', 'N/A')}")
            lines.append(f"- **文件总数**: {context.get('total_files', 0)}")
            lines.append(f"- **关键文件**: {len(context.get('critical_files', []))}")
            lines.append(f"- **配置文件**: {len(context.get('config_files', []))}")
            lines.append("")

        # 摘要
        lines.append("## 📊 审计摘要")
        lines.append("")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 总发现 | **{summary['total']}** |")
        lines.append(f"| 🔴 严重 (CRITICAL) | **{summary['critical_count']}** |")
        lines.append(f"| 🟠 高危 (HIGH) | **{summary['high_count']}** |")
        lines.append(f"| 🟡 中危 (MEDIUM) | **{summary['medium_count']}** |")
        lines.append(f"| 🟢 低危 (LOW) | **{summary['low_count']}** |")
        lines.append("")

        # 发现列表
        if findings:
            lines.append("## 🐛 漏洞详情")
            lines.append("")

            # 按严重性排序
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
            sorted_findings = sorted(
                findings, key=lambda f: severity_order.get(f.get("severity", "MEDIUM"), 5)
            )

            for i, finding in enumerate(sorted_findings, 1):
                sev = finding.get("severity", "MEDIUM")
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFORMATIONAL": "⚪"}.get(sev, "⚪")

                lines.append(f"### {emoji} {finding['id']}: {finding.get('title', '')}")
                lines.append("")
                lines.append(f"| 属性 | 值 |")
                lines.append(f"|------|------|")
                lines.append(f"| **严重性** | {sev} |")
                lines.append(f"| **CWE** | {finding.get('cwe_id', 'N/A')} |")
                lines.append(f"| **CVSS** | {finding.get('cvss_score', 'N/A')} |")
                lines.append(f"| **文件** | `{finding.get('file', 'N/A')}` |")
                lines.append(f"| **行号** | {finding.get('line', 'N/A')} |")
                lines.append(f"| **发现工具** | {finding.get('discovered_by', 'N/A')} |")
                lines.append("")

                if finding.get("description"):
                    lines.append(f"**描述**: {finding['description']}")
                    lines.append("")

                if finding.get("attack_scenario"):
                    lines.append(f"**攻击场景**: {finding['attack_scenario']}")
                    lines.append("")

                if finding.get("fix_suggestion"):
                    lines.append(f"**💡 修复建议**: {finding['fix_suggestion']}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # 修复优先级建议
        if summary["total"] > 0:
            lines.append("## 🔧 修复优先级建议")
            lines.append("")
            lines.append("1. **立即修复** — 所有 CRITICAL 和 HIGH 级别的漏洞")
            lines.append("2. **本迭代修复** — MEDIUM 级别的漏洞")
            lines.append("3. **计划修复** — LOW 级别的漏洞，纳入后续迭代")
            lines.append("4. **持续关注** — INFORMATIONAL 级别作为安全基线参考")
            lines.append("")

        # 方法论
        lines.append("## 📝 审计方法")
        lines.append("")
        lines.append("本审计由 **CoreCoder 网络安全智能体** 自动完成，采用三阶段流水线:")
        lines.append("")
        lines.append("1. **Recon (侦察)** — 识别项目类型、关键入口点、攻击面")
        lines.append("2. **Hunt (狩猎)** — 多 Agent 并行检测，覆盖内存安全、不安全配置、注入漏洞")
        lines.append("3. **Report (报告)** — 生成结构化报告和修复建议")
        lines.append("")
        lines.append("### 技能来源")
        lines.append("")
        lines.append("- **Cloudflare security-audit-skill** — 六阶段审计流水线架构 (精简为三阶段)")
        lines.append("- **Trail of Bits skills** — 专业 C/C++ 安全审查、不安全默认值检测")
        lines.append("- **Anthropic Cybersecurity Skills** — 攻击模式知识库 (Web/API/Cloud/Container)")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*本报告由 CoreCoder 网络安全智能体自动生成 | 版本 v1.0.0-MVP*")

        return "\n".join(lines)

    def write_files(self, report: dict, output_dir: str) -> dict:
        """将报告写入文件系统.

        Args:
            report: self.generate() 的返回值
            output_dir: 输出目录路径

        Returns:
            {"report_md_path": "...", "findings_json_path": "..."}
        """
        os.makedirs(output_dir, exist_ok=True)

        # REPORT.md
        report_md_path = os.path.join(output_dir, "REPORT.md")
        with open(report_md_path, "w", encoding="utf-8") as f:
            f.write(report["report_md"])

        # findings.json
        findings_json_path = os.path.join(output_dir, "findings.json")
        output_data = {
            "version": "1.0.0",
            "metadata": report["metadata"],
            "findings": report["findings"],
        }
        with open(findings_json_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        return {
            "report_md_path": report_md_path,
            "findings_json_path": findings_json_path,
        }
