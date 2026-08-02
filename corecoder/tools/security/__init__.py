"""CoreCoder Security Tools — MVP 网络安全智能体子包.

基于 trailofbits/skills、cloudflare/security-audit-skill、
mukul975/Anthropic-Cybersecurity-Skills 三个仓库的技能提取与重构。

目录:
    schema.py            — findings.json JSON Schema 定义
    pipeline.py          — AuditPipeline: 三阶段审计流水线编排器
    c_review.py          — CReviewTool: C/C++ 内存安全审计
    insecure_defaults.py — InsecureDefaultsTool: 不安全默认值/配置检测
    injection_scanner.py — InjectionScannerTool: SQLi/XSS/命令注入扫描
    report.py            — ReportGenerator: REPORT.md + findings.json 生成
    knowledge/           — 攻击模式知识库 (提取自 mukul975 仓库)
"""

from ..base import Tool

# 全局 finding ID 计数器
_finding_counter = 0


def _next_finding_id() -> str:
    """生成自增的 finding ID: FINDING-0001, FINDING-0002, ..."""
    global _finding_counter
    _finding_counter += 1
    return f"FINDING-{_finding_counter:04d}"


def _reset_counter():
    """重置计数器（每次审计启动时调用）。"""
    global _finding_counter
    _finding_counter = 0


class SecurityTool(Tool):
    """安全审计 Tool 基类.

    扩展标准 CoreCoder Tool，增加:
    - CWE 映射: 每个发现自动关联 CWE ID
    - 严重性评级: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    - SSE 事件发射: 通过 _on_event 回调向流水线报告进度
    - 标准化 finding 字典: _build_finding() 确保输出格式一致
    """

    # 子类可覆盖: 检测模式 → CWE-ID 的映射
    cwe_mapping: dict[str, str] = {}

    def __init__(self):
        super().__init__()
        self._on_event = None  # 由 Pipeline 注入: async callable(event_type, data)

    def _emit(self, event_type: str, data: dict) -> None:
        """发送审计事件（由 Pipeline 设置回调）。"""
        if self._on_event:
            self._on_event(event_type, data)

    def _build_finding(
        self,
        title: str,
        severity: str,
        cwe_id: str,
        file_path: str,
        line: int,
        description: str = "",
        fix_suggestion: str = "",
        attack_scenario: str = "",
    ) -> dict:
        """构造标准化的 finding 字典，遵循 findings.json Schema。"""
        return {
            "id": _next_finding_id(),
            "title": title,
            "severity": severity.upper(),
            "verdict": "SUSPECTED",
            "cwe_id": cwe_id,
            "cvss_score": self._severity_to_cvss(severity),
            "file": file_path,
            "line": line,
            "description": description,
            "attack_scenario": attack_scenario,
            "fix_suggestion": fix_suggestion,
            "discovered_by": self.name,
            "validated_by": "",
        }

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        """严重性 → CVSS 分值映射."""
        return {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFORMATIONAL": 0.0,
        }.get(severity.upper(), 5.0)

    @staticmethod
    def _calc_severity(likelihood: str, impact: str) -> str:
        """严重性 = 可能性 × 影响 (Cloudflare 审计设计原则)."""
        matrix = {
            ("HIGH", "HIGH"): "CRITICAL",
            ("HIGH", "MEDIUM"): "HIGH",
            ("MEDIUM", "HIGH"): "HIGH",
            ("HIGH", "LOW"): "MEDIUM",
            ("MEDIUM", "MEDIUM"): "MEDIUM",
            ("LOW", "HIGH"): "MEDIUM",
            ("MEDIUM", "LOW"): "LOW",
            ("LOW", "MEDIUM"): "LOW",
            ("LOW", "LOW"): "INFORMATIONAL",
        }
        return matrix.get(
            (likelihood.upper(), impact.upper()), "MEDIUM"
        )
