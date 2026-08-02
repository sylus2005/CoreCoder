"""findings.json JSON Schema — 翻译自 Cloudflare security-audit-skill 的 report-schema.json.

来源: skills/cloudflare-security-audit/skills/security-audit/report-schema.json
"""

from datetime import datetime, timezone

FINDINGS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SecurityAuditFindings",
    "type": "object",
    "required": ["version", "metadata", "findings"],
    "properties": {
        "version": {"const": "1.0.0"},
        "metadata": {
            "type": "object",
            "required": ["target", "timestamp", "phases_run"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "审计目标目录或文件",
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time",
                    "description": "审计完成时间 (ISO 8601)",
                },
                "phases_run": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["recon", "hunt", "report"]},
                    "description": "已执行的流水线阶段",
                },
                "agent_model": {
                    "type": "string",
                    "description": "使用的 LLM 模型",
                },
                "duration_seconds": {
                    "type": "number",
                    "description": "审计总耗时（秒）",
                },
                "tools_used": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "已启用的安全 Tool 名称",
                },
            },
        },
        "findings": {
            "type": "array",
            "description": "安全发现列表",
            "items": {
                "type": "object",
                "required": [
                    "id", "title", "severity", "cwe_id", "file", "line",
                ],
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^FINDING-\\d{4}$",
                        "description": "发现编号",
                    },
                    "title": {
                        "type": "string",
                        "maxLength": 200,
                        "description": "漏洞标题",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                        "description": "严重性等级",
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["CONFIRMED", "SUSPECTED", "FALSE_POSITIVE"],
                        "description": "验证结论",
                    },
                    "cwe_id": {
                        "type": "string",
                        "pattern": "^CWE-\\d{1,4}$",
                        "description": "CWE 编号",
                    },
                    "cvss_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 10.0,
                        "description": "CVSS 3.1 评分",
                    },
                    "file": {
                        "type": "string",
                        "description": "文件路径（相对于审计目标）",
                    },
                    "line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "行号",
                    },
                    "description": {
                        "type": "string",
                        "description": "漏洞详细描述",
                    },
                    "attack_scenario": {
                        "type": "string",
                        "description": "攻击场景描述",
                    },
                    "fix_suggestion": {
                        "type": "string",
                        "description": "修复建议",
                    },
                    "discovered_by": {
                        "type": "string",
                        "description": "发现该漏洞的 Tool 名称",
                    },
                    "validated_by": {
                        "type": "string",
                        "description": "验证该漏洞的 Tool 名称（MVP 阶段为空）",
                    },
                    "mitre_attack": {
                        "type": "string",
                        "description": "MITRE ATT&CK 技术 ID",
                    },
                    "nist_csf": {
                        "type": "string",
                        "description": "NIST CSF 2.0 类别",
                    },
                },
            },
        },
    },
}


def build_metadata(
    target: str,
    phases_run: list[str],
    tools_used: list[str],
    duration_seconds: float,
    model: str = "",
) -> dict:
    """构造 findings.json 的 metadata 块."""
    return {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phases_run": phases_run,
        "tools_used": tools_used,
        "duration_seconds": round(duration_seconds, 1),
        "agent_model": model,
    }
