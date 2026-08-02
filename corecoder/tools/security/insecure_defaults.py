"""不安全默认值/配置检测 Tool.

提取自:
- trailofbits/skills: insecure-defaults (硬编码凭据、不安全默认配置)
- trailofbits/skills: sharp-edges (危险 API/配置)
- mukul975/Anthropic-Cybersecurity-Skills: Cloud/Container Security 领域

检测类别:
    - 硬编码凭据: 密码、API Key、Token 出现在配置/源码中
    - 调试模式开启: DEBUG=True, ENV=development 在生产环境
    - 不安全 CORS: Access-Control-Allow-Origin: *
    - 宽松文件权限: chmod 777, umask 000
    - 默认密码: admin/admin, root/root 等
    - 危险端口: 23 (Telnet), 21 (FTP) 明文协议
"""

import re
import json
import os

from . import SecurityTool


class InsecureDefaultsTool(SecurityTool):
    name = "insecure_defaults"
    description = (
        "Scan for insecure defaults, hardcoded credentials, debug modes left enabled, "
        "overly permissive CORS settings, weak file permissions, and default passwords. "
        "Works on source code, config files, Dockerfiles, and .env files."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the file to scan.",
            },
            "focus": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "hardcoded_secret",
                        "debug_mode",
                        "insecure_cors",
                        "weak_permissions",
                        "default_password",
                        "dangerous_port",
                    ],
                },
                "description": "Specific issue categories to focus on.",
            },
        },
        "required": ["file_path"],
    }

    _RULES: list[tuple[str, str, str, str, str, str]] = [
        # (category, pattern, cwe, severity, title_template, fix_suggestion)

        # 硬编码凭据 — 来自 trailofbits insecure-defaults
        #  注: _pass / _pwd / _secret / _token / _key 后缀覆盖 admin_pass、
        #  db_password、api_token 等常见变量名（c_review.py 已修，此处同步）
        (
            "hardcoded_secret",
            r"(?i)(\w*(?:password|passwd|pwd|_pass|_pwd)\w*)\s*(?:\[\])?\s*[:=]\s*['\"][^'\"]{3,}['\"]",
            "CWE-798",
            "HIGH",
            "硬编码密码: {var}",
            "将密码移至环境变量或密钥管理服务（AWS Secrets Manager / HashiCorp Vault）",
        ),
        (
            "hardcoded_secret",
            r"(?i)(\w*(?:api[_-]?key|api[_-]?secret|access[_-]?key|_secret|_token|_key)\w*)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "CWE-798",
            "HIGH",
            "硬编码 API 密钥/令牌: {var}",
            "使用环境变量存储 API 密钥，不要提交到代码仓库",
        ),
        (
            "hardcoded_secret",
            r"(?i)(\w*(?:token|jwt[_-]?secret|private[_-]?key)\w*)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "CWE-798",
            "HIGH",
            "硬编码令牌/密钥: {var}",
            "使用安全的密钥管理方案，如 AWS KMS 或环境变量",
        ),
        (
            "hardcoded_secret",
            r"(?i)(?:connection[_-]?string|conn[_-]?str|database[_-]?url)\s+\S*\s*=\s*\"[^\"]{10,}\"",
            "CWE-798",
            "HIGH",
            "硬编码数据库连接字符串: {var}",
            "将连接字符串存储到环境变量或密钥管理服务中",
        ),
        # C/C++ 特定: const char *var = "secret" 或 char var[] = "secret"
        (
            "hardcoded_secret",
            r"(?i)(?:const\s+)?char\s*(?:\*\s*|(?:\w+\s*)*)\w*(?:password|_pass|_pwd|secret|key|token|_secret|_key|_token)\w*\s*(?:\[\s*\])?\s*=\s*\"[^\"]{3,}\"",
            "CWE-798",
            "HIGH",
            "C/C++ 硬编码凭据: {var}",
            "将凭据移至环境变量或安全的密钥管理服务，不要写在源码中",
        ),
        (
            "hardcoded_secret",
            r"(?i)#\s*define\s+\w*(?:CONNECTION|PASSWORD|SECRET|TOKEN|KEY|_PASS|_PWD|_SECRET|_KEY|_TOKEN)\w*\s+\"[^\"]{6,}\"",
            "CWE-798",
            "HIGH",
            "#define 宏定义中的硬编码凭据: {var}",
            "将凭据移至环境变量或安全的密钥管理服务",
        ),

        # 调试模式 — 来自 trailofbits insecure-defaults
        (
            "debug_mode",
            r"(?i)#\s*define\s+(DEBUG|DEBUG_MODE)\s+1\b",
            "CWE-215",
            "MEDIUM",
            "调试模式开启: {var} — 生产环境暴露调试信息 (C/C++ 宏定义)",
            "在生产环境中使用 #define DEBUG_MODE 0 或 #undef DEBUG_MODE",
        ),
        (
            "debug_mode",
            r"(?i)(DEBUG|DEBUG_MODE|FLASK_ENV|ENVIRONMENT)\s*[:=]\s*['\"]?(true|1|development|dev)['\"]?",
            "CWE-215",
            "MEDIUM",
            "调试模式开启: {var} — 生产环境暴露调试信息",
            "在生产环境中设置 DEBUG=False，使用独立的日志系统",
        ),
        (
            "debug_mode",
            r"(?i)(DJANGO_DEBUG|APP_DEBUG)\s*=\s*(True|true|1)",
            "CWE-215",
            "MEDIUM",
            "Web 框架调试模式开启: {var}",
            "在生产环境关闭 DEBUG，使用 sentry 等错误追踪工具",
        ),

        # 不安全 CORS — 来自 mukul975 Web Security
        (
            "insecure_cors",
            r"(?i)Access-Control-Allow-Origin\s*:\s*\*",
            "CWE-942",
            "MEDIUM",
            "CORS 配置过于宽松: 允许任意来源访问",
            "将 Access-Control-Allow-Origin 限制为受信任的域名列表",
        ),
        (
            "insecure_cors",
            r"(?i)cors_allow_all|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            "CWE-942",
            "MEDIUM",
            "CORS 允许所有来源 — 可能导致 CSRF 和数据泄露",
            "指定具体的允许域名列表",
        ),

        # 宽松文件权限 — 来自 mukul975 Container Security
        (
            "weak_permissions",
            r"chmod\s+(-R\s+)?(777|666|o\+w)",
            "CWE-732",
            "MEDIUM",
            "不安全的文件权限: 所有用户可读写",
            "使用最小权限原则: chmod 750 或更严格的权限",
        ),
        (
            "weak_permissions",
            r"umask\s+(000|0)",
            "CWE-732",
            "LOW",
            "umask 设置为 0 — 新建文件默认所有人可读写",
            "设置 umask 027 或 077",
        ),

        # 默认密码 — 来自 mukul975 Cloud Security
        (
            "default_password",
            r"(?i)(admin|root|guest|test|user)\s*[:=]\s*['\"](admin|root|password|123456|test|guest)['\"]",
            "CWE-1392",
            "HIGH",
            "使用默认凭据: {var}",
            "立即修改默认密码，使用强密码策略",
        ),

        # 危险端口 — 来自 mukul975 Network Security
        (
            "dangerous_port",
            r"(?i)\b(23|21|512|513|514|2049)\b.*(?:port|listen|bind)",
            "CWE-319",
            "LOW",
            "使用明文协议端口: Telnet(23)/FTP(21) — 通信未加密",
            "使用 SSH(22) 替代 Telnet，SFTP(22) 替代 FTP",
        ),
    ]

    def execute(self, file_path: str, focus: list[str] | None = None) -> str:
        self._emit("tool_start", {"tool": self.name, "file": file_path})

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (IOError, OSError) as e:
            return json.dumps({"error": f"Cannot read {file_path}: {e}", "findings": []})

        lines = content.split("\n")
        focus_set = set(focus) if focus else None
        findings = []

        for rule in self._RULES:
            category, pattern, cwe, severity, title_tmpl, fix = rule

            if focus_set and category not in focus_set:
                continue

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[: match.start()].count("\n") + 1
                line_content = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""
                matched_text = match.group(0)[:80]

                var_name = match.group(1) if match.lastindex else matched_text.split("=")[0].strip()

                finding = self._build_finding(
                    title=title_tmpl.format(var=var_name or matched_text),
                    severity=severity,
                    cwe_id=cwe,
                    file_path=file_path,
                    line=line_no,
                    description=f"第 {line_no} 行: `{line_content}`",
                    fix_suggestion=fix,
                    attack_scenario=(
                        f"{file_path}:{line_no} 的配置可被利用。"
                        f"攻击者可能通过 {matched_text[:60]} 获取未授权的访问或信息。"
                    ),
                )
                findings.append(finding)
                self._emit("finding", finding)

        # 去重
        seen = set()
        deduped = []
        for f in findings:
            key = (f["file"], f["line"], f["cwe_id"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        stats = {
            "file": file_path,
            "total": len(deduped),
            "by_severity": {},
        }
        for f in deduped:
            stats["by_severity"][f["severity"]] = (
                stats["by_severity"].get(f["severity"], 0) + 1
            )

        self._emit("tool_done", {"tool": self.name, "file": file_path, **stats})

        return json.dumps({"findings": deduped, "stats": stats}, indent=2, ensure_ascii=False)
