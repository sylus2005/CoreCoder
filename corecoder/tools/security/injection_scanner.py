"""注入漏洞扫描 Tool.
提取自:
- trailofbits/skills: semgrep (静态分析模式匹配)
- mukul975/Anthropic-Cybersecurity-Skills: Web Application Security 领域

检测类别:
    - SQL 注入: 字符串拼接构造 SQL 查询
    - 命令注入: os.system / subprocess 使用用户输入
    - XSS (跨站脚本): 未转义的用户输入写入 HTML
    - 路径遍历: 用户输入拼接到文件路径
    - 服务端请求伪造 (SSRF): 用户可控的 URL 请求
"""

import re
import json

from . import SecurityTool


class InjectionScannerTool(SecurityTool):
    name = "injection_scanner"
    description = (
        "Scan source code for injection vulnerabilities: SQL injection, "
        "command injection, XSS (cross-site scripting), path traversal, and SSRF. "
        "Uses pattern matching enhanced by LLM context analysis."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the source file to scan.",
            },
            "focus": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "sql_injection",
                        "command_injection",
                        "xss",
                        "path_traversal",
                        "ssrf",
                    ],
                },
                "description": "Specific injection types to focus on.",
            },
        },
        "required": ["file_path"],
    }

    _RULES: list[tuple[str, str, str, str, str, str]] = [
        # SQL 注入 — 各种语言的字符串拼接模式
        (
            "sql_injection",
            r"(?i)(?:execute|cursor\.execute|rawQuery|db\.query)\s*\(\s*(?:f['\"]|[^'\"]*\s*\+\s*)",
            "CWE-89",
            "HIGH",
            "SQL 查询使用字符串拼接 — 可能存在 SQL 注入",
            "使用参数化查询: cursor.execute('SELECT ...', (param,))",
        ),
        (
            "sql_injection",
            r"(?i)SELECT\s+.*\s+FROM\s+.*\bformat\b|%s.*\buser|request\.\w+",
            "CWE-89",
            "HIGH",
            "SQL 查询中直接使用用户输入 — SQL 注入风险",
            "始终使用参数化查询或 ORM 的安全查询方法",
        ),
        (
            "sql_injection",
            r"(?i)(?:query|sql)\s*=\s*['\"].*\{\w+['\"]\s*\.format|f['\"].*SELECT",
            "CWE-89",
            "HIGH",
            "f-string/format 构造 SQL 查询 — SQL 注入风险",
            "使用参数化查询替代字符串格式化",
        ),

        # 命令注入
        (
            "command_injection",
            r"(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec|eval)\s*\(\s*(?:f['\"]|[^'\"]*\s*\+\s*|.*request\.|.*input\()",
            "CWE-78",
            "HIGH",
            "命令执行函数使用动态输入 — 命令注入风险",
            "使用 subprocess.run([cmd, arg1, arg2]) 列表形式，或 shlex.quote()",
        ),
        (
            "command_injection",
            r"(?i)(?:shell_exec|exec|system|passthru)\s*\(\s*\$",
            "CWE-78",
            "HIGH",
            "PHP 命令执行函数使用变量输入 — 命令注入风险",
            "使用 escapeshellarg() 对参数进行转义",
        ),

        # XSS (跨站脚本)
        (
            "xss",
            r"(?i)(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)\s*=|\.html\s*\(\s*(?!.*escape|.*sanitize)",
            "CWE-79",
            "MEDIUM",
            "未转义的用户输入写入 DOM — XSS 风险",
            "使用 textContent 替代 innerHTML，或使用 DOMPurify 净化",
        ),
        (
            "xss",
            r"(?i)(?:render_template_string|Markup\s*\()",
            "CWE-79",
            "MEDIUM",
            "模板字符串直接渲染 — XSS 风险",
            "启用模板引擎的自动转义功能",
        ),

        # 路径遍历
        (
            "path_traversal",
            r"(?i)(?:open|read|write|delete)\s*\([^)]*request\.\w+[^)]*\)",
            "CWE-22",
            "MEDIUM",
            "文件操作中使用用户输入路径 — 路径遍历风险",
            "使用 os.path.basename() 过滤路径，或白名单验证",
        ),
        (
            "path_traversal",
            r"(?i)os\.path\.join\s*\([^)]*request\.\w+",
            "CWE-22",
            "MEDIUM",
            "用户输入拼接到文件路径 — 路径遍历风险",
            "在使用前对用户输入进行路径规范化验证",
        ),

        # SSRF (服务端请求伪造)
        (
            "ssrf",
            r"(?i)(?:requests\.(?:get|post|put)|urllib\.request\.urlopen|http\.client|axios)\s*\([^)]*request\.\w+[^)]*\)",
            "CWE-918",
            "MEDIUM",
            "用户可控的 URL 请求 — SSRF 风险",
            "使用 URL 白名单，禁止访问内网地址（127.0.0.1, 10.0.0.0/8 等）",
        ),
        (
            "ssrf",
            r"(?i)fetch\s*\(\s*(?:`[^`]*\$\{.*\}|\w+\s*\+\s*)",
            "CWE-918",
            "MEDIUM",
            "fetch 使用动态 URL 拼接 — SSRF 风险",
            "在服务端验证目标 URL，限制可访问的域名和 IP 范围",
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
            category, pattern, cwe, severity, title, fix = rule

            if focus_set and category not in focus_set:
                continue

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[: match.start()].count("\n") + 1
                line_content = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""

                finding = self._build_finding(
                    title=title,
                    severity=severity,
                    cwe_id=cwe,
                    file_path=file_path,
                    line=line_no,
                    description=f"第 {line_no} 行: `{line_content}`",
                    fix_suggestion=fix,
                    attack_scenario=(
                        f"攻击者可向 {file_path}:{line_no} 注入恶意载荷。"
                        f"这是一个 {category} 漏洞，属于 OWASP Top 10 中的常见攻击类型。"
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
