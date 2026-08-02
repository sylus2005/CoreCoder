"""C/C++ 内存安全审计 Tool.

提取自:
- trailofbits/skills: c-review (C/C++ security review)
- mukul975/Anthropic-Cybersecurity-Skills: 内存安全相关的攻击模式

检测类别:
    - 缓冲区溢出 (CWE-120): strcpy/strcat/sprintf/gets/memcpy 无边界检查
    - Use-After-Free (CWE-416): free 后继续使用指针
    - 整数溢出 (CWE-190): malloc(n * size) 未检查溢出
    - 格式化字符串 (CWE-134): printf 非字面量格式串
    - 空指针解引用 (CWE-476): 未检查 malloc 返回值
    - 硬编码凭据 (CWE-798): 代码中硬编码的密码/密钥
"""

import re
import json

from . import SecurityTool


class CReviewTool(SecurityTool):
    name = "c_review"
    description = (
        "Analyze C/C++ source files for memory safety vulnerabilities: "
        "buffer overflow, use-after-free, integer overflow, format string bugs, "
        "null pointer dereference, and hardcoded credentials. "
        "Returns structured findings with CWE IDs and fix suggestions."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the .c or .h file to review.",
            },
            "focus": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "buffer_overflow",
                        "use_after_free",
                        "integer_overflow",
                        "format_string",
                        "null_pointer",
                        "hardcoded_secret",
                    ],
                },
                "description": (
                    "Specific vulnerability classes to focus on. "
                    "Omit to scan for all categories."
                ),
            },
        },
        "required": ["file_path"],
    }

    # === 检测规则 ===
    # 每条规则: (正则模式, CWE-ID, 严重性, 标题, 修复建议)
    # 提取自 trailofbits c-review 的攻击向量 + mukul975 知识库

    _RULES: list[tuple[str, str, str, str, str, str]] = [
        # (category, pattern, cwe, severity, title_template, fix)
        (
            "buffer_overflow",
            r"\b(strcpy|strcat|sprintf|vsprintf)\s*\(",
            "CWE-120",
            "HIGH",
            "危险函数调用: {func} — 不检查目标缓冲区边界",
            "使用 strncpy / strncat / snprintf 并显式指定缓冲区大小限制",
        ),
        (
            "buffer_overflow",
            r"\bgets\s*\(",
            "CWE-242",
            "HIGH",
            "gets() 函数 — 天生不安全，无法限制输入长度",
            "使用 fgets(buffer, size, stdin) 替代",
        ),
        (
            "buffer_overflow",
            r"\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*\)",
            "CWE-120",
            "HIGH",
            "memcpy 使用可疑长度参数 — 可能存在缓冲区溢出",
            "在 memcpy 前验证目标缓冲区大小 ≥ 拷贝长度",
        ),
        (
            "use_after_free",
            r"\bfree\s*\(\s*(\w+)\s*\)",
            "CWE-416",
            "HIGH",
            "free() 调用 — 检查后续是否继续使用已释放指针",
            "free() 后将指针置为 NULL，或使用 defer/free 后不再访问",
        ),
        (
            "integer_overflow",
            r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)",
            "CWE-190",
            "MEDIUM",
            "malloc(n * size) — 乘法可能整数溢出导致分配不足",
            "在乘法前检查: if (n > SIZE_MAX / size) return NULL;",
        ),
        (
            "integer_overflow",
            r"\bcalloc\s*\(\s*\w+\s*,\s*\w+\s*\)",
            "CWE-190",
            "MEDIUM",
            "calloc(n, size) — 乘法可能整数溢出",
            "在 calloc 前检查: if (n > SIZE_MAX / size) return NULL;",
        ),
        (
            "format_string",
            r"\bprintf\s*\(\s*(?!\"[^\"]*\"\s*\))[^\"][^)]*\)",
            "CWE-134",
            "HIGH",
            "printf 使用非字面量格式字符串 — 格式化字符串漏洞",
            '使用 printf("%s", user_input) 替代 printf(user_input)',
        ),
        (
            "format_string",
            r"\b(fprintf|sprintf|snprintf)\s*\(\s*\w+\s*,\s*(?!\"[^\"]*\"\s*\))[^\"][^)]*\)",
            "CWE-134",
            "HIGH",
            "{func} 使用非字面量格式字符串",
            '使用 {func}(out, "%s", user_input) 替代 {func}(out, user_input)',
        ),
        (
            "null_pointer",
            r"\b(malloc|calloc|realloc)\s*\([^)]+\)\s*;",
            "CWE-476",
            "LOW",
            "内存分配后未检查返回值 — 可能导致空指针解引用",
            "分配后立即检查: if (!ptr) { /* handle error */ }",
        ),
        (
            "hardcoded_secret",
            r"(?i)(password|passwd|_pass|_pwd|secret|api_key|token|private_key|connection_string)\b[^;]*=\s*\"[^\"]+\"",
            "CWE-798",
            "HIGH",
            "硬编码凭据: {var} — 敏感信息不应出现在源代码中",
            "使用环境变量或安全的密钥管理服务（如 AWS Secrets Manager）",
        ),
        (
            "hardcoded_secret",
            r"(?i)(password|passwd|_pass|_pwd|secret|api_key|private_key)\b[^;]*=\s*'[^']+'",
            "CWE-798",
            "HIGH",
            "硬编码凭据: {var} — 敏感信息不应出现在源代码中",
            "使用环境变量或安全的密钥管理服务",
        ),
    ]

    def execute(self, file_path: str, focus: list[str] | None = None) -> str:
        """对指定 C/C++ 文件执行内存安全审计。

        Args:
            file_path: 要审查的 .c/.h 文件路径
            focus: 可选，限定检测的漏洞类别

        Returns:
            JSON 字符串: {"findings": [...], "stats": {...}}
        """
        self._emit("tool_start", {"tool": self.name, "file": file_path})

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        except (IOError, OSError) as e:
            return json.dumps({"error": f"Cannot read {file_path}: {e}", "findings": []})

        lines = code.split("\n")
        focus_set = set(focus) if focus else None
        findings = []

        for rule in self._RULES:
            category, pattern, cwe, severity, title_tmpl, fix = rule

            if focus_set and category not in focus_set:
                continue

            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                line_no = code[: match.start()].count("\n") + 1
                matched_text = match.group(0)[:80]
                line_content = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""

                # 构造标题: 替换模板变量
                func_name = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                var_name = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                title = title_tmpl.format(
                    func=func_name or matched_text.split("(")[0],
                    var=var_name or "unknown",
                )

                finding = self._build_finding(
                    title=title,
                    severity=severity,
                    cwe_id=cwe,
                    file_path=file_path,
                    line=line_no,
                    description=f"第 {line_no} 行: `{line_content}`",
                    fix_suggestion=fix,
                    attack_scenario=self._build_attack_scenario(
                        category, file_path, line_no
                    ),
                )
                findings.append(finding)
                self._emit("finding", finding)

        # 去重: 同一文件+同一行+同一类别只保留一个
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

    def _build_attack_scenario(self, category: str, file_path: str, line: int) -> str:
        """为每种漏洞类型生成攻击场景描述."""
        scenarios = {
            "buffer_overflow": (
                f"攻击者可向 {file_path}:{line} 传入超长输入，"
                "覆盖栈上的返回地址或相邻变量，可能导致任意代码执行。"
                "在真实攻击中，这通常通过精心构造的输入（如 exploit payload）触发。"
            ),
            "use_after_free": (
                f"{file_path}:{line} 处的内存在释放后可能被继续使用。"
                "攻击者可在 free 后分配新对象占据同一内存区域，"
                "从而劫持悬垂指针的后续操作，导致信息泄露或代码执行。"
            ),
            "integer_overflow": (
                f"{file_path}:{line} 处的乘法可能整数溢出，"
                "导致实际分配的内存远小于预期。后续写入操作将触发"
                "堆缓冲区溢出，可能被利用进行任意代码执行。"
            ),
            "format_string": (
                f"{file_path}:{line} 使用用户可控的格式字符串。"
                "攻击者可传入 %n 写入任意内存地址，或通过 %x/%s "
                "泄露栈上的敏感信息（如密码、密钥）。"
            ),
            "null_pointer": (
                f"{file_path}:{line} 处的内存分配失败时返回 NULL，"
                "若未检查直接解引用将导致程序崩溃（拒绝服务）。"
                "在某些内核场景下可能进一步导致权限提升。"
            ),
            "hardcoded_secret": (
                f"源代码中硬编码的凭据可被任何人通过 git log 或反编译获取。"
                "一旦泄露，攻击者可直接使用该凭据认证，无需其他攻击步骤。"
                "这在供应链攻击中尤为危险。"
            ),
        }
        return scenarios.get(category, f"在 {file_path}:{line} 发现安全漏洞。")
