"""CoreCoder Security Knowledge Base.

Attack patterns extracted from:
- mukul975/Anthropic-Cybersecurity-Skills
  - Web Application Security (42 skills)
  - API Security (28 skills)
  - Cloud Security (66 skills)
  - Container Security (33 skills)
  - AI Security (14 skills)

MVP 阶段: 仅提供精选的攻击模式数据结构，供 Hunt Agent Prompt 使用。
完整方案阶段: 扩展为独立的 Prompt 模板系统。
"""

# 精选攻击模式 — 注入类
INJECTION_PATTERNS = [
    {
        "category": "sql_injection",
        "cwe": "CWE-89",
        "description": "SQL injection via string concatenation in query building",
        "indicators": ["cursor.execute(f'...')", "query = 'SELECT' + user_input", "db.query(format(...))"],
        "fix": "Use parameterized queries: cursor.execute('SELECT ...', (param,))",
    },
    {
        "category": "xss",
        "cwe": "CWE-79",
        "description": "Cross-site scripting via unescaped user input in HTML/JS",
        "indicators": ["innerHTML =", "dangerouslySetInnerHTML", "document.write(", ".html("],
        "fix": "Use textContent, DOMPurify.sanitize(), or framework auto-escaping",
    },
]

# 精选攻击模式 — 认证类
AUTH_PATTERNS = [
    {
        "category": "hardcoded_credentials",
        "cwe": "CWE-798",
        "description": "Hardcoded passwords, API keys, or tokens in source code",
        "indicators": ["password = '", "api_key = \"", "secret = '", "token = '"],
        "fix": "Use environment variables or a secrets manager (AWS Secrets Manager, Vault)",
    },
    {
        "category": "default_password",
        "cwe": "CWE-1392",
        "description": "Default or weak credentials in configuration",
        "indicators": ["admin/admin", "root/root", "guest/guest", "password: 'password'"],
        "fix": "Enforce strong password policy; change defaults on first deployment",
    },
]

# 精选攻击模式 — 内存安全类
MEMORY_SAFETY_PATTERNS = [
    {
        "category": "buffer_overflow",
        "cwe": "CWE-120",
        "description": "Stack/heap buffer overflow via unbounded copy",
        "indicators": ["strcpy(", "strcat(", "sprintf(", "memcpy(..., user_len)", "gets("],
        "fix": "Use strncpy/strncat/snprintf with explicit size limits",
    },
    {
        "category": "use_after_free",
        "cwe": "CWE-416",
        "description": "Using memory after it has been freed",
        "indicators": ["free(ptr)", "ptr is used after free() call"],
        "fix": "Set pointer to NULL after free(); use RAII or defer patterns",
    },
]

# 所有模式汇总
ALL_ATTACK_PATTERNS = {
    "injection": INJECTION_PATTERNS,
    "authentication": AUTH_PATTERNS,
    "memory_safety": MEMORY_SAFETY_PATTERNS,
}
