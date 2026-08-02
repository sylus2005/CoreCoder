/**
 * config.h — 全局配置头文件
 *
 * 预埋漏洞:
 *   - CWE-215: 调试模式在生产环境启用 (DEBUG printf 泄露敏感信息)
 *   - 敏感配置硬编码
 */

#ifndef CONFIG_H
#define CONFIG_H

/* ===== 运行模式 ===== */

/*
 * BUG: DEBUG_MODE 在生产构建中应设为 0。
 * 当前开启状态会通过 printf 泄露内部状态和栈信息。
 * 严重性: LOW (CWE-215)
 */
#define DEBUG_MODE 1  // ← BUG: 生产环境应关闭

/* ===== 连接配置 ===== */
#define DEFAULT_PORT 80
#define MAX_CONNECTIONS 1000
#define CONNECTION_TIMEOUT 30  // 秒

/* ===== 日志配置 ===== */
#define LOG_LEVEL 0  // 0=TRACE, 1=DEBUG, 2=INFO, 3=WARN, 4=ERROR

// BUG: 硬编码的数据库连接字符串 (CWE-798)
#define DB_CONNECTION_STRING "Server=prod-db.internal:5432;Database=app;User Id=admin;Password=SecretPass123;"

#endif /* CONFIG_H */
