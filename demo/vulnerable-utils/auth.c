/**
 * auth.c — 认证模块
 *
 * 预埋漏洞:
 *   - CWE-798: 硬编码凭据 (管理员密码写死在源码中)
 *   - CWE-134: 格式化字符串漏洞 (printf 使用非字面量格式串)
 */

#include <stdio.h>
#include <string.h>

/*
 * 验证用户凭据
 *
 * BUG 1: admin_pass 是硬编码密码，攻击者可通过 git log 或 strings 获取。
 *        严重性: HIGH (CWE-798)
 *
 * BUG 2: printf(username) 将用户输入作为格式字符串，
 *        攻击者可传入 %x/%n 泄露或修改内存。
 *        严重性: HIGH (CWE-134)
 */
int authenticate(const char *username, const char *password) {
    const char *admin_pass = "Admin123!@#";  // ← BUG: 硬编码密码
    printf(username);  // ← BUG: 格式字符串漏洞
    printf(" attempting login\n");
    return strcmp(password, admin_pass) == 0;
}

/*
 * 修改密码 (预留功能)
 */
int change_password(const char *username, const char *old_pass, const char *new_pass) {
    // 简化实现: 总是失败
    printf("Password change not implemented for %s\n", username);
    return 0;
}

int main(void) {
    printf("=== Auth Test ===\n");
    int ok = authenticate("admin", "wrong");
    printf("Auth result: %s\n", ok ? "OK" : "FAIL");

    // 注意: admin 密码是 Admin123!@#
    ok = authenticate("admin", "Admin123!@#");
    printf("Auth result: %s\n", ok ? "OK" : "FAIL");

    return 0;
}
