/**
 * parser.c — 数据包解析模块
 *
 * 预埋漏洞:
 *   - CWE-120: 缓冲区溢出 (memcpy 未检查边界)
 *   - CWE-476: 空指针解引用 (malloc 未检查返回值)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET 4096

/*
 * 解析收到的数据包
 *
 * BUG: 直接使用用户传入的 len 作为 memcpy 长度，
 * 如果 len > 64 将导致栈缓冲区溢出。
 * 严重性: HIGH (CWE-120)
 */
void parse_packet(const char *user_data, int user_len) {
    char buffer[64];
    memcpy(buffer, user_data, user_len);  // ← BUG: 未检查 user_len <= 64
    printf("Parsed packet: %s\n", buffer);
}

/*
 * 分配并初始化缓冲区
 *
 * BUG: malloc 返回 NULL 时未检查，后续 memset 触发空指针解引用。
 * 严重性: LOW (CWE-476)
 */
char *create_buffer(int size) {
    char *buf = (char *)malloc(size);  // ← BUG: 未检查 malloc 返回值
    memset(buf, 0, size);
    return buf;
}

/*
 * 处理请求
 */
void handle_request(const char *data, int length) {
    if (length > MAX_PACKET) {
        printf("Packet too large\n");
        return;
    }
    parse_packet(data, length);
}

int main(int argc, char **argv) {
    // 模拟接收外部数据
    char test_data[128];
    memset(test_data, 'A', sizeof(test_data));

    printf("=== Parser Test ===\n");
    handle_request(test_data, 128);  // 故意传入超过 buffer[64] 的长度
    return 0;
}
