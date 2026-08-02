/**
 * network.c — 网络工具模块
 *
 * 预埋漏洞:
 *   - CWE-190: 整数溢出 (malloc(count * size) 未检查乘法溢出)
 *   - CWE-120: strcat 缓冲区溢出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * 分配网络缓冲区
 *
 * BUG: count * size 可能整数溢出导致分配不足。
 * 后续的写入操作将导致堆缓冲区溢出。
 * 严重性: MEDIUM (CWE-190)
 */
void *allocate_buffer(int count, int size) {
    return malloc(count * size);  // ← BUG: 未检查乘法溢出
}

/*
 * 拼接 URL
 *
 * BUG: strcat 不检查目标缓冲区边界。
 * 如果 base + path 总长度超过 256，将导致栈溢出。
 * 严重性: MEDIUM (CWE-120)
 */
void build_url(const char *base, const char *path) {
    char url[256];
    strcpy(url, base);
    strcat(url, path);  // ← BUG: 未检查 url 缓冲区大小
    printf("URL: %s\n", url);
}

/*
 * 发送数据
 */
int send_data(const char *host, int port, const char *data, int len) {
    printf("Sending %d bytes to %s:%d\n", len, host, port);

    // BUG: 直接使用 len 分配，未检查
    char *buf = (char *)allocate_buffer(len, 1);
    if (buf) {
        memcpy(buf, data, len);
        free(buf);
    }
    return 0;
}

int main(void) {
    printf("=== Network Test ===\n");
    build_url("https://api.example.com/v1/", "users/profile/../../admin/delete");
    send_data("192.168.1.1", 8080, "test", 4);
    return 0;
}
