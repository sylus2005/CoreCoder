#include <stdio.h>
#include <string.h>

int main() {
    char user_buf[64];
    printf("请输入你的昵称：");
    // 高危：strcpy不做长度检查，无边界限制，可控输入覆盖栈
    strcpy(user_buf, stdin);
    printf("你输入的昵称：%s\n", user_buf);
    return 0;
}