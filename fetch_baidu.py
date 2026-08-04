# -*- coding: utf-8 -*-
"""抓取百度网页首页内容"""
import urllib.request
import urllib.parse
import sys

def fetch_baidu(url="https://www.baidu.com", save_path="baidu_home.html"):
    """抓取指定 URL 的网页内容并保存到本地文件"""
    # 设置请求头，模拟浏览器访问，避免被反爬
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            # 读取原始字节
            raw = resp.read()
            # 尝试从响应头获取编码
            charset = resp.headers.get_content_charset()
            if not charset:
                charset = "utf-8"

            try:
                html = raw.decode(charset)
            except (UnicodeDecodeError, LookupError):
                # 回退到 utf-8 或 gbk
                for enc in ("utf-8", "gbk", "gb2312"):
                    try:
                        html = raw.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    html = raw.decode("utf-8", errors="replace")

            # 保存到文件
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(html)

            print(f"[OK] 抓取成功: {url}")
            print(f"[OK] 保存到: {save_path}")
            print(f"[INFO] 内容大小: {len(html)} 字符")
            return html

    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP 错误: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print(f"[ERROR] 网络错误: {e.reason}")
    except Exception as e:
        print(f"[ERROR] 未知错误: {e}")
    return None


if __name__ == "__main__":
    # 支持命令行参数: python fetch_baidu.py [url] [save_path]
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://www.baidu.com"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "baidu_home.html"
    fetch_baidu(target_url, out_path)
