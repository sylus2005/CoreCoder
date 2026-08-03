"""Markdown 格式化工具。

调用 baoyu-format-markdown 子技能，优化 Markdown 文档的排版和格式。
"""

import subprocess
from pathlib import Path

from .base import Tool

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SKILL_DIR = _PROJECT_ROOT / "skills" / "content-creation-publisher"
_FORMAT_SCRIPT = _SKILL_DIR / "baoyu-format-markdown" / "scripts" / "main.ts"


class FormatMarkdownTool(Tool):
    """格式化和优化 Markdown 文档。

    自动修复中文标点导致的加粗 bug、在中文和英文之间添加空格、
    优化 CJK 字符间距、调整标题层级、统一文档风格。
    """

    name = "format_markdown"
    description = (
        "格式化和优化 Markdown 文档的排版。"
        "功能包括：修复中文标点导致的 **加粗 bug**、"
        "自动在中文和英文/数字之间添加空格、"
        "ASCII 标点转全角引号、CJK 字符间距优化、"
        "自动格式化 YAML frontmatter 并调整缩进。"
        "适用于：优化采集的网页内容、格式化原创文章、统一文档风格。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "要格式化的 Markdown 文件路径（绝对路径或相对于工作目录的路径）",
            },
            "fix_quotes": {
                "type": "boolean",
                "description": "是否将 ASCII 引号替换为全角引号（默认 false，仅中文场景建议开启）",
            },
            "fix_spacing": {
                "type": "boolean",
                "description": "是否修复 CJK/英文间距（默认 true）",
            },
            "fix_emphasis": {
                "type": "boolean",
                "description": "是否修复 CJK 加粗标点问题（默认 true）",
            },
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        fix_quotes: bool = False,
        fix_spacing: bool = True,
        fix_emphasis: bool = True,
    ) -> str:
        """执行 Markdown 格式化，返回格式化结果。"""
        path = Path(file_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists():
            return f"❌ 文件不存在：{path}"

        if not _FORMAT_SCRIPT.exists():
            return (
                f"❌ 脚本未找到：{_FORMAT_SCRIPT}\n"
                "请确认 skills/content-creation-publisher/ 已正确安装。"
            )

        cmd = ["npx.cmd", "tsx", str(_FORMAT_SCRIPT), str(path)]
        if fix_quotes:
            cmd.append("--quotes")
        if not fix_spacing:
            cmd.append("--no-spacing")
        if not fix_emphasis:
            cmd.append("--no-emphasis")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                cwd=str(_SKILL_DIR),
            )
        except subprocess.TimeoutExpired:
            return "⏱ 格式化超时（30s）。文件可能过大，请尝试分段处理。"
        except FileNotFoundError:
            return "❌ 未找到 npx。请确认 Node.js 已安装并加入 PATH。"

        if proc.returncode != 0:
            err = proc.stderr.strip() or "(无错误输出)"
            return f"❌ 格式化失败（exit {proc.returncode}）：\n{err}"

        lines = ["✅ 格式化完成！"]
        lines.append(f"📄 文件：{path}")

        if fix_quotes:
            lines.append("🔤 引号替换：已开启")
        if fix_spacing:
            lines.append("↔ CJK/英文间距：已优化")
        if fix_emphasis:
            lines.append("✨ 加粗标点：已修复")

        lines.append(f"\n{proc.stdout.strip()}")
        return "\n".join(lines)
