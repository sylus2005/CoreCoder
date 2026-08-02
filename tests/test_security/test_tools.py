"""Tests for CoreCoder Security Tools — MVP."""

import json
import pytest

from corecoder.tools.security.c_review import CReviewTool
from corecoder.tools.security.insecure_defaults import InsecureDefaultsTool
from corecoder.tools.security.injection_scanner import InjectionScannerTool


class TestCReviewTool:
    def test_name_and_schema(self):
        tool = CReviewTool()
        assert tool.name == "c_review"
        schema = tool.schema()
        assert schema["type"] == "function"
        assert "file_path" in schema["function"]["parameters"]["properties"]

    def test_detect_buffer_overflow(self, tmp_path):
        code = tmp_path / "test.c"
        code.write_text('#include <string.h>\nvoid f(char *d) { char b[64]; strcpy(b, d); }')
        tool = CReviewTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("strcpy" in f["title"].lower() for f in result["findings"])

    def test_detect_hardcoded_secret(self, tmp_path):
        code = tmp_path / "auth.c"
        code.write_text('const char *admin_pass = "SuperSecret123";')
        tool = CReviewTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("CWE-798" in f["cwe_id"] for f in result["findings"])

    def test_detect_format_string(self, tmp_path):
        code = tmp_path / "fmt.c"
        code.write_text('#include <stdio.h>\nvoid log(char *u) { printf(u); }')
        tool = CReviewTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("CWE-134" in f["cwe_id"] for f in result["findings"])

    def test_no_false_positive_on_safe_code(self, tmp_path):
        code = tmp_path / "safe.c"
        code.write_text('#include <stdio.h>\nint main() { printf("%s\\n", "hello"); return 0; }')
        tool = CReviewTool()
        result = json.loads(tool.execute(file_path=str(code)))
        # 安全代码不应有高危发现
        high = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert len(high) == 0

    def test_file_not_found(self):
        tool = CReviewTool()
        result = json.loads(tool.execute(file_path="/nonexistent/file.c"))
        assert "error" in result
        assert result["findings"] == []


class TestInsecureDefaultsTool:
    def test_name_and_schema(self):
        tool = InsecureDefaultsTool()
        assert tool.name == "insecure_defaults"
        schema = tool.schema()
        assert schema["type"] == "function"

    def test_detect_debug_mode_define(self, tmp_path):
        code = tmp_path / "config.h"
        code.write_text('#define DEBUG_MODE 1\n#define MAX 100')
        tool = InsecureDefaultsTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("DEBUG" in f["title"] for f in result["findings"])

    def test_detect_connection_string(self, tmp_path):
        code = tmp_path / "db.h"
        code.write_text('#define DB_CONNECTION_STRING "Server=prod;Password=Secret123;"')
        tool = InsecureDefaultsTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("CWE-798" in f["cwe_id"] for f in result["findings"])

    def test_safe_config(self, tmp_path):
        code = tmp_path / "safe.h"
        code.write_text('#define DEBUG_MODE 0\n#define PORT 8080')
        tool = InsecureDefaultsTool()
        result = json.loads(tool.execute(file_path=str(code)))
        highs = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert len(highs) == 0


class TestInjectionScannerTool:
    def test_name_and_schema(self):
        tool = InjectionScannerTool()
        assert tool.name == "injection_scanner"
        schema = tool.schema()
        assert schema["type"] == "function"

    def test_detect_sql_injection(self, tmp_path):
        code = tmp_path / "db.py"
        code.write_text('query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)')
        tool = InjectionScannerTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("CWE-89" in f["cwe_id"] for f in result["findings"])

    def test_detect_command_injection(self, tmp_path):
        code = tmp_path / "cmd.py"
        code.write_text('import os\nos.system(f"ping {user_host}")')
        tool = InjectionScannerTool()
        result = json.loads(tool.execute(file_path=str(code)))
        assert result["stats"]["total"] >= 1
        assert any("CWE-78" in f["cwe_id"] for f in result["findings"])

    def test_safe_code(self, tmp_path):
        code = tmp_path / "safe.py"
        code.write_text('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))')
        tool = InjectionScannerTool()
        result = json.loads(tool.execute(file_path=str(code)))
        highs = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert len(highs) == 0
