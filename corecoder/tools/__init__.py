"""Tool registry."""

from .bash import BashTool
from .read import ReadFileTool
from .write import WriteFileTool
from .edit import EditFileTool
from .glob_tool import GlobTool
from .grep import GrepTool
from .agent import AgentTool
from .now import NowTool
from .fetch import FetchUrlTool
from .security.c_review import CReviewTool
from .security.insecure_defaults import InsecureDefaultsTool
from .security.injection_scanner import InjectionScannerTool
from .security.audit_tool import AuditTool
from .report_docx import GenerateDocxReportTool
from .report_pptx import GeneratePptxReportTool

ALL_TOOLS = [
    BashTool(),
    ReadFileTool(),
    WriteFileTool(),
    EditFileTool(),
    GlobTool(),
    GrepTool(),
    AgentTool(),
    NowTool(),
    FetchUrlTool(),
    CReviewTool(),
    InsecureDefaultsTool(),
    InjectionScannerTool(),
    AuditTool(),
    GenerateDocxReportTool(),
    GeneratePptxReportTool(),
]


def get_tool(name: str):
    """Look up a tool by name."""
    for t in ALL_TOOLS:
        if t.name == name:
            return t
    return None
