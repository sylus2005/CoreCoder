"""请求/响应数据模型."""

from pydantic import BaseModel


class AuditRequest(BaseModel):
    """启动审计请求."""
    target: str = "./demo/vulnerable-utils/"
    tools: list[str] = ["c_review", "insecure_defaults", "injection_scanner"]
    model: str = ""
    requirements: str = ""  # 用户自然语言描述的需求


class AuditResponse(BaseModel):
    """审计启动响应."""
    audit_id: str
    status: str


class UploadResponse(BaseModel):
    """文件上传响应."""
    target_path: str
    file_count: int
    files: list[str]


class ChatRequest(BaseModel):
    """LLM Agent 对话请求."""
    message: str
    target: str = ""  # 可选: 审计目标路径
    session_id: str = ""  # 可选: 会话 ID (用于多轮对话)


class ChatResponse(BaseModel):
    """对话启动响应."""
    chat_id: str
    status: str
