/**
 * CoreCoder Security Agent — API Layer
 * 封装与后端 FastAPI 的所有通信
 */

const API_BASE = 'http://49.233.195.118:8000';

/**
 * 启动安全审计 (正则 Pipeline - 快速扫描)
 * @param {string} target - 目标目录或文件路径
 * @param {string[]} tools - 启用的工具列表
 * @param {string} requirements - 用户自然语言需求
 * @returns {Promise<{audit_id: string, status: string}>}
 */
export async function startAudit(target, tools = ['c_review', 'insecure_defaults', 'injection_scanner'], requirements = '') {
  const res = await fetch(`${API_BASE}/api/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, tools, requirements }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * 上传文件到后端临时目录
 * @param {File[]} files - 文件列表
 * @param {string} folderName - 文件夹名称（用于组织上传文件）
 * @returns {Promise<{target_path: string, file_count: number, files: string[]}>}
 */
export async function uploadFiles(files, folderName = 'upload') {
  const formData = new FormData();
  for (const file of files) {
    formData.append('files', file);
  }
  formData.append('folder_name', folderName);

  const res = await fetch(`${API_BASE}/api/audit/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(errText || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * 建立 SSE 实时日志连接 (Pipeline 审计)
 * @param {string} auditId
 * @param {object} callbacks - { onPhase, onFinding, onLog, onDone, onError }
 * @returns {EventSource}
 */
export function connectAuditStream(auditId, callbacks = {}) {
  const es = new EventSource(`${API_BASE}/api/audit/${auditId}/stream`);

  es.addEventListener('phase', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onPhase?.(data);
  });

  es.addEventListener('finding', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onFinding?.(data);
  });

  es.addEventListener('log', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onLog?.(data);
  });

  es.addEventListener('done', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onDone?.(data);
    es.close();
  });

  // 自定义审计错误事件 (event: audit_error)
  es.addEventListener('audit_error', (e) => {
    try {
      const data = JSON.parse(e.data);
      callbacks.onLog?.({ message: `[ERROR] ${data.message}`, type: 'error' });
    } catch {}
  });

  // 浏览器原生连接错误 (不解析 data)
  es.addEventListener('error', () => {
    callbacks.onLog?.({ message: 'SSE connection lost, retrying...', type: 'error' });
  });

  // 默认 message 事件
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      callbacks.onLog?.(data);
    } catch {}
  };

  return es;
}

/**
 * 启动 LLM Agent 对话 (AI 驱动审计)
 * @param {string} message - 用户自然语言消息
 * @param {string} target - 审计目标路径
 * @param {string} sessionId - 可选: 会话 ID (用于多轮对话连贯性)
 * @returns {Promise<{chat_id: string, status: string, session_id: string}>}
 */
export async function startChat(message, target = '', sessionId = '') {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, target, session_id: sessionId }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * 建立 SSE 实时流连接 (Agent 对话)
 * @param {string} chatId
 * @param {object} callbacks - { onLog, onToolCall, onToken, onDone, onError }
 * @returns {EventSource}
 */
export function connectChatStream(chatId, callbacks = {}) {
  const es = new EventSource(`${API_BASE}/api/chat/${chatId}/stream`);

  es.addEventListener('log', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onLog?.(data);
  });

  es.addEventListener('tool_call', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onToolCall?.(data);
  });

  es.addEventListener('token', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onToken?.(data);
  });

  es.addEventListener('done', (e) => {
    const data = JSON.parse(e.data);
    callbacks.onDone?.(data);
    es.close();
  });

  es.addEventListener('chat_error', (e) => {
    try {
      const data = JSON.parse(e.data);
      callbacks.onLog?.({ message: `[ERROR] ${data.message}`, type: 'error' });
    } catch {}
  });

  es.addEventListener('error', () => {
    callbacks.onError?.();
  });

  return es;
}

/**
 * 获取完整审计报告
 * @param {string} auditId
 * @returns {Promise<object>}
 */
export async function getReport(auditId) {
  const res = await fetch(`${API_BASE}/api/audit/${auditId}/report`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * 下载 Agent 对话报告 (Word/Markdown)
 * @param {string} chatId - 对话 ID
 * @param {string} format - 输出格式 (docx | md)
 */
export function downloadChatReport(chatId, format = 'docx') {
  window.open(`${API_BASE}/api/chat/${chatId}/report?format=${format}`, '_blank');
}

/**
 * 健康检查
 * @returns {Promise<object>}
 */
export async function healthCheck() {
  const res = await fetch(`${API_BASE}/api/health`);
  return res.json();
}
