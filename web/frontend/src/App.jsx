import React, { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { Layout, Button, Space, Typography, ConfigProvider, theme, Tag, Input, Tooltip } from 'antd';
import {
  PlayCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ThunderboltFilled,
  RobotOutlined,
  SendOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import UploadPanel from './components/UploadPanel';
import AuditLog from './components/AuditLog';
import ReportView from './components/ReportView';
import HistoryPanel from './components/HistoryPanel';
import { startAudit, connectAuditStream, startChat, connectChatStream } from './api';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;
const { TextArea } = Input;

const DEFAULT_TARGET = './demo/vulnerable-utils/';
const HISTORY_KEY = 'corecoder_chat_history';

// ★ 从 AI 响应中提取对话主题
function extractTopic(chatContent) {
  if (!chatContent) return '';
  // 尝试提取第一个 # 标题
  const h1Match = chatContent.match(/^#\s+(.+)$/m);
  if (h1Match) return h1Match[1].trim().substring(0, 60);
  // 尝试提取第一个 ## 标题
  const h2Match = chatContent.match(/^##\s+(.+)$/m);
  if (h2Match) return h2Match[1].trim().substring(0, 60);
  // 否则取第一行非空文本
  const firstLine = chatContent.split('\n').find((l) => l.trim() && !l.startsWith('```'));
  if (firstLine) {
    const cleaned = firstLine.replace(/^[#*\-\s]+/, '').trim();
    return cleaned.substring(0, 60);
  }
  return '';
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveHistory(entries) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
  } catch { /* storage full — ignore */ }
}

export default function App() {
  const [auditing, setAuditing] = useState(false);
  const [auditId, setAuditId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [phaseInfo, setPhaseInfo] = useState({});
  const [summary, setSummary] = useState(null);
  const [reportMd, setReportMd] = useState('');
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [requirements, setRequirements] = useState('');
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploadedTargetPath, setUploadedTargetPath] = useState('');
  const [chatMode, setChatMode] = useState(false);
  const [chatContent, setChatContent] = useState('');
  const [toolCalls, setToolCalls] = useState([]);
  const [chatDone, setChatDone] = useState(false);
  const [sessionId, setSessionId] = useState('');  // ★ 多轮对话 session
  const [history, setHistory] = useState(loadHistory); // ★ 历史记录
  const [lastUserMessage, setLastUserMessage] = useState(''); // ★ 最近一条用户消息

  const eventSourceRef = useRef(null);
  const inputRef = useRef(null);

  // ★ 从 chatContent 提取对话主题
  const conversationTopic = useMemo(() => extractTopic(chatContent), [chatContent]);

  // 持久化历史记录
  useEffect(() => {
    saveHistory(history);
  }, [history]);

  const addLog = useCallback((message, type = 'info') => {
    setLogs((prev) => [...prev, { id: Date.now(), message, type, time: new Date().toLocaleTimeString() }]);
  }, []);

  const reset = useCallback(() => {
    setAuditing(false);
    setAuditId(null);
    setLogs([]);
    setFindings([]);
    setPhaseInfo({});
    setSummary(null);
    setReportMd('');
    setChatContent('');
    setChatMode(false);
    setToolCalls([]);
    setChatDone(false);
    setLastUserMessage('');
    // ★ 保持 sessionId 不变（维持多轮对话连续性）
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  // ★ 完全重置（包括 session，切换上下文时用）
  const fullReset = useCallback(() => {
    setSessionId('');
    reset();
  }, [reset]);

  // ★ 新建对话: 清空当前内容 + 生成新 sessionId
  const handleNewConversation = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setAuditing(false);
    setAuditId(null);
    setLogs([]);
    setFindings([]);
    setPhaseInfo({});
    setSummary(null);
    setReportMd('');
    setChatContent('');
    setChatMode(false);
    setToolCalls([]);
    setChatDone(false);
    setLastUserMessage('');
    setSessionId('');  // ★ 生成新的 sessionId
    // 聚焦输入框
    inputRef.current?.focus();
  }, []);

  // 文件上传成功回调
  const handleFilesUploaded = useCallback((targetPath, files) => {
    setUploadedTargetPath(targetPath);
    setUploadedFiles(files);
    setTarget(targetPath);
    addLog(`📤 已上传 ${files.length} 个文件到: ${targetPath}`, 'success');
  }, [addLog]);

  const handleClearFiles = useCallback(() => {
    setUploadedFiles([]);
    if (uploadedTargetPath && target === uploadedTargetPath) {
      setTarget(DEFAULT_TARGET);
    }
    setUploadedTargetPath('');
  }, [uploadedTargetPath, target]);

  // ── 快速 Pipeline 审计 ──────────────────────────────

  const handlePipelineAudit = useCallback(async () => {
    reset();
    setAuditing(true);
    setChatMode(false);
    addLog('🔗 Connecting to CoreCoder Security Engine (Pipeline)...', 'info');

    try {
      const auditTarget = uploadedTargetPath || target;
      const { audit_id } = await startAudit(auditTarget);
      setAuditId(audit_id);
      addLog(`✅ Audit session started — ID: ${audit_id}`, 'success');
      addLog(`📂 Target: ${auditTarget}`, 'info');

      const es = connectAuditStream(audit_id, {
        onPhase: (data) => {
          setPhaseInfo((prev) => ({ ...prev, [data.phase]: data.status }));
          addLog(data.message || `[${data.phase}] ${data.status}`, data.status === 'done' ? 'success' : 'info');
        },
        onFinding: (data) => {
          setFindings((prev) => [...prev, data]);
        },
        onLog: (data) => {
          addLog(data.message || JSON.stringify(data), 'info');
        },
        onDone: (data) => {
          setSummary(data.summary);
          setReportMd(data.report_md || '');
          addLog(`🎯 Audit complete! Found ${data.summary?.total || 0} vulnerabilities.`, 'success');
          setAuditing(false);
        },
        onError: () => {
          addLog('⚠️ SSE connection error', 'error');
        },
      });
      eventSourceRef.current = es;
    } catch (err) {
      addLog(`❌ Startup failed: ${err.message}`, 'error');
      setAuditing(false);
    }
  }, [target, uploadedTargetPath, reset, addLog]);

  // ── AI Agent 对话审计 ──────────────────────────────

  const handleChatAudit = useCallback(async (message) => {
    reset();
    setAuditing(true);
    setChatMode(true);
    setChatContent('');
    setLastUserMessage(message);

    addLog('🤖 Starting CoreCoder AI Agent...', 'info');

    const auditTarget = uploadedTargetPath || target;
    const msg = message.trim() || `请审计目标路径: ${auditTarget}`;

    try {
      // ★ 传入 session_id 实现多轮对话
      const { chat_id, session_id } = await startChat(msg, auditTarget, sessionId || undefined);
      if (!sessionId) {
        setSessionId(session_id);
      }
      setAuditId(chat_id);
      addLog(`✅ AI Agent connected — ID: ${chat_id}`, 'success');
      addLog(`💬 "${msg}"`, 'info');
      addLog(`📂 Target: ${auditTarget}`, 'info');

      let lastContent = '';
      const es = connectChatStream(chat_id, {
        onLog: (data) => {
          addLog(data.message || JSON.stringify(data), 'info');
        },
        onToolCall: (data) => {
          setToolCalls((prev) => [...prev, { ...data, id: Date.now(), time: new Date().toLocaleTimeString() }]);
          addLog(`🔧 Tool: ${data.tool}(${JSON.stringify(data.arguments)})`, 'finding');
        },
        onToken: (data) => {
          lastContent += (data.content || '');
          setChatContent((prev) => prev + (data.content || ''));
        },
        onDone: (data) => {
          const finalContent = data.content || lastContent;
          if (finalContent) {
            setChatContent(finalContent);
          }
          setChatDone(true);
          addLog('✅ AI Agent 分析完成', 'success');
          setAuditing(false);

          // ★ 保存到历史记录
          const entry = {
            id: chat_id,
            session_id: sessionId || session_id,
            message: msg,
            target: auditTarget,
            chatContent: finalContent,
            toolCalls: [],
            timestamp: Date.now(),
          };
          setHistory((prev) => {
            const filtered = prev.filter((h) => h.session_id !== entry.session_id);
            return [entry, ...filtered].slice(0, 50);
          });
        },
        onError: () => {
          addLog('⚠️ Agent connection lost', 'error');
        },
      });
      eventSourceRef.current = es;
    } catch (err) {
      addLog(`❌ Agent startup failed: ${err.message}`, 'error');
      setAuditing(false);
    }
  }, [target, uploadedTargetPath, sessionId, reset, addLog]);

  // ── Start: 智能选择 Pipeline 或 Agent ──────────────

  const handleStart = useCallback(async () => {
    if (requirements.trim()) {
      const msg = requirements.trim();
      setRequirements('');  // ★ 清空输入框
      await handleChatAudit(msg);
    } else {
      await handlePipelineAudit();
    }
  }, [requirements, handleChatAudit, handlePipelineAudit]);

  // ── 底部输入框提交 ──────────────────────────────

  const handleInputSubmit = useCallback(() => {
    if (!requirements.trim()) return;
    handleStart();
  }, [requirements, handleStart]);

  const handleInputKeyDown = useCallback((e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleInputSubmit();
    }
  }, [handleInputSubmit]);

  // ── 历史记录操作 ──────────────────────────────

  const handleHistorySelect = useCallback((item) => {
    if (item.session_id) {
      setSessionId(item.session_id);
    }
    setChatContent(item.chatContent || '');
    setChatMode(true);
    setChatDone(true);
    setAuditId(item.id);
    setTarget(item.target || DEFAULT_TARGET);
    setAuditing(false);
    setLastUserMessage(item.message || '');
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  const handleHistoryDelete = useCallback((id) => {
    setHistory((prev) => prev.filter((h) => h.id !== id));
  }, []);

  // Live stats for header
  const highCount = findings.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL').length;
  const medCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFORMATIONAL').length;

  return (
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#6366f1',
          borderRadius: 8,
          colorBgContainer: '#ffffff',
          fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        },
      }}
    >
      <Layout className="app-layout" style={{ minHeight: '100vh', background: '#f0f2f5' }}>
        {/* ── Gradient Header ── */}
        <Header
          className="header-gradient"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 28px',
            height: 64,
            lineHeight: 'normal',
            flexShrink: 0,
          }}
        >
          <Space size={12}>
            <div style={{
              width: 38, height: 38, borderRadius: 10,
              background: 'rgba(255,255,255,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              backdropFilter: 'blur(8px)',
              flexShrink: 0,
            }}>
              <SafetyCertificateOutlined style={{ fontSize: 20, color: '#fff' }} />
            </div>
            <div>
              <div style={{ color: '#fff', fontSize: 18, fontWeight: 700, lineHeight: 1.2, letterSpacing: '-0.3px' }}>
                CoreCoder Security Agent
              </div>
              <div style={{ color: 'rgba(255,255,255,0.7)', fontSize: 11, fontWeight: 400 }}>
                AI-Powered Cybersecurity Audit Dashboard
              </div>
            </div>
          </Space>

          <Space size={16}>
            {findings.length > 0 && (
              <Space size={10}>
                <Tag color="error" style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}>
                  🔴 {highCount} High
                </Tag>
                <Tag color="warning" style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}>
                  🟡 {medCount} Med
                </Tag>
                <Tag color="success" style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}>
                  🟢 {lowCount} Low
                </Tag>
              </Space>
            )}
            {chatMode && (
              <Tag color="purple" style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}>
                <RobotOutlined /> AI Agent
              </Tag>
            )}
            {/* ★ 添加新对话按钮 */}
            <Tooltip title="新建对话">
              <Button
                icon={<PlusOutlined />}
                onClick={handleNewConversation}
                style={{
                  borderRadius: 10,
                  height: 40,
                  fontWeight: 500,
                  background: 'rgba(255,255,255,0.15)',
                  borderColor: 'rgba(255,255,255,0.25)',
                  color: '#fff',
                }}
              >
                新对话
              </Button>
            </Tooltip>
            <Button
              type="primary"
              icon={auditing ? <ReloadOutlined spin /> : <ThunderboltFilled />}
              onClick={handleStart}
              loading={auditing}
              size="large"
              style={{
                background: auditing ? undefined : 'rgba(255,255,255,0.2)',
                borderColor: 'rgba(255,255,255,0.3)',
                backdropFilter: 'blur(8px)',
                fontWeight: 600,
                borderRadius: 10,
                height: 40,
              }}
            >
              {auditing ? (chatMode ? 'AI Analyzing...' : 'Auditing...') : 'Start Audit'}
            </Button>
            {!auditing && (summary || chatContent) && (
              <Button
                icon={<ReloadOutlined />}
                onClick={fullReset}
                style={{ borderRadius: 10, height: 40, fontWeight: 500 }}
              >
                Reset
              </Button>
            )}
          </Space>
        </Header>

        {/* ── Body: Sider + Content (side by side) ── */}
        <Layout style={{ background: '#f0f2f5', flex: 1, overflow: 'hidden' }}>
          {/* ── Left Sidebar ── */}
          <Sider
            width={300}
            style={{
              background: '#ffffff',
              boxShadow: '2px 0 20px rgba(0,0,0,0.04)',
              padding: 20,
              borderRight: 'none',
              overflow: 'auto',
              flexShrink: 0,
            }}
          >
            <UploadPanel
              target={target}
              onTargetChange={setTarget}
              disabled={auditing}
              onFilesUploaded={handleFilesUploaded}
              uploadedFiles={uploadedFiles}
              onClearFiles={handleClearFiles}
            >
              {/* ★ HistoryPanel 插入到 Target Path 下方、Enabled Tools 上方 */}
              <HistoryPanel
                history={history}
                onSelect={handleHistorySelect}
                onDelete={handleHistoryDelete}
                activeSessionId={sessionId}
              />
            </UploadPanel>
          </Sider>

          {/* ── Right Content Area (含主内容 + 底部输入栏) ── */}
          <Content style={{
            display: 'flex',
            flexDirection: 'column',
            background: '#f0f2f5',
            overflow: 'hidden',
            flex: 1,
          }}>
            {/* 可滚动主内容区 */}
            <div style={{
              flex: 1,
              overflow: 'auto',
              padding: '24px 28px 0 28px',
            }}>
              {!summary && !chatContent ? (
                <AuditLog
                  logs={logs}
                  phaseInfo={phaseInfo}
                  findings={findings}
                  auditing={auditing}
                  chatMode={chatMode}
                  chatContent={chatContent}
                  toolCalls={toolCalls}
                  chatDone={chatDone}
                  auditId={auditId}
                  conversationTopic={conversationTopic}
                  lastUserMessage={lastUserMessage}
                />
              ) : chatMode && chatContent ? (
                <AuditLog
                  logs={logs}
                  phaseInfo={phaseInfo}
                  findings={findings}
                  auditing={auditing}
                  chatMode={chatMode}
                  chatContent={chatContent}
                  toolCalls={toolCalls}
                  chatDone={chatDone}
                  auditId={auditId}
                  conversationTopic={conversationTopic}
                  lastUserMessage={lastUserMessage}
                />
              ) : (
                <ReportView
                  summary={summary}
                  findings={findings}
                  reportMd={reportMd}
                  phaseInfo={phaseInfo}
                />
              )}
            </div>

            {/* ── ★ 底部输入栏 (内容区域内，居中) ── */}
            <div style={{
              flexShrink: 0,
              background: '#ffffff',
              borderTop: '1px solid #e2e8f0',
              padding: '14px 40px',
              display: 'flex',
              alignItems: 'flex-end',
              justifyContent: 'center',
              gap: 12,
              boxShadow: '0 -2px 12px rgba(0,0,0,0.04)',
            }}>
              {/* 输入区域：限制最大宽度 + 居中 */}
              <div style={{
                display: 'flex',
                alignItems: 'flex-end',
                gap: 12,
                width: '100%',
                maxWidth: 860,
              }}>
                <TextArea
                  ref={inputRef}
                  value={requirements}
                  onChange={(e) => setRequirements(e.target.value)}
                  onKeyDown={handleInputKeyDown}
                  disabled={auditing}
                  placeholder={
                    'Describe what you want to audit... e.g. "审计这个程序的SQL注入漏洞" or "检查C代码的内存安全问题"  (Enter to send, Shift+Enter for new line)'
                  }
                  rows={1}
                  autoSize={{ minRows: 1, maxRows: 3 }}
                  style={{
                    flex: 1,
                    borderRadius: 10,
                    borderColor: '#e2e8f0',
                    fontSize: 13,
                    resize: 'none',
                  }}
                />
                <Button
                  type="primary"
                  icon={<SendOutlined />}
                  onClick={handleInputSubmit}
                  disabled={auditing || !requirements.trim()}
                  loading={auditing}
                  style={{
                    borderRadius: 10,
                    fontWeight: 600,
                    height: 40,
                    paddingLeft: 20,
                    paddingRight: 20,
                    background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
                    border: 'none',
                    flexShrink: 0,
                  }}
                >
                  Send
                </Button>
              </div>
            </div>
          </Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
