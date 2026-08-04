import React, { useState, useRef, useCallback, useEffect } from 'react';
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
import LandingPage from './components/LandingPage';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;
const { TextArea } = Input;

const DEFAULT_TARGET = '';
const HISTORY_KEY = 'corecoder_chat_history';

// ★ 从用户消息中提取对话主题（固定使用第一次请求）
function extractTopic(message) {
  if (!message) return '';
  const cleaned = message.replace(/^[#*\-\s]+/, '').trim();
  return cleaned.substring(0, 60);
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
  const [chatDone, setChatDone] = useState(false);
  const [sessionId, setSessionId] = useState('');

  // ★★★ 多轮对话状态（重构：取代单一 chatContent / toolCalls / lastUserMessage）★★★
  // turns: [{userMessage, aiResponse, timestamp, toolCalls}]
  const [turns, setTurns] = useState([]);
  // 当前轮次的流式响应（存在状态中以便中途渲染）
  const [currentResponse, setCurrentResponse] = useState('');
  // 当前轮次的工具调用
  const [currentToolCalls, setCurrentToolCalls] = useState([]);
  // ★ 对话主题：从第一次用户需求提取后固定，不再变化
  const [conversationTopic, setConversationTopic] = useState('');

  // ★ 日志隔离 token：每次新建对话更新，日志回调中校验
  const [logSessionToken, setLogSessionToken] = useState(Date.now);

  // 历史记录
  const [history, setHistory] = useState(loadHistory);

  const eventSourceRef = useRef(null);
  const inputRef = useRef(null);
  // ★ 用 ref 存储 logSessionToken，确保 SSE 回调中读取最新值
  const logTokenRef = useRef(logSessionToken);
  useEffect(() => { logTokenRef.current = logSessionToken; }, [logSessionToken]);

  // 持久化历史记录
  useEffect(() => {
    saveHistory(history);
  }, [history]);

  // ── 日志工具函数 ──────────────────────────────

  const addLog = useCallback((message, type = 'info') => {
    setLogs((prev) => [...prev, {
      id: Date.now(),
      message,
      type,
      time: new Date().toLocaleTimeString(),
    }]);
  }, []);

  // ★ 带 token 校验的日志：仅当 session token 匹配时才添加日志
  const addLogChecked = useCallback((message, type = 'info', token) => {
    if (token !== logTokenRef.current) return; // 旧会话的事件，丢弃
    setLogs((prev) => [...prev, {
      id: Date.now(),
      message,
      type,
      time: new Date().toLocaleTimeString(),
    }]);
  }, []);

  // ── 重置函数 ──────────────────────────────

  // ★ 轻量重置：清除瞬时 UI 状态（用于同一会话内发送新请求）
  const resetTransient = useCallback(() => {
    setAuditing(false);
    setChatDone(false);
    setCurrentResponse('');
    setCurrentToolCalls([]);
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  // ★ 完全重置：清除一切（Pipeline 模式切换、点击 Reset、报告后返回）
  const fullReset = useCallback(() => {
    setAuditing(false);
    setAuditId(null);
    setLogs([]);
    setFindings([]);
    setPhaseInfo({});
    setSummary(null);
    setReportMd('');
    setChatMode(false);
    setChatDone(false);
    setTurns([]);
    setCurrentResponse('');
    setCurrentToolCalls([]);
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  // ★ 新建对话：完全重置 + 清除 session + 更新日志 token + 新 topic
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
    setChatMode(false);
    setChatDone(false);
    setTurns([]);
    setCurrentResponse('');
    setCurrentToolCalls([]);
    setSessionId('');
    setConversationTopic('');
    const newToken = Date.now();
    setLogSessionToken(newToken);
    logTokenRef.current = newToken;
    // 聚焦输入框
    inputRef.current?.focus();
  }, []);

  // ── 文件上传回调 ──────────────────────────────

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
    fullReset();
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
  }, [target, uploadedTargetPath, fullReset, addLog]);

  // ── AI Agent 对话审计（多轮对话）──────────────────────

  const handleChatAudit = useCallback(async (message) => {
    // ★ 不调用 fullReset！保留之前的 turns、logs、topic
    resetTransient();
    setAuditing(true);
    setChatMode(true);
    setCurrentResponse('');
    setCurrentToolCalls([]);

    // ★ 第一次请求：固定对话主题
    if (turns.length === 0 && !conversationTopic) {
      const topic = extractTopic(message);
      setConversationTopic(topic);
    }

    // ★ 追加新的 turn（响应先为空）
    const newTurn = {
      userMessage: message,
      aiResponse: '',
      timestamp: Date.now(),
      toolCalls: [],
    };
    setTurns((prev) => [...prev, newTurn]);

    addLog('🤖 Starting CoreCoder AI Agent...', 'info');

    const auditTarget = uploadedTargetPath || target;
    const msg = message.trim() || `请审计目标路径: ${auditTarget}`;

    // 捕获当前 session token 用于 SSE 回调过滤
    const sessionToken = logTokenRef.current;

    try {
      const { chat_id, session_id } = await startChat(msg, auditTarget, sessionId || undefined);
      if (!sessionId) {
        setSessionId(session_id);
      }
      setAuditId(chat_id);
      addLogChecked(`✅ AI Agent connected — ID: ${chat_id}`, 'success', sessionToken);
      addLogChecked(`💬 "${msg}"`, 'info', sessionToken);
      addLogChecked(`📂 Target: ${auditTarget}`, 'info', sessionToken);

      let lastContent = '';
      const turnIndex = turns.length; // 当前 turn 的索引（追加前 turns 的长度）

      const es = connectChatStream(chat_id, {
        onLog: (data) => {
          addLogChecked(data.message || JSON.stringify(data), 'info', sessionToken);
        },
        onToolCall: (data) => {
          const tcEntry = { ...data, id: Date.now(), time: new Date().toLocaleTimeString() };
          setCurrentToolCalls((prev) => [...prev, tcEntry]);
          // 同时更新当前 turn 的 toolCalls
          setTurns((prev) => {
            const updated = [...prev];
            if (updated[turnIndex]) {
              updated[turnIndex] = {
                ...updated[turnIndex],
                toolCalls: [...updated[turnIndex].toolCalls, tcEntry],
              };
            }
            return updated;
          });
          addLogChecked(`🔧 Tool: ${data.tool}(${JSON.stringify(data.arguments)})`, 'finding', sessionToken);
        },
        onToken: (data) => {
          lastContent += (data.content || '');
          setCurrentResponse((prev) => prev + (data.content || ''));
          // 同时更新当前 turn 的响应
          setTurns((prev) => {
            const updated = [...prev];
            if (updated[turnIndex]) {
              updated[turnIndex] = {
                ...updated[turnIndex],
                aiResponse: updated[turnIndex].aiResponse + (data.content || ''),
              };
            }
            return updated;
          });
        },
        onDone: (data) => {
          const finalContent = data.content || lastContent;
          setCurrentResponse(finalContent);
          // 最终更新当前 turn
          setTurns((prev) => {
            const updated = [...prev];
            if (updated[turnIndex]) {
              updated[turnIndex] = {
                ...updated[turnIndex],
                aiResponse: finalContent || updated[turnIndex].aiResponse,
              };
            }
            return updated;
          });
          setChatDone(true);
          addLogChecked('✅ AI Agent 分析完成', 'success', sessionToken);
          setAuditing(false);

          // ★ 保存到历史记录（含完整 turns）
          setTurns((currentTurns) => {
            const entry = {
              id: chat_id,
              session_id: sessionId || session_id,
              topic: conversationTopic || extractTopic(message),
              turns: currentTurns.map((t) => ({
                userMessage: t.userMessage,
                aiResponse: t.aiResponse,
                timestamp: t.timestamp,
                toolCalls: t.toolCalls,
              })),
              target: auditTarget,
              timestamp: Date.now(),
            };
            setHistory((prev) => {
              const filtered = prev.filter((h) => h.session_id !== entry.session_id);
              return [entry, ...filtered].slice(0, 50);
            });
            return currentTurns;
          });
        },
        onError: () => {
          addLogChecked('⚠️ Agent connection lost', 'error', sessionToken);
        },
      });
      eventSourceRef.current = es;
    } catch (err) {
      addLogChecked(`❌ Agent startup failed: ${err.message}`, 'error', sessionToken);
      setAuditing(false);
    }
  }, [target, uploadedTargetPath, sessionId, turns, conversationTopic, resetTransient, addLog, addLogChecked]);

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
    setTurns(item.turns || []);
    setConversationTopic(item.topic || '');
    setChatMode(true);
    setChatDone(true);
    setAuditId(item.id);
    setTarget(item.target || DEFAULT_TARGET);
    setAuditing(false);
    setCurrentResponse('');
    setCurrentToolCalls([]);
    // ★ 更新日志 token，防止旧 SSE 事件污染
    const newToken = Date.now();
    setLogSessionToken(newToken);
    logTokenRef.current = newToken;
    // ★ 清空日志（切换到历史对话）
    setLogs([]);
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

  // ★ 判断是否有 chat 内容要展示（turns 有内容 或 正在流式接收）
  const hasChatContent = turns.length > 0 || currentResponse;

  // ★ 开场页门控 — LandingPage 自身管理显隐，每次挂载自动显示
  // 始终渲染主应用 + LandingPage（叠加在上面），不依赖父组件 state
  return (
    <>
      <LandingPage />
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
            {/* ★ 新建对话按钮 */}
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
            {!auditing && (summary || hasChatContent) && (
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
              {!summary && !hasChatContent ? (
                <AuditLog
                  logs={logs}
                  phaseInfo={phaseInfo}
                  findings={findings}
                  auditing={auditing}
                  chatMode={chatMode}
                  turns={turns}
                  currentResponse={currentResponse}
                  currentToolCalls={currentToolCalls}
                  chatDone={chatDone}
                  auditId={auditId}
                  conversationTopic={conversationTopic}
                />
              ) : chatMode && hasChatContent ? (
                <AuditLog
                  logs={logs}
                  phaseInfo={phaseInfo}
                  findings={findings}
                  auditing={auditing}
                  chatMode={chatMode}
                  turns={turns}
                  currentResponse={currentResponse}
                  currentToolCalls={currentToolCalls}
                  chatDone={chatDone}
                  auditId={auditId}
                  conversationTopic={conversationTopic}
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

            {/* ── 底部输入栏 (内容区域内，居中) ── */}
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
    </>
  );
}
