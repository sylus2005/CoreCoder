import React, { useState, useRef, useCallback } from 'react';
import { Layout, Button, Space, Typography, ConfigProvider, theme, Tag } from 'antd';
import {
  PlayCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ThunderboltFilled,
  RobotOutlined,
} from '@ant-design/icons';
import UploadPanel from './components/UploadPanel';
import AuditLog from './components/AuditLog';
import ReportView from './components/ReportView';
import { startAudit, connectAuditStream, startChat, connectChatStream } from './api';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

const DEFAULT_TARGET = './demo/vulnerable-utils/';

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
  const [chatMode, setChatMode] = useState(false);  // true = LLM Agent, false = regex Pipeline
  const [chatContent, setChatContent] = useState('');  // 流式 Agent 响应内容
  const [toolCalls, setToolCalls] = useState([]);       // Agent 调用的工具记录

  const eventSourceRef = useRef(null);

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
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  // 文件上传成功回调
  const handleFilesUploaded = useCallback((targetPath, files) => {
    setUploadedTargetPath(targetPath);
    setUploadedFiles(files);
    setTarget(targetPath);
    addLog(`📤 已上传 ${files.length} 个文件到: ${targetPath}`, 'success');
  }, [addLog]);

  // 清除已上传文件
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

  const handleChatAudit = useCallback(async () => {
    reset();
    setAuditing(true);
    setChatMode(true);
    setChatContent('');
    addLog('🤖 Starting CoreCoder AI Agent...', 'info');

    const auditTarget = uploadedTargetPath || target;
    const message = requirements.trim() || `请审计目标路径: ${auditTarget}`;

    try {
      const { chat_id } = await startChat(message, auditTarget);
      setAuditId(chat_id);
      addLog(`✅ AI Agent connected — ID: ${chat_id}`, 'success');
      addLog(`💬 "${message}"`, 'info');
      addLog(`📂 Target: ${auditTarget}`, 'info');

      const es = connectChatStream(chat_id, {
        onLog: (data) => {
          addLog(data.message || JSON.stringify(data), 'info');
        },
        onToolCall: (data) => {
          setToolCalls((prev) => [...prev, { ...data, id: Date.now(), time: new Date().toLocaleTimeString() }]);
          addLog(`🔧 Tool: ${data.tool}(${JSON.stringify(data.arguments)})`, 'finding');
        },
        onToken: (data) => {
          setChatContent((prev) => prev + (data.content || ''));
        },
        onDone: (data) => {
          if (data.content) {
            setChatContent(data.content);
          }
          addLog('✅ AI Agent 分析完成', 'success');
          // 从 Agent 响应中提取 findings 信息
          addLog('📋 详见上方 Agent 分析报告', 'success');
          setAuditing(false);
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
  }, [target, uploadedTargetPath, requirements, reset, addLog]);

  // ── Start: 智能选择 Pipeline 或 Agent ──────────────

  const handleStart = useCallback(async () => {
    if (requirements.trim()) {
      // 有自然语言需求 → 使用 LLM Agent (更智能)
      await handleChatAudit();
    } else {
      // 无自然语言需求 → 使用快速 Pipeline (正则扫描)
      await handlePipelineAudit();
    }
  }, [requirements, handleChatAudit, handlePipelineAudit]);

  // Live stats for the header
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
            {/* Live finding badges */}
            {findings.length > 0 && (
              <Space size={10}>
                <Tag
                  color="error"
                  style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}
                >
                  🔴 {highCount} High
                </Tag>
                <Tag
                  color="warning"
                  style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}
                >
                  🟡 {medCount} Med
                </Tag>
                <Tag
                  color="success"
                  style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}
                >
                  🟢 {lowCount} Low
                </Tag>
              </Space>
            )}
            {chatMode && (
              <Tag
                color="purple"
                style={{ borderRadius: 20, padding: '2px 12px', fontWeight: 600, fontSize: 13 }}
              >
                <RobotOutlined /> AI Agent
              </Tag>
            )}
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
            {!auditing && summary && (
              <Button
                icon={<ReloadOutlined />}
                onClick={reset}
                style={{ borderRadius: 10, height: 40, fontWeight: 500 }}
              >
                Reset
              </Button>
            )}
          </Space>
        </Header>

        <Layout style={{ background: '#f0f2f5' }}>
          {/* ── Sidebar ── */}
          <Sider
            width={300}
            style={{
              background: '#ffffff',
              boxShadow: '2px 0 20px rgba(0,0,0,0.04)',
              padding: 20,
              borderRight: 'none',
              overflow: 'auto',
              maxHeight: 'calc(100vh - 64px)',
            }}
          >
            <UploadPanel
              target={target}
              onTargetChange={setTarget}
              disabled={auditing}
              onFilesUploaded={handleFilesUploaded}
              uploadedFiles={uploadedFiles}
              onClearFiles={handleClearFiles}
              requirements={requirements}
              onRequirementsChange={setRequirements}
              onStartAudit={handleStart}
            />
          </Sider>

          {/* ── Main Content ── */}
          <Content
            style={{
              padding: 24,
              background: '#f0f2f5',
              overflow: 'auto',
              maxHeight: 'calc(100vh - 64px)',
            }}
          >
            {!summary && !chatContent ? (
              <AuditLog
                logs={logs}
                phaseInfo={phaseInfo}
                findings={findings}
                auditing={auditing}
                chatMode={chatMode}
                chatContent={chatContent}
                toolCalls={toolCalls}
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
              />
            ) : (
              <ReportView
                summary={summary}
                findings={findings}
                reportMd={reportMd}
                phaseInfo={phaseInfo}
              />
            )}
          </Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
