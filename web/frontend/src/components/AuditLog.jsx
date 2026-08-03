import React, { useEffect, useRef, useState } from 'react';
import { Card, Typography, Tag, Spin, Space, Button, Modal } from 'antd';
import {
  CheckCircleOutlined,
  LoadingOutlined,
  BugOutlined,
  SearchOutlined,
  FileTextOutlined,
  RobotOutlined,
  EyeOutlined,
  FileMarkdownOutlined,
  MessageOutlined,
} from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const { Text, Paragraph } = Typography;

const PHASE_LABELS = {
  recon: 'Phase 1: Recon',
  hunt: 'Phase 2: Hunt',
  report: 'Phase 3: Report',
};

const PHASE_ICONS = {
  recon: <SearchOutlined />,
  hunt: <BugOutlined />,
  report: <FileTextOutlined />,
};

const SEVERITY_COLORS = {
  CRITICAL: 'red',
  HIGH: 'volcano',
  MEDIUM: 'gold',
  LOW: 'green',
  INFORMATIONAL: 'default',
};

const API_BASE = 'http://localhost:8000';

export default function AuditLog({
  logs, phaseInfo, findings, auditing, chatMode,
  chatContent, toolCalls, chatDone, auditId,
  conversationTopic, lastUserMessage,
}) {
  const logEndRef = useRef(null);
  const [previewVisible, setPreviewVisible] = useState(false);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, chatContent]);

  // Calculate phase progress
  const phaseOrder = ['recon', 'hunt', 'report'];
  const currentPhaseIdx = phaseOrder.findIndex((p) => phaseInfo[p] === 'started');

  // Group findings by severity for live counter
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const handleDownloadMarkdown = () => {
    const blob = new Blob([chatContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SECURITY_AUDIT_REPORT_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ maxWidth: 960, margin: '0 auto' }}>
      {/* ── Phase Progress (Pipeline mode only) ── */}
      {!chatMode && (
        <Card
          className="content-card"
          style={{ marginBottom: 20 }}
          title={
            <Space>
              <ThunderboltIcon />
              <span style={{ fontSize: 15, fontWeight: 600, color: '#334155' }}>Audit Progress</span>
              {auditing && <Spin size="small" style={{ marginLeft: 4 }} />}
            </Space>
          }
        >
          <div style={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center', padding: '8px 0' }}>
            {phaseOrder.map((phase, idx) => {
              const status = phaseInfo[phase];
              const isActive = status === 'started';
              const isDone = status === 'done';
              return (
                <React.Fragment key={phase}>
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 8,
                    opacity: isActive || isDone ? 1 : 0.35,
                  }}>
                    <div style={{
                      width: 44, height: 44, borderRadius: '50%',
                      background: isDone
                        ? 'linear-gradient(135deg, #22c55e, #16a34a)'
                        : isActive
                          ? 'linear-gradient(135deg, #6366f1, #7c3aed)'
                          : '#e2e8f0',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      boxShadow: isActive ? '0 0 0 4px rgba(99,102,241,0.15)' : 'none',
                      transition: 'all 0.4s ease',
                    }}>
                      {isDone ? (
                        <CheckCircleOutlined style={{ color: '#fff', fontSize: 18 }} />
                      ) : isActive ? (
                        <LoadingOutlined style={{ color: '#fff', fontSize: 18 }} />
                      ) : (
                        <span style={{ color: '#94a3b8', fontSize: 16 }}>{PHASE_ICONS[phase]}</span>
                      )}
                    </div>
                    <Text style={{
                      fontSize: 12,
                      fontWeight: isActive ? 600 : 400,
                      color: isActive ? '#6366f1' : isDone ? '#16a34a' : '#94a3b8',
                    }}>
                      {PHASE_LABELS[phase]}
                    </Text>
                  </div>
                  {idx < 2 && (
                    <div style={{
                      flex: 1, height: 3,
                      background: isDone ? 'linear-gradient(90deg, #22c55e, #6366f1)' : '#e2e8f0',
                      borderRadius: 2,
                      margin: '0 8px',
                      marginBottom: 20,
                    }} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </Card>
      )}

      {/* ── Live Findings Counter ── */}
      {findings.length > 0 && (
        <Card
          className="content-card"
          style={{ marginBottom: 20 }}
          bodyStyle={{ padding: '12px 20px' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
            <Space size={6}>
              <BugOutlined style={{ fontSize: 18, color: '#6366f1' }} />
              <Text strong style={{ fontSize: 16, color: '#334155' }}>
                {findings.length}
              </Text>
              <Text style={{ color: '#94a3b8', fontSize: 13 }}>findings found</Text>
            </Space>
            <div style={{ flex: 1 }} />
            <Space size={8}>
              {Object.entries(severityCounts).map(([sev, count]) => (
                <Tag
                  key={sev}
                  color={SEVERITY_COLORS[sev]}
                  style={{ borderRadius: 12, padding: '2px 10px', fontWeight: 600, fontSize: 12 }}
                >
                  {sev}: {count}
                </Tag>
              ))}
            </Space>
          </div>
        </Card>
      )}

      {/* ── ★ 对话主题 (显示在实时日志上方) ── */}
      {chatMode && conversationTopic && (
        <Card
          className="content-card"
          style={{ marginBottom: 12 }}
          bodyStyle={{ padding: '12px 20px' }}
        >
          <Space size={8}>
            <MessageOutlined style={{ color: '#6366f1', fontSize: 15 }} />
            <Text style={{ fontSize: 13, color: '#94a3b8', fontWeight: 400 }}>当前对话主题：</Text>
            <Text style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>
              {conversationTopic}
            </Text>
            {auditing && <Tag color="processing" style={{ borderRadius: 12, fontSize: 11 }}>进行中</Tag>}
            {chatDone && <Tag color="success" style={{ borderRadius: 12, fontSize: 11 }}>已完成</Tag>}
          </Space>
        </Card>
      )}

      {/* ── Terminal-Style Log ── */}
      <Card
        className="content-card"
        style={{ marginBottom: 20 }}
        title={
          <Space>
            <div style={{
              width: 10, height: 10, borderRadius: '50%',
              background: auditing ? '#fbbf24' : '#22c55e',
              boxShadow: auditing ? '0 0 6px rgba(251,191,36,0.4)' : '0 0 6px rgba(34,197,94,0.4)',
            }} />
            <Text style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: '#334155' }}>
              {chatMode ? 'corecoder-agent --chat' : 'audit --target --pipeline'}
            </Text>
          </Space>
        }
        bodyStyle={{ padding: 0 }}
      >
        <div style={{
          background: '#1e293b',
          borderRadius: '0 0 12px 12px',
          padding: '16px 20px',
          maxHeight: chatMode ? 300 : 440,
          overflow: 'auto',
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
          fontSize: 12.5,
          lineHeight: 1.8,
        }}>
          {logs.length === 0 ? (
            <div style={{ color: '#64748b', textAlign: 'center', padding: '40px 0' }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>
                {chatMode ? '🤖' : '🖥️'}
              </div>
              <div>
                {chatMode
                  ? 'Waiting for AI Agent to start...'
                  : 'Waiting for audit to start...'}
              </div>
              <div style={{ fontSize: 11, marginTop: 4, color: '#475569' }}>
                {chatMode
                  ? 'Type your audit requirements and click "Start Audit"'
                  : 'Click "Start Audit" to begin the security scan'}
              </div>
            </div>
          ) : (
            logs.map((log) => (
              <div
                key={log.id}
                style={{
                  marginBottom: 2,
                  color:
                    log.type === 'error' ? '#f87171' :
                    log.type === 'success' ? '#4ade80' :
                    log.type === 'finding' ? '#fbbf24' :
                    '#94a3b8',
                }}
              >
                <span style={{ color: '#475569', marginRight: 10 }}>[{log.time}]</span>
                <span style={{
                  color:
                    log.message?.startsWith('✅') ? '#4ade80' :
                    log.message?.startsWith('⚠') ? '#fbbf24' :
                    log.message?.startsWith('❌') ? '#f87171' :
                    log.message?.startsWith('🔍') ? '#818cf8' :
                    log.message?.startsWith('⚔️') ? '#f97316' :
                    log.message?.startsWith('📝') ? '#22d3ee' :
                    log.message?.startsWith('🎯') ? '#c084fc' :
                    log.message?.startsWith('🤖') ? '#c084fc' :
                    log.message?.startsWith('💬') ? '#a78bfa' :
                    log.message?.startsWith('🔧') ? '#fbbf24' :
                    'inherit',
                }}>
                  {log.message}
                </span>
              </div>
            ))
          )}
          {auditing && (
            <div style={{ color: '#475569', marginTop: 4 }}>
              <Spin size="small" />{' '}
              {chatMode
                ? 'AI Agent analyzing...'
                : phaseOrder.find((p) => phaseInfo[p] === 'started')
                  ? PHASE_LABELS[phaseOrder.find((p) => phaseInfo[p] === 'started')] || 'Processing...'
                  : 'Initializing scan...'}
              <span className="blinking-cursor">▌</span>
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      </Card>

      {/* ── AI Agent Response Card (chat mode) — only shown when done ── */}
      {chatMode && chatDone && chatContent && (
        <Card
          className="content-card"
          style={{ marginBottom: 20 }}
          title={
            <Space>
              <div style={{
                width: 28, height: 28, borderRadius: 7,
                background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <RobotOutlined style={{ color: '#fff', fontSize: 14 }} />
              </div>
              <span style={{ fontSize: 15, fontWeight: 600, color: '#334155' }}>AI Agent Response</span>
              {auditing && <Spin size="small" />}
            </Space>
          }
          extra={
            chatDone && (
              <Space size={8}>
                <Button
                  size="small"
                  icon={<FileMarkdownOutlined />}
                  onClick={handleDownloadMarkdown}
                  style={{
                    borderRadius: 6,
                    fontWeight: 500,
                    borderColor: '#94a3b8',
                    color: '#64748b',
                  }}
                >
                  下载 .md
                </Button>
              </Space>
            )
          }
          bodyStyle={{ padding: '16px 20px' }}
        >
          <div className="markdown-content" style={{
            maxHeight: 600,
            overflow: 'auto',
          }}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {chatContent}
            </ReactMarkdown>
            {auditing && <span className="blinking-cursor">▌</span>}
          </div>
        </Card>
      )}

      {/* ── Markdown Preview Modal ── */}
      <Modal
        title={
          <Space>
            <EyeOutlined style={{ color: '#6366f1' }} />
            <span style={{ fontWeight: 600 }}>Markdown 源码预览</span>
            <Tag color="purple" style={{ fontSize: 11, borderRadius: 8 }}>.md</Tag>
          </Space>
        }
        open={previewVisible}
        onCancel={() => setPreviewVisible(false)}
        width={900}
        footer={
          <Space>
            <Button icon={<FileMarkdownOutlined />} onClick={handleDownloadMarkdown}>
              下载 Markdown
            </Button>
          </Space>
        }
        style={{ top: 20 }}
      >
        <div className="markdown-content" style={{
          maxHeight: '70vh',
          overflow: 'auto',
          padding: '8px 0',
        }}>
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {chatContent}
          </ReactMarkdown>
        </div>
      </Modal>

      <style>{`
        @keyframes blink {
          0%, 50% { opacity: 1; }
          51%, 100% { opacity: 0; }
        }
        .blinking-cursor {
          animation: blink 1s infinite;
          color: #6366f1;
        }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-4px); }
        }
      `}</style>
    </div>
  );
}

function ThunderboltIcon() {
  return (
    <div style={{
      width: 28, height: 28, borderRadius: 7,
      background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <span style={{ color: '#fff', fontSize: 13 }}>⚡</span>
    </div>
  );
}
