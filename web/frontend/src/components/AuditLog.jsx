import React, { useEffect, useRef, useState } from 'react';
import { Card, Typography, Tag, Spin, Space, Button, Modal, Collapse } from 'antd';
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
  CaretRightOutlined,
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

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function truncate(text, maxLen) {
  if (!text) return '';
  return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
}

export default function AuditLog({
  logs, phaseInfo, findings, auditing, chatMode,
  turns, currentResponse, currentToolCalls, chatDone, auditId,
  conversationTopic,
}) {
  const logEndRef = useRef(null);
  const [previewVisible, setPreviewVisible] = useState(false);
  const [previewContent, setPreviewContent] = useState('');
  // ★ 当前展开的 turn key（默认展开最新一个）
  const [activeTurnKeys, setActiveTurnKeys] = useState([]);

  // ★ 当 turns 变化时，自动展开最新 turn
  useEffect(() => {
    if (turns.length > 0 && chatDone) {
      setActiveTurnKeys([String(turns.length - 1)]);
    }
  }, [turns.length, chatDone]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, currentResponse]);

  // Calculate phase progress
  const phaseOrder = ['recon', 'hunt', 'report'];
  const currentPhaseIdx = phaseOrder.findIndex((p) => phaseInfo[p] === 'started');

  // Group findings by severity for live counter
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const handleDownloadMarkdown = (content) => {
    const blob = new Blob([content || ''], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SECURITY_AUDIT_REPORT_${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePreview = (content) => {
    setPreviewContent(content || '');
    setPreviewVisible(true);
  };

  // ★ 构建 Collapse items（已完成的 turns）
  const collapseItems = turns.map((turn, idx) => ({
    key: String(idx),
    label: (
      <Space size={8} wrap style={{ width: '100%' }}>
        <Text
          type="secondary"
          style={{ fontSize: 12, fontWeight: 600, fontFamily: 'monospace', flexShrink: 0 }}
        >
          Q{idx + 1}:
        </Text>
        <Text
          style={{
            fontSize: 13,
            fontWeight: idx === turns.length - 1 ? 600 : 400,
            color: idx === turns.length - 1 ? '#334155' : '#64748b',
            flex: 1,
          }}
          ellipsis={{ tooltip: turn.userMessage }}
        >
          {truncate(turn.userMessage, 50)}
        </Text>
        <Text type="secondary" style={{ fontSize: 11, flexShrink: 0 }}>
          {formatTime(turn.timestamp)}
        </Text>
        {idx === turns.length - 1 && (
          <Tag color="purple" style={{ borderRadius: 8, fontSize: 10, margin: 0, flexShrink: 0 }}>
            最新
          </Tag>
        )}
      </Space>
    ),
    children: (
      <div>
        {/* 本轮工具调用 */}
        {turn.toolCalls && turn.toolCalls.length > 0 && (
          <div style={{
            marginBottom: 12,
            padding: '8px 12px',
            background: '#fffbeb',
            borderRadius: 8,
            border: '1px solid #fde68a',
          }}>
            <Text type="secondary" style={{ fontSize: 11, fontWeight: 600 }}>
              🔧 工具调用 ({turn.toolCalls.length})
            </Text>
            {turn.toolCalls.map((tc, tci) => (
              <div key={tci} style={{ fontSize: 11, color: '#92400e', marginTop: 4 }}>
                <Text style={{ fontFamily: 'monospace', fontSize: 11, color: '#b45309' }}>
                  {tc.tool}
                </Text>
                <Text type="secondary" style={{ fontSize: 10, marginLeft: 8 }}>
                  {tc.time || ''}
                </Text>
              </div>
            ))}
          </div>
        )}

        {/* Markdown 响应 */}
        <div className="markdown-content" style={{ maxHeight: 500, overflow: 'auto' }}>
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {turn.aiResponse || '*（无响应内容）*'}
          </ReactMarkdown>
        </div>

        {/* 下载按钮 */}
        {turn.aiResponse && (
          <Space size={8} style={{ marginTop: 12 }}>
            <Button
              size="small"
              icon={<FileMarkdownOutlined />}
              onClick={() => handleDownloadMarkdown(turn.aiResponse)}
              style={{ borderRadius: 6, fontWeight: 500 }}
            >
              下载 .md
            </Button>
            <Button
              size="small"
              icon={<EyeOutlined />}
              onClick={() => handlePreview(turn.aiResponse)}
              style={{ borderRadius: 6, fontWeight: 500 }}
            >
              预览
            </Button>
          </Space>
        )}
      </div>
    ),
  }));

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

      {/* ── ★ 对话主题（从第一次需求提取，固定不变）── */}
      {chatMode && conversationTopic && (
        <Card
          className="content-card"
          style={{ marginBottom: 12 }}
          bodyStyle={{ padding: '12px 20px' }}
        >
          <Space size={8}>
            <MessageOutlined style={{ color: '#6366f1', fontSize: 15 }} />
            <Text style={{ fontSize: 13, color: '#94a3b8', fontWeight: 400 }}>对话主题：</Text>
            <Text style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>
              {conversationTopic}
            </Text>
            <Text type="secondary" style={{ fontSize: 11, marginLeft: 4 }}>
              （{turns.length} 轮对话）
            </Text>
            {auditing && <Tag color="processing" style={{ borderRadius: 12, fontSize: 11 }}>进行中</Tag>}
            {chatDone && !auditing && <Tag color="success" style={{ borderRadius: 12, fontSize: 11 }}>已完成</Tag>}
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

      {/* ── ★ 当前轮次流式输出（正在生成中，未完成）── */}
      {chatMode && auditing && currentResponse && (
        <Card
          className="content-card"
          style={{ marginBottom: 16 }}
          title={
            <Space>
              <div style={{
                width: 28, height: 28, borderRadius: 7,
                background: 'linear-gradient(135deg, #f59e0b, #f97316)',
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <RobotOutlined style={{ color: '#fff', fontSize: 14 }} />
              </div>
              <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>
                Q{turns.length}: {truncate(turns[turns.length - 1]?.userMessage || '', 40)}
              </span>
              <Tag color="processing" style={{ borderRadius: 12, fontSize: 11 }}>生成中...</Tag>
            </Space>
          }
          bodyStyle={{ padding: '16px 20px' }}
        >
          <div className="markdown-content" style={{ maxHeight: 500, overflow: 'auto' }}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {currentResponse}
            </ReactMarkdown>
            <span className="blinking-cursor">▌</span>
          </div>
        </Card>
      )}

      {/* ── ★ 多轮对话 Collapse（已完成的 turns）── */}
      {chatMode && chatDone && turns.length > 0 && (
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
              <span style={{ fontSize: 15, fontWeight: 600, color: '#334155' }}>
                AI Agent Response
              </span>
            </Space>
          }
          extra={
            <Space size={8}>
              <Button
                size="small"
                icon={<FileMarkdownOutlined />}
                onClick={() => {
                  // 下载所有 turns 合并的 Markdown
                  const allMd = turns.map((t, i) => (
                    `---\n### Q${i + 1}: ${t.userMessage}\n\n${t.aiResponse}\n`
                  )).join('\n');
                  handleDownloadMarkdown(allMd);
                }}
                style={{ borderRadius: 6, fontWeight: 500, borderColor: '#94a3b8', color: '#64748b' }}
              >
                下载全部 .md
              </Button>
            </Space>
          }
          bodyStyle={{ padding: '0' }}
        >
          <Collapse
            activeKey={activeTurnKeys}
            onChange={(keys) => setActiveTurnKeys(keys)}
            expandIcon={({ isActive }) => <CaretRightOutlined rotate={isActive ? 90 : 0} />}
            style={{
              border: 'none',
              borderRadius: '0 0 12px 12px',
              background: 'transparent',
            }}
            items={collapseItems}
          />
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
            <Button
              icon={<FileMarkdownOutlined />}
              onClick={() => {
                handleDownloadMarkdown(previewContent);
                setPreviewVisible(false);
              }}
            >
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
            {previewContent}
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
