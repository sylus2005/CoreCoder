import React, { useEffect, useRef } from 'react';
import { Card, Typography, Tag, Spin, Badge, Space, Progress, Steps } from 'antd';
import {
  CheckCircleOutlined,
  LoadingOutlined,
  BugOutlined,
  CodeOutlined,
  SearchOutlined,
  FileTextOutlined,
  RobotOutlined,
} from '@ant-design/icons';

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

export default function AuditLog({ logs, phaseInfo, findings, auditing, chatMode, chatContent, toolCalls }) {
  const logEndRef = useRef(null);

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

  return (
    <div style={{ maxWidth: 960, margin: '0 auto' }}>
      {/* ── AI Agent Response Card (chat mode) ── */}
      {chatMode && chatContent && (
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
          bodyStyle={{ padding: '16px 20px' }}
        >
          <div style={{
            background: 'linear-gradient(135deg, #f8f9ff 0%, #faf5ff 100%)',
            borderRadius: 10,
            padding: '16px 20px',
            border: '1px solid #e0e7ff',
            maxHeight: 500,
            overflow: 'auto',
            fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            fontSize: 14,
            lineHeight: 1.8,
            color: '#334155',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}>
            {chatContent}
            {auditing && <span className="blinking-cursor">▌</span>}
          </div>
        </Card>
      )}

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

      {/* ── Tool Calls (Chat mode) ── */}
      {chatMode && toolCalls && toolCalls.length > 0 && (
        <Card
          className="content-card"
          style={{ marginBottom: 20 }}
          size="small"
          title={
            <Space size={6}>
              <CodeOutlined style={{ color: '#f59e0b', fontSize: 14 }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
                Tools Called ({toolCalls.length})
              </span>
              {auditing && <Spin size="small" />}
            </Space>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {toolCalls.map((tc, idx) => (
              <div
                key={tc.id || idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '8px 12px',
                  background: '#fffbeb',
                  borderRadius: 8,
                  border: '1px solid #fde68a',
                }}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: 6,
                  background: 'linear-gradient(135deg, #f59e0b, #d97706)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <span style={{ color: '#fff', fontSize: 13, fontWeight: 700 }}>{idx + 1}</span>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <Text strong style={{ fontSize: 13, color: '#92400e', fontFamily: "'JetBrains Mono', monospace" }}>
                    {tc.tool}
                  </Text>
                  {tc.arguments && Object.keys(tc.arguments).length > 0 && (
                    <div style={{ fontSize: 11, color: '#a16207', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                      {Object.entries(tc.arguments).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 8 }}>
                          <span style={{ opacity: 0.6 }}>{k}=</span>
                          <span>{String(v).substring(0, 80)}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {tc.time && (
                  <Text style={{ fontSize: 10, color: '#a16207', flexShrink: 0 }}>{tc.time}</Text>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ── Terminal-Style Log ── */}
      <Card
        className="content-card"
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
          maxHeight: chatMode ? 360 : 440,
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
          {auditing && !chatMode && (
            <div style={{ color: '#475569', marginTop: 4 }}>
              <Spin size="small" />{' '}
              {phaseOrder.find((p) => phaseInfo[p] === 'started')
                ? PHASE_LABELS[phaseOrder.find((p) => phaseInfo[p] === 'started')] || 'Processing...'
                : 'Initializing scan...'}
              <span className="blinking-cursor">▌</span>
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      </Card>

      <style>{`
        @keyframes blink {
          0%, 50% { opacity: 1; }
          51%, 100% { opacity: 0; }
        }
        .blinking-cursor {
          animation: blink 1s infinite;
          color: #6366f1;
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
