import React from 'react';
import { Card, Table, Tag, Typography, Row, Col, Button, Space, Divider, Tooltip } from 'antd';
import {
  BugOutlined,
  WarningOutlined,
  SecurityScanOutlined,
  InfoCircleOutlined,
  DownloadOutlined,
  FileTextOutlined,
  RiseOutlined,
  AlertOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  ThunderboltFilled,
} from '@ant-design/icons';
import SeverityChart from './SeverityChart';

const { Text, Title, Paragraph } = Typography;

const SEVERITY_CONFIG = {
  CRITICAL: { color: '#ef4444', bg: '#fef2f2', icon: '🔴', order: 0, label: 'Critical' },
  HIGH: { color: '#f97316', bg: '#fff7ed', icon: '🟠', order: 1, label: 'High' },
  MEDIUM: { color: '#eab308', bg: '#fefce8', icon: '🟡', order: 2, label: 'Medium' },
  LOW: { color: '#22c55e', bg: '#f0fdf4', icon: '🟢', order: 3, label: 'Low' },
  INFORMATIONAL: { color: '#6366f1', bg: '#eef2ff', icon: '🔵', order: 4, label: 'Info' },
};

const columns = [
  {
    title: '#',
    dataIndex: 'id',
    key: 'id',
    width: 100,
    render: (id) => (
      <Text code style={{ color: '#6366f1', fontSize: 11, fontWeight: 600 }}>
        {id}
      </Text>
    ),
  },
  {
    title: 'Severity',
    dataIndex: 'severity',
    key: 'severity',
    width: 90,
    render: (sev) => {
      const cfg = SEVERITY_CONFIG[sev] || { color: '#94a3b8', bg: '#f8fafc' };
      return (
        <Tag
          color={cfg.color}
          style={{ borderRadius: 8, fontWeight: 600, fontSize: 11, padding: '0 8px' }}
        >
          {sev}
        </Tag>
      );
    },
    sorter: (a, b) => (SEVERITY_CONFIG[a.severity]?.order ?? 5) - (SEVERITY_CONFIG[b.severity]?.order ?? 5),
    defaultSortOrder: 'ascend',
  },
  {
    title: 'Vulnerability',
    dataIndex: 'title',
    key: 'title',
    ellipsis: true,
    render: (title) => (
      <Text style={{ fontWeight: 500, color: '#334155' }}>{title}</Text>
    ),
  },
  {
    title: 'CWE',
    dataIndex: 'cwe_id',
    key: 'cwe_id',
    width: 90,
    render: (cwe) => (
      <Tag style={{ borderRadius: 6, fontSize: 11, background: '#f8fafc', border: '1px solid #e2e8f0', color: '#64748b' }}>
        {cwe}
      </Tag>
    ),
  },
  {
    title: 'File',
    dataIndex: 'file',
    key: 'file',
    width: 160,
    ellipsis: true,
    render: (file) => {
      const parts = (file || '').split(/[/\\]/);
      const basename = parts[parts.length - 1] || file;
      return (
        <Tooltip title={file}>
          <Text style={{ fontSize: 11, color: '#6366f1', fontFamily: "'JetBrains Mono', monospace" }}>
            📄 {basename}
          </Text>
        </Tooltip>
      );
    },
  },
  {
    title: 'Line',
    dataIndex: 'line',
    key: 'line',
    width: 55,
    align: 'center',
    render: (line) => (
      <Text style={{ fontSize: 11, color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace" }}>
        :{line}
      </Text>
    ),
  },
];

// ── Stat Card Component ──
function StatCard({ icon, label, value, color, gradient, subtitle }) {
  return (
    <Card
      className="stat-card"
      bodyStyle={{ padding: '18px 20px' }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <Text style={{ color: '#64748b', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {label}
          </Text>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#1e293b', marginTop: 4, lineHeight: 1 }}>
            {value}
          </div>
          {subtitle && (
            <Text style={{ color: '#94a3b8', fontSize: 11 }}>{subtitle}</Text>
          )}
        </div>
        <div style={{
          width: 44, height: 44, borderRadius: 12,
          background: `linear-gradient(135deg, ${gradient[0]}, ${gradient[1]})`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: `0 4px 12px ${gradient[0]}30`,
        }}>
          <span style={{ color: '#fff', fontSize: 20 }}>{icon}</span>
        </div>
      </div>
    </Card>
  );
}

export default function ReportView({ summary, findings, reportMd, phaseInfo }) {
  const handleDownload = () => {
    const blob = new Blob([reportMd], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SECURITY_REPORT.md';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Sort findings by severity
  const sortedFindings = [...findings].sort(
    (a, b) => (SEVERITY_CONFIG[a.severity]?.order ?? 5) - (SEVERITY_CONFIG[b.severity]?.order ?? 5)
  );

  const total = summary?.total || 0;
  const highTotal = (summary?.high_count || 0) + (summary?.by_severity?.CRITICAL || 0);
  const medTotal = summary?.medium_count || summary?.by_severity?.MEDIUM || 0;
  const lowTotal = (summary?.low_count || 0) + (summary?.by_severity?.INFORMATIONAL || 0);

  return (
    <div style={{ maxWidth: 1060, margin: '0 auto' }}>
      {/* ── Stat Cards Row ── */}
      <Row gutter={16} style={{ marginBottom: 20 }}>
        <Col span={6}>
          <StatCard
            icon={<BugOutlined />}
            label="Total Findings"
            value={total}
            gradient={['#6366f1', '#7c3aed']}
            subtitle={`in ${findings.length > 0 ? new Set(findings.map((f) => f.file?.split(/[/\\]/).pop())).size : 0} files`}
          />
        </Col>
        <Col span={6}>
          <StatCard
            icon={<AlertOutlined />}
            label="High / Critical"
            value={highTotal}
            gradient={['#ef4444', '#dc2626']}
            subtitle={total > 0 ? `${Math.round(highTotal / total * 100)}% of total` : '-'}
          />
        </Col>
        <Col span={6}>
          <StatCard
            icon={<WarningOutlined />}
            label="Medium"
            value={medTotal}
            gradient={['#f97316', '#ea580c']}
            subtitle={total > 0 ? `${Math.round(medTotal / total * 100)}% of total` : '-'}
          />
        </Col>
        <Col span={6}>
          <StatCard
            icon={<InfoCircleOutlined />}
            label="Low / Info"
            value={lowTotal}
            gradient={['#22c55e', '#16a34a']}
            subtitle={total > 0 ? `${Math.round(lowTotal / total * 100)}% of total` : '-'}
          />
        </Col>
      </Row>

      {/* ── Chart + Summary Row ── */}
      <Row gutter={16} style={{ marginBottom: 20 }}>
        <Col span={14}>
          <Card
            className="content-card"
            title={
              <Space>
                <RiseOutlined style={{ color: '#6366f1' }} />
                <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>Severity Distribution</span>
              </Space>
            }
          >
            <SeverityChart summary={summary} />
          </Card>
        </Col>
        <Col span={10}>
          <Card
            className="content-card"
            title={
              <Space>
                <CheckCircleOutlined style={{ color: '#22c55e' }} />
                <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>Audit Summary</span>
              </Space>
            }
            bodyStyle={{ padding: '16px 20px' }}
          >
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <Text style={{ color: '#64748b', fontSize: 12 }}>Duration</Text>
                <Text strong style={{ color: '#334155', fontSize: 13 }}>
                  <ClockCircleOutlined style={{ marginRight: 4, color: '#6366f1' }} />
                  {summary?.duration_seconds || summary?.duration || '-'}s
                </Text>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <Text style={{ color: '#64748b', fontSize: 12 }}>Tools Used</Text>
                <Text strong style={{ color: '#334155', fontSize: 13 }}>
                  <ThunderboltFilled style={{ marginRight: 4, color: '#6366f1' }} />
                  3 (c_review + insecure_defaults + injection_scanner)
                </Text>
              </div>
              <Divider style={{ margin: '10px 0', borderColor: '#f1f5f9' }} />
              {[
                { label: 'CRITICAL', color: '#ef4444', count: summary?.by_severity?.CRITICAL || 0 },
                { label: 'HIGH', color: '#f97316', count: summary?.by_severity?.HIGH || 0 },
                { label: 'MEDIUM', color: '#eab308', count: summary?.by_severity?.MEDIUM || 0 },
                { label: 'LOW', color: '#22c55e', count: summary?.by_severity?.LOW || 0 },
                { label: 'INFO', color: '#6366f1', count: summary?.by_severity?.INFORMATIONAL || 0 },
              ].map(({ label, color, count }) => count > 0 && (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, alignItems: 'center' }}>
                  <Space size={6}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                    <Text style={{ color: '#64748b', fontSize: 12 }}>{label}</Text>
                  </Space>
                  <Text strong style={{ color: '#334155', fontSize: 14 }}>{count}</Text>
                </div>
              ))}
            </div>
          </Card>
        </Col>
      </Row>

      {/* ── Actions Row ── */}
      <Row gutter={16} style={{ marginBottom: 20 }}>
        <Col span={24}>
          <Card
            className="content-card"
            bodyStyle={{ padding: '12px 20px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Space size={6}>
                <SecurityScanOutlined style={{ color: '#6366f1', fontSize: 16 }} />
                <Text strong style={{ color: '#334155', fontSize: 14 }}>Actions</Text>
              </Space>
              <Space size={12}>
                <Button
                  type="primary"
                  icon={<DownloadOutlined />}
                  onClick={handleDownload}
                  style={{
                    background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
                    border: 'none',
                    borderRadius: 8,
                    fontWeight: 600,
                    boxShadow: '0 2px 8px rgba(99,102,241,0.3)',
                  }}
                >
                  Download REPORT.md
                </Button>
                <Button
                  icon={<FileTextOutlined />}
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'findings.json';
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  style={{ borderRadius: 8, fontWeight: 500 }}
                >
                  Export findings.json
                </Button>
              </Space>
            </div>
          </Card>
        </Col>
      </Row>

      {/* ── Findings Table ── */}
      <Card
        className="content-card"
        title={
          <Space>
            <BugOutlined style={{ color: '#ef4444' }} />
            <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>Vulnerability Details</span>
            <Tag style={{ borderRadius: 10, fontWeight: 600 }}>{sortedFindings.length} items</Tag>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={sortedFindings}
          rowKey="id"
          size="middle"
          pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (t) => `${t} findings` }}
          expandable={{
            expandedRowRender: (record) => {
              const cfg = SEVERITY_CONFIG[record.severity] || {};
              return (
                <div style={{
                  background: '#f8f9ff',
                  borderRadius: 10,
                  padding: '16px 20px',
                  margin: '4px 0',
                  borderLeft: `3px solid ${cfg.color || '#6366f1'}`,
                }}>
                  <Row gutter={16}>
                    <Col span={16}>
                      <Paragraph style={{ marginBottom: 10 }}>
                        <Text strong style={{ color: '#475569', fontSize: 12 }}>Description</Text>
                        <br />
                        <Text style={{ color: '#334155', fontSize: 13 }}>{record.description}</Text>
                      </Paragraph>
                      {record.attack_scenario && (
                        <Paragraph style={{ marginBottom: 10 }}>
                          <Text strong style={{ color: '#ef4444', fontSize: 12 }}>⚠ Attack Scenario</Text>
                          <br />
                          <Text style={{ color: '#475569', fontSize: 13 }}>{record.attack_scenario}</Text>
                        </Paragraph>
                      )}
                    </Col>
                    <Col span={8}>
                      <div style={{
                        background: '#fff', borderRadius: 8, padding: '10px 14px',
                        border: '1px solid #e2e8f0',
                      }}>
                        <Text strong style={{ color: '#475569', fontSize: 11, display: 'block', marginBottom: 8 }}>
                          Metadata
                        </Text>
                        <Space size={4} wrap>
                          <Tag color="purple" style={{ fontSize: 11 }}>{record.cwe_id}</Tag>
                          <Tag color="blue" style={{ fontSize: 11 }}>CVSS {record.cvss_score || 'N/A'}</Tag>
                          <Tag style={{ fontSize: 11, background: '#f1f5f9', border: 'none' }}>
                            {record.discovered_by || 'regex-engine'}
                          </Tag>
                        </Space>
                      </div>
                    </Col>
                  </Row>
                  {record.fix_suggestion && (
                    <div style={{
                      marginTop: 12,
                      background: 'linear-gradient(135deg, #f0fdf4, #ecfdf5)',
                      borderRadius: 8,
                      padding: '10px 14px',
                      border: '1px solid #bbf7d0',
                    }}>
                      <Text strong style={{ color: '#16a34a', fontSize: 12 }}>💡 Fix Suggestion</Text>
                      <br />
                      <Text style={{ color: '#334155', fontSize: 13 }}>{record.fix_suggestion}</Text>
                    </div>
                  )}
                </div>
              );
            },
          }}
        />
      </Card>
    </div>
  );
}
