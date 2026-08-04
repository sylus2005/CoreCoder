import React from 'react';
import { Card, Typography, Space, Button, Tag, Empty, Tooltip, Popconfirm } from 'antd';
import {
  HistoryOutlined,
  DeleteOutlined,
  EyeOutlined,
  MessageOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';

const { Text } = Typography;

/**
 * 历史对话面板 — 显示之前的对话和结果报告.
 *
 * 数据存储在 localStorage 中，包含:
 * - id, session_id: 对话标识
 * - topic: 对话主题（从第一次用户需求提取）
 * - turns: [{userMessage, aiResponse, timestamp, toolCalls}] 多轮对话
 * - target: 审计目标路径
 * - timestamp: 创建时间
 */
export default function HistoryPanel({ history, onSelect, onDelete, activeSessionId }) {
  if (!history || history.length === 0) {
    return (
      <div style={{ marginTop: 0 }}>
        <div style={{ marginBottom: 12 }}>
          <Space size={6}>
            <HistoryOutlined style={{ color: '#6366f1', fontSize: 14 }} />
            <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>
              History
            </span>
          </Space>
        </div>
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description={
            <span style={{ fontSize: 12, color: '#94a3b8' }}>
              No conversation history
            </span>
          }
          style={{ padding: '12px 0' }}
        />
      </div>
    );
  }

  return (
    <div style={{ marginTop: 0 }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 12,
      }}>
        <Space size={6}>
          <HistoryOutlined style={{ color: '#6366f1', fontSize: 14 }} />
          <span style={{ fontSize: 14, fontWeight: 600, color: '#334155' }}>
            History ({history.length})
          </span>
        </Space>
      </div>

      <div style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        maxHeight: 280,
        overflow: 'auto',
      }}>
        {history.map((item) => {
          const isActive = item.session_id === activeSessionId;
          return (
            <Card
              key={item.id}
              size="small"
              style={{
                background: isActive ? '#f8f9ff' : '#ffffff',
                border: isActive ? '1px solid #c7d2fe' : '1px solid #f1f5f9',
                borderRadius: 8,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                boxShadow: isActive ? '0 2px 8px rgba(99,102,241,0.12)' : 'none',
              }}
              bodyStyle={{ padding: '8px 10px' }}
              onClick={() => onSelect?.(item)}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.borderColor = '#e2e8f0';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.borderColor = '#f1f5f9';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                <MessageOutlined style={{
                  color: isActive ? '#6366f1' : '#94a3b8',
                  fontSize: 12,
                  marginTop: 2,
                  flexShrink: 0,
                }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <Text style={{
                    fontSize: 12,
                    fontWeight: isActive ? 600 : 500,
                    color: isActive ? '#4338ca' : '#334155',
                    display: 'block',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    {item.topic || item.message || '(no topic)'}
                  </Text>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                    <ClockCircleOutlined style={{ fontSize: 10, color: '#94a3b8' }} />
                    <Text style={{ fontSize: 10, color: '#94a3b8' }}>
                      {new Date(item.timestamp).toLocaleString()}
                    </Text>
                    {item.turns && item.turns.length > 1 && (
                      <Tag color="blue" style={{ fontSize: 10, lineHeight: '14px', padding: '0 4px', borderRadius: 4, margin: 0 }}>
                        {item.turns.length} turns
                      </Tag>
                    )}
                    {isActive && (
                      <Tag color="purple" style={{ fontSize: 10, lineHeight: '14px', padding: '0 4px', borderRadius: 4, margin: 0 }}>
                        active
                      </Tag>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 2, flexShrink: 0 }}>
                  <Tooltip title="View report">
                    <Button
                      type="text"
                      size="small"
                      icon={<EyeOutlined style={{ fontSize: 12 }} />}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelect?.(item);
                      }}
                      style={{ color: '#6366f1', padding: '0 4px', height: 22, minWidth: 22 }}
                    />
                  </Tooltip>
                  <Popconfirm
                    title="Delete this conversation?"
                    onConfirm={(e) => {
                      e?.stopPropagation();
                      onDelete?.(item.id);
                    }}
                    onCancel={(e) => e?.stopPropagation()}
                    okText="Delete"
                    cancelText="Cancel"
                  >
                    <Button
                      type="text"
                      size="small"
                      icon={<DeleteOutlined style={{ fontSize: 11 }} />}
                      onClick={(e) => e.stopPropagation()}
                      style={{ color: '#ef4444', padding: '0 4px', height: 22, minWidth: 22 }}
                    />
                  </Popconfirm>
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
