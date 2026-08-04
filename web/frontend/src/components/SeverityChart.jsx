import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Empty, Typography } from 'antd';

const { Text } = Typography;

// Modern gradient palette: blue-purple-indigo scheme
const SEVERITY_DATA = [
  { name: 'HIGH/CRITICAL', color: '#ef4444', gradient: ['#ef4444', '#dc2626'] },
  { name: 'MEDIUM', color: '#eab308', gradient: ['#eab308', '#ca8a04'] },
  { name: 'LOW', color: '#22c55e', gradient: ['#22c55e', '#16a34a'] },
  { name: 'INFORMATIONAL', color: '#6366f1', gradient: ['#6366f1', '#4f46e5'] },
];

// Custom label
const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name, value }) => {
  if (percent < 0.05) return null; // Don't label tiny slices
  const radius = innerRadius + (outerRadius - innerRadius) * 0.6;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>
      {`${value}`}
    </text>
  );
};

export default function SeverityChart({ summary }) {
  if (!summary || summary.total === 0) {
    return (
      <div style={{ textAlign: 'center', padding: 30 }}>
        <Empty
          description={<Text style={{ color: '#94a3b8' }}>No findings to display</Text>}
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </div>
    );
  }

  const data = SEVERITY_DATA
    .map((s) => {
      let value;
      if (s.name === 'HIGH/CRITICAL') {
        value = (summary.by_severity?.CRITICAL || 0) + (summary.by_severity?.HIGH || 0);
      } else {
        value = summary.by_severity?.[s.name] || 0;
      }
      return { name: s.name, value, color: s.color, gradient: s.gradient };
    })
    .filter((d) => d.value > 0);

  if (data.length === 0) {
    return <Empty description={<Text style={{ color: '#94a3b8' }}>No findings</Text>} />;
  }

  return (
    <div>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart>
          <defs>
            {data.map((entry, index) => (
              <linearGradient key={`grad-${index}`} id={`pieGrad-${index}`} x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor={entry.gradient[0]} />
                <stop offset="100%" stopColor={entry.gradient[1]} />
              </linearGradient>
            ))}
          </defs>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={105}
            paddingAngle={3}
            dataKey="value"
            label={renderCustomLabel}
            labelLine={false}
            cornerRadius={4}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={`url(#pieGrad-${index})`}
                stroke="#fff"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#fff',
              border: 'none',
              borderRadius: 10,
              boxShadow: '0 4px 20px rgba(0,0,0,0.12)',
              padding: '8px 14px',
              fontSize: 13,
              color: '#334155',
            }}
            formatter={(value, name) => [`${value} findings`, name]}
          />
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(value) => (
              <span style={{ color: '#64748b', fontSize: 12, fontWeight: 500 }}>{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Total in center */}
      <div style={{ textAlign: 'center', marginTop: -180, marginBottom: 120, position: 'relative', zIndex: 0, pointerEvents: 'none' }}>
        <div style={{ fontSize: 36, fontWeight: 700, color: '#334155', lineHeight: 1 }}>
          {summary.total}
        </div>
        <div style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Total
        </div>
      </div>
    </div>
  );
}
