import React, { useState, useRef, useCallback } from 'react';
import { Card, Input, Typography, Divider, Tag, Space, Button, message, Tooltip } from 'antd';
import {
  FolderOutlined,
  ToolOutlined,
  SecurityScanOutlined,
  ThunderboltFilled,
  BugOutlined,
  CloudUploadOutlined,
  FileOutlined,
  DeleteOutlined,
  PaperClipOutlined,
  InboxOutlined,
} from '@ant-design/icons';
import { uploadFiles } from '../api';

const { Text, Title } = Typography;
const TOOLS_INFO = [
  {
    name: 'c_review',
    icon: <BugOutlined />,
    color: '#ef4444',
    bgColor: '#fef2f2',
    desc: 'C/C++ Memory Safety Analysis',
    detail: 'Buffer overflow, UAF, integer overflow, format string',
  },
  {
    name: 'insecure_defaults',
    icon: <SecurityScanOutlined />,
    color: '#f97316',
    bgColor: '#fff7ed',
    desc: 'Insecure Configuration Detection',
    detail: 'Hardcoded secrets, debug mode, weak permissions',
  },
  {
    name: 'injection_scanner',
    icon: <ThunderboltFilled />,
    color: '#6366f1',
    bgColor: '#eef2ff',
    desc: 'Injection Vulnerability Scanner',
    detail: 'SQLi, XSS, command injection, path traversal',
  },
];

export default function UploadPanel({
  target,
  onTargetChange,
  disabled,
  onFilesUploaded,
  uploadedFiles,
  onClearFiles,
  children,
}) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const processFiles = useCallback(async (fileList) => {
    if (!fileList || fileList.length === 0) return;
    setUploading(true);
    try {
      const result = await uploadFiles(Array.from(fileList));
      message.success(`Uploaded ${result.file_count} file(s)`);
      onFilesUploaded?.(result.target_path, result.files);
    } catch (err) {
      message.error(`Upload failed: ${err.message}`);
    } finally {
      setUploading(false);
      setIsDragOver(false);
    }
  }, [onFilesUploaded]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const items = e.dataTransfer.items;
    if (!items) return;

    const files = [];
    const queue = [];

    // 递归遍历条目（支持文件夹）
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.kind === 'file') {
        queue.push({ entry: item.webkitGetAsEntry?.() || null, file: item.getAsFile(), path: '' });
      }
    }

    // 使用 webkitGetAsEntry 递归读取文件夹
    const readEntry = (entry, basePath) => {
      return new Promise((resolve) => {
        if (entry.isFile) {
          entry.file((file) => {
            // 保留相对路径
            Object.defineProperty(file, 'webkitRelativePath', {
              value: basePath ? `${basePath}/${file.name}` : file.name,
            });
            files.push(file);
            resolve();
          });
        } else if (entry.isDirectory) {
          const dirReader = entry.createReader();
          const dirPath = basePath ? `${basePath}/${entry.name}` : entry.name;
          dirReader.readEntries((entries) => {
            Promise.all(entries.map((e) => readEntry(e, dirPath))).then(resolve);
          });
        } else {
          resolve();
        }
      });
    };

    // 处理队列
    Promise.all(
      queue.map(({ entry, file, path }) => {
        if (entry) {
          return readEntry(entry, path);
        } else if (file) {
          files.push(file);
          return Promise.resolve();
        }
        return Promise.resolve();
      })
    ).then(() => {
      if (files.length > 0) {
        processFiles(files);
      }
    });
  }, [processFiles]);

  const handleFileSelect = useCallback((e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      processFiles(Array.from(files));
    }
    e.target.value = '';
  }, [processFiles]);

  return (
    <div>
      {/* ── 1. Audit Pipeline (最上面) ── */}
      <div style={{ marginBottom: 16 }}>
        <Title level={5} style={{ color: '#334155', marginBottom: 4, fontSize: 14, fontWeight: 600 }}>
          <ThunderboltFilled style={{ marginRight: 8, color: '#7c3aed' }} />
          Audit Pipeline
        </Title>
        <Text style={{ color: '#94a3b8', fontSize: 11 }}>
          3-Phase: Recon → Hunt → Report
        </Text>

        {/* Pipeline visualization */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginTop: 12, marginBottom: 4 }}>
          {['Recon', 'Hunt', 'Report'].map((phase, i) => (
            <React.Fragment key={phase}>
              <div style={{
                flex: 1,
                textAlign: 'center',
                background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
                color: '#fff',
                borderRadius: 8,
                padding: '8px 6px',
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: '0.3px',
              }}>
                {i === 0 ? '🔍 ' : i === 1 ? '⚔️ ' : '📝 '}
                {phase}
              </div>
              {i < 2 && (
                <div style={{
                  width: 20, height: 2,
                  background: 'linear-gradient(90deg, #7c3aed, #6366f1)',
                  flexShrink: 0,
                }} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      <Divider style={{ borderColor: '#f1f5f9', margin: '16px 0' }} />

      {/* ── 2. File Upload Section ── */}
      <div style={{ marginBottom: 20 }}>
        <Title level={5} style={{ color: '#334155', marginBottom: 12, fontSize: 14, fontWeight: 600 }}>
          <CloudUploadOutlined style={{ marginRight: 8, color: '#6366f1' }} />
          Upload Files
        </Title>

        {/* Drag & Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !disabled && fileInputRef.current?.click()}
          style={{
            border: `2px dashed ${isDragOver ? '#6366f1' : '#e2e8f0'}`,
            borderRadius: 12,
            padding: '24px 16px',
            textAlign: 'center',
            cursor: disabled ? 'not-allowed' : 'pointer',
            background: isDragOver
              ? 'linear-gradient(135deg, #eef2ff 0%, #faf5ff 100%)'
              : '#fafbfc',
            transition: 'all 0.25s ease',
            opacity: disabled ? 0.6 : 1,
          }}
        >
          <InboxOutlined style={{
            fontSize: 28,
            color: isDragOver ? '#6366f1' : '#94a3b8',
            transition: 'color 0.25s ease',
          }} />
          <div style={{
            marginTop: 8,
            fontSize: 13,
            fontWeight: 500,
            color: isDragOver ? '#6366f1' : '#64748b',
          }}>
            {uploading
              ? 'Uploading...'
              : isDragOver
                ? '✨ Drop files here'
                : 'Drag & drop files / folders'}
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
            or click to browse · Supports single files & folders
          </div>
        </div>

        {/* Hidden file inputs */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={handleFileSelect}
        />
        <input
          ref={folderInputRef}
          type="file"
          webkitdirectory="true"
          directory=""
          style={{ display: 'none' }}
          onChange={handleFileSelect}
        />

        {/* Action buttons */}
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <Button
            size="small"
            icon={<PaperClipOutlined />}
            onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}
            disabled={disabled}
            style={{ flex: 1, borderRadius: 8, fontSize: 11 }}
          >
            Select Files
          </Button>
          <Button
            size="small"
            icon={<FolderOutlined />}
            onClick={(e) => { e.stopPropagation(); folderInputRef.current?.click(); }}
            disabled={disabled}
            style={{ flex: 1, borderRadius: 8, fontSize: 11 }}
          >
            Select Folder
          </Button>
        </div>

        {/* Uploaded files list */}
        {uploadedFiles && uploadedFiles.length > 0 && (
          <div style={{
            marginTop: 10,
            background: '#f8fafc',
            borderRadius: 8,
            padding: '8px 10px',
            maxHeight: 120,
            overflow: 'auto',
            border: '1px solid #f1f5f9',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <Text style={{ fontSize: 11, color: '#64748b', fontWeight: 500 }}>
                📎 {uploadedFiles.length} file(s) uploaded
              </Text>
              <Button
                type="text"
                size="small"
                icon={<DeleteOutlined />}
                onClick={onClearFiles}
                style={{ color: '#ef4444', fontSize: 12, padding: '0 4px', height: 20 }}
              />
            </div>
            {uploadedFiles.slice(0, 5).map((f, i) => (
              <div key={i} style={{ fontSize: 11, color: '#6366f1', fontFamily: "'JetBrains Mono', monospace", padding: '1px 0' }}>
                <FileOutlined style={{ marginRight: 4, fontSize: 10 }} />
                {f}
              </div>
            ))}
            {uploadedFiles.length > 5 && (
              <Text style={{ fontSize: 10, color: '#94a3b8' }}>...and {uploadedFiles.length - 5} more</Text>
            )}
          </div>
        )}
      </div>

      <Divider style={{ borderColor: '#f1f5f9', margin: '16px 0' }} />

      {/* ── 3. Target Path ── */}
      <div style={{ marginBottom: 20 }}>
        <Title level={5} style={{ color: '#334155', marginBottom: 12, fontSize: 14, fontWeight: 600 }}>
          <FolderOutlined style={{ marginRight: 8, color: '#6366f1' }} />
          Target Path
        </Title>
        <Input
          value={target}
          onChange={(e) => onTargetChange(e.target.value)}
          disabled={disabled}
          placeholder="./demo/vulnerable-utils/ or single file path"
          prefix={<span style={{ color: '#6366f1' }}>📁</span>}
          style={{
            borderRadius: 10,
            borderColor: '#e2e8f0',
            boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
            fontSize: 13,
          }}
        />
        <Text style={{ color: '#94a3b8', fontSize: 11, display: 'block', marginTop: 6 }}>
          Directory path or single file path to audit
        </Text>
      </div>

      {/* ── 4. Children slot (History Panel injected here) ── */}
      {children && (
        <>
          <Divider style={{ borderColor: '#f1f5f9', margin: '16px 0' }} />
          {children}
          <Divider style={{ borderColor: '#f1f5f9', margin: '16px 0' }} />
        </>
      )}

      {/* ── 5. Enabled Tools Section (最下面) ── */}
      <div>
        <Title level={5} style={{ color: '#334155', marginBottom: 12, fontSize: 14, fontWeight: 600 }}>
          <ToolOutlined style={{ marginRight: 8, color: '#6366f1' }} />
          Enabled Tools
        </Title>
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          {TOOLS_INFO.map((tool) => (
            <Card
              key={tool.name}
              size="small"
              style={{
                background: '#ffffff',
                border: '1px solid #f1f5f9',
                borderRadius: 10,
                boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
                transition: 'all 0.2s ease',
                cursor: 'default',
              }}
              bodyStyle={{ padding: '10px 12px' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(99,102,241,0.1)';
                e.currentTarget.style.transform = 'translateY(-1px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.03)';
                e.currentTarget.style.transform = 'none';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: tool.bgColor,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <span style={{ color: tool.color, fontSize: 14 }}>{tool.icon}</span>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Text strong style={{ fontSize: 12, color: '#334155' }}>{tool.name}</Text>
                    <Tag color="blue" style={{ fontSize: 10, lineHeight: '16px', padding: '0 4px', borderRadius: 4 }}>
                      active
                    </Tag>
                  </div>
                  <Text style={{ fontSize: 11, color: '#64748b' }}>{tool.desc}</Text>
                  <br />
                  <Text style={{ fontSize: 10, color: '#94a3b8' }}>{tool.detail}</Text>
                </div>
              </div>
            </Card>
          ))}
        </Space>
      </div>
    </div>
  );
}
