import React from 'react'
import { Tag } from 'antd'

const statusMap = { pending: ['default', '等待调度'], running: ['processing', '运行中'], waiting_approval: ['warning', '等待审批'], completed: ['success', '已完成'], partial: ['warning', '部分完成'], denied: ['error', '已拒绝'], failed: ['error', '失败'], timeout: ['error', '超时'], unavailable: ['error', '不可用'], poll_error: ['error', '轮询异常'], idle: ['default', '待命'], active: ['processing', '工作中'] }

export function StatusTag({ status }) {
  const [color, label] = statusMap[status] || ['default', status || '未知']
  return <Tag color={color}>{label}</Tag>
}
