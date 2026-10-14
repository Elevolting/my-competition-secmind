export function incidentFeedback(result, operation = 'command') {
  const status = result?.action?.status
  if (status === 'failed') return { level: 'error', text: result.action.error || '执行失败，请查看回执' }
  if (status === 'partial') return { level: 'warning', text: '采集部分完成，请查看错误明细' }
  if (status === 'denied' || result?.approval?.status === 'denied') return { level: 'info', text: '审批已拒绝，动作未执行' }
  if (result?.approval?.status === 'pending') return { level: 'info', text: '已进入审批队列，尚未执行' }
  if (operation === 'upload') return { level: 'success', text: '上传完成，文件尚未隔离' }
  return { level: 'success', text: '操作完成' }
}
