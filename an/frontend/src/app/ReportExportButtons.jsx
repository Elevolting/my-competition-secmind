import React, { useState } from 'react'
import { DownloadOutlined } from '@ant-design/icons'
import { Alert, Button, Space } from 'antd'
import { createReportDownloads, downloadReport } from './reportExport.js'

/**
 * Export the supplied report snapshot only; no refresh or model/API requests.
 * @param {{ report: import('./reportExport.js').ExportReportInput | null, run: import('./reportExport.js').ExportRunInput | null | undefined }} props
 * @returns {React.JSX.Element}
 */
export function ReportExportButtons({ report, run }) {
  const [error, setError] = useState('')

  /** @param {(files: import('./reportExport.js').ReportDownloads) => import('./reportExport.js').ReportDownload} selectFile @returns {void} */
  function saveReport(selectFile) {
    setError('')
    try {
      if (!report) throw new TypeError('报告尚未生成，无法导出；请等待报告生成后重试')
      downloadReport(selectFile(createReportDownloads(report, run)))
    } catch (cause) {
      if (!(cause instanceof Error)) throw cause
      setError(`报告导出失败：${cause.message}`)
    }
  }

  return <Space direction="vertical" size="small" data-testid="report-export-controls" aria-label="报告下载">
    <Space wrap size="small">
      <Button size="small" icon={<DownloadOutlined />} data-testid="report-export-markdown" aria-label="下载 Markdown 报告"
        disabled={!report} onClick={() => saveReport(files => files.markdown)}>下载 Markdown</Button>
      <Button size="small" icon={<DownloadOutlined />} data-testid="report-export-html" aria-label="下载 HTML 报告"
        disabled={!report} onClick={() => saveReport(files => files.html)}>下载 HTML</Button>
    </Space>
    {error && <Alert type="error" showIcon title={error} role="alert" data-testid="report-export-error" />}
  </Space>
}
