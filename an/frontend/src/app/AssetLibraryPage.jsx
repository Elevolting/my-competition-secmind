import React, { useEffect, useState } from 'react'
import { Alert, Button, Empty, Input, Modal, Select, Space, Spin, Table, Tag, Typography } from 'antd'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getAsset, listAssets } from '../api.js'
import './asset-library.css'

const kinds = { domain: '域名', ip: 'IP', service: '服务', endpoint: '端点' }
const sources = { scope: '任务范围', tool: '成功观测', invocation: '工具调用', finding: '发现引用' }
const statuses = { scoped: '范围已登记', referenced: '有发现引用', invoked: '已调用工具', discovered: '有成功观测' }
const pageSize = 20
const time = value => value ? new Date(value).toLocaleString('zh-CN') : '—'
const options = labels => Object.entries(labels).map(([value, label]) => ({ value, label }))

export function AssetLibraryPage() {
  const navigate = useNavigate()
  const { assetId } = useParams()
  const [filters, setFilters] = useState({ search: '', kind: '', coverage: '', run_id: '' })
  const [page, setPage] = useState(1)
  const [revision, setRevision] = useState(0)
  const [listing, setListing] = useState({ busy: true, data: null, error: '' })
  const [detail, setDetail] = useState({ busy: false, data: null, error: '' })
  const filter = (key, value) => { setFilters(current => ({ ...current, [key]: value || '' })); setPage(1) }

  useEffect(() => {
    const controller = new AbortController()
    setListing({ busy: true, data: null, error: '' })
    listAssets({ ...filters, limit: pageSize, offset: (page - 1) * pageSize }, controller.signal)
      .then(data => {
        if (controller.signal.aborted) return
        if (page > 1 && data.total <= (page - 1) * pageSize) { setPage(1); return }
        setListing({ busy: false, data, error: '' })
      })
      .catch(error => { if (!controller.signal.aborted) setListing({ busy: false, data: null, error: error.message }) })
    return () => controller.abort()
  }, [filters, page, revision])

  useEffect(() => {
    const controller = new AbortController()
    setDetail({ busy: !!assetId, data: null, error: '' })
    if (assetId) getAsset(assetId, controller.signal)
      .then(data => { if (!controller.signal.aborted) setDetail({ busy: false, data, error: '' }) })
      .catch(error => { if (!controller.signal.aborted) setDetail({ busy: false, data: null, error: error.message }) })
    return () => controller.abort()
  }, [assetId, revision])

  return <div className="asset-library">
    <div className="asset-library-heading">
      <div><Typography.Title level={3}>跨任务资产库</Typography.Title><p>查看资产的历史来源、任务范围和成功观测。</p></div>
      <Button onClick={() => setRevision(value => value + 1)} loading={listing.busy}>刷新资产</Button>
    </div>
    <Alert type="info" showIcon title="观测记录不代表完整测试覆盖"
      description="观测表示任务有成功的显式记录，不代表该资产的所有方法和参数均已验证。每个任务的授权范围独立。" />
    <div className="asset-library-filters">
      <Input.Search aria-label="搜索资产" placeholder="搜索域名、IP 或路径" allowClear onSearch={value => filter('search', value)} />
      <Select aria-label="资产类型" placeholder="全部类型" allowClear value={filters.kind || undefined}
        options={options(kinds)} onChange={value => filter('kind', value)} />
      <Select aria-label="观测状态" placeholder="全部观测状态" allowClear value={filters.coverage || undefined}
        options={options({ observed: '有成功观测的任务', unobserved: '无成功观测的任务' })}
        onChange={value => filter('coverage', value)} />
      <Input.Search aria-label="按任务筛选资产" placeholder="输入完整任务编号" allowClear onSearch={value => filter('run_id', value.trim())} />
    </div>
    <section className="asset-library-results" aria-label="资产列表">
      <Typography.Text type="secondary">匹配资产 {listing.data?.total ?? '—'} 个 · 计数为各资产的累计任务记录</Typography.Text>
      {listing.error && <Alert type="error" showIcon title="资产列表加载失败" description={listing.error}
        action={<Button onClick={() => setRevision(value => value + 1)}>重试</Button>} />}
      <Table rowKey="asset_id" loading={listing.busy} dataSource={listing.data?.assets || []}
        scroll={{ x: 780 }} locale={{ emptyText: <Empty description="没有匹配的资产" /> }}
        pagination={{ current: page, pageSize, total: listing.data?.total || 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          { title: '资产', dataIndex: 'label', width: 360, render: (label, asset) => <Link className="asset-library-label" to={`/assets/${encodeURIComponent(asset.asset_id)}`}>{label}</Link> },
          { title: '类型', dataIndex: 'kind', render: kind => <Tag>{kinds[kind] || kind}</Tag> },
          { title: '来源任务', dataIndex: 'run_count' },
          { title: '有观测任务', dataIndex: 'observed_run_count' },
          { title: '关联发现', dataIndex: 'finding_count' },
        ]} />
    </section>
    <Modal open={!!assetId} title="资产详情与任务来源" width={940} footer={null} onCancel={() => navigate('/assets')}>
      <div className="asset-library-detail">
        {detail.busy && <div role="status"><Spin /> 正在加载资产…</div>}
        {detail.error && <Alert type="error" title="资产详情加载失败" description={detail.error}
          action={<Button onClick={() => setRevision(value => value + 1)}>重试</Button>} />}
        {detail.data && <>
          <Typography.Title level={4}>{detail.data.label}</Typography.Title>
          <Tag>{kinds[detail.data.kind] || detail.data.kind}</Tag>
          {detail.data.runs.map(run => <section className="asset-library-run" key={run.run_id}>
            <Space wrap><Link to={`/workbench?run=${encodeURIComponent(run.run_id)}`}>打开任务 {run.run_id}</Link>
              <Tag color={run.coverage === 'observed' ? 'green' : 'default'}>{run.coverage === 'observed' ? '有成功观测' : '无成功观测'}</Tag>
              <Tag>{statuses[run.status] || run.status}</Tag></Space>
            <div><b>任务授权范围</b><ul>{run.scope_display.map((value, index) => <li key={index}>{value}</li>)}</ul></div>
            <div><b>来源：</b>{run.sources.map(source => sources[source] || source).join('、')}</div>
            <div><b>关联发现：</b>{run.finding_ids.length ? run.finding_ids.join('、') : '暂无'}</div>
            <Typography.Text type="secondary">首次记录 {time(run.first_seen)} · 最近记录 {time(run.last_seen)}</Typography.Text>
            <details><summary>来源记录（{run.provenance.length}）</summary>
              <ul>{run.provenance.map((item, index) => <li key={index}>{sources[item.source] || item.source} · {item.ref || '未提供引用'}
                {item.observed_at && ` · ${time(item.observed_at)}`}{item.confidence != null && ` · 置信度 ${item.confidence}`}</li>)}</ul>
            </details>
          </section>)}
        </>}
      </div>
    </Modal>
  </div>
}
