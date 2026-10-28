import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Empty, Form, Input, Modal, Popconfirm, Select, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { backfillExperiences, createExperience, deleteExperience, listExperiences, getExperience, editExperience,
  reviewExperience, distillExperience, searchExperiences, feedbackExperience } from '../api.js'
const { Title, Text } = Typography
const modules = { code_audit: '代码审计', reverse: '逆向分析', log_analysis: '日志分析', penetration: '渗透测试' }
const statuses = { draft: '待审核', approved: '已审核启用', rejected: '已拒绝', retired: '已停用' }
const methods = { evidence_rules_v2: '实际证据提取', model_distillation: '模型提炼', manual: '人工编写', manual_edit: '人工编辑' }
const kinds = { success_pattern: '完成任务经验', failure_lesson: '失败教训', operator_note: '人工经验' }
const pageSize = 12
const toLines = value => (value || []).join('\n')
const fromLines = value => String(value || '').split('\n').map(x => x.trim()).filter(Boolean)
const labelTime = value => value ? new Date(value).toLocaleString() : '—'
export function ExperienceLibraryPage() {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const experienceId = searchParams.get('experience') || ''
  const linkedRunId = searchParams.get('run') || ''
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [distilling, setDistilling] = useState(false)
  const [filters, setFilters] = useState({ module_route: '', review_status: '', q: '' })
  const [page, setPage] = useState(1)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [usagePage, setUsagePage] = useState(1)
  const [editor, setEditor] = useState(null)
  const [form] = Form.useForm()
  const [previewQuery, setPreviewQuery] = useState('')
  const [previewModule, setPreviewModule] = useState('code_audit')
  const [matches, setMatches] = useState(null)
  const [feedback, setFeedback] = useState(null)
  const [note, setNote] = useState('')
  const loadSequence = useRef(0)
  const detailSequence = useRef(0)
  const detailTarget = useRef(null)
  const previewSequence = useRef(0)
  const actionInFlight = useRef(false)
  const editorSequence = useRef(0)
  const load = async () => {
    const sequence = ++loadSequence.current
    try { const next = await listExperiences({ ...filters, limit: pageSize, offset: (page - 1) * pageSize }); if (sequence === loadSequence.current) { setData(next); setError(''); if (page > 1 && next.statistics.total <= (page - 1) * pageSize) setPage(page - 1) }; return true }
    catch(e) { if (sequence === loadSequence.current) { setData(null); setError(e.message) }; return false }
  }
  useEffect(() => { load() }, [filters.module_route, filters.review_status, filters.q, page])
  const refreshDetail = useCallback(async id => {
    const sequence = ++detailSequence.current
    detailTarget.current = id
    setDetail(null)
    setDetailLoading(true)
    setDetailError('')
    try {
      const next = await getExperience(id)
      if (sequence !== detailSequence.current) return false
      if (next?.experience?.experience_id !== id || !Array.isArray(next.uses) || !Array.isArray(next.history)
        || next.uses.some(use => typeof use?.run_id !== 'string' || !use.run_id || !Number.isInteger(use.version) || use.version < 1)) {
        throw new TypeError(`经验 ${id} 的详情响应缺少有效的 experience、uses 或 history 字段，请刷新重试`)
      }
      setDetail(next)
      return true
    } catch(e) {
      if (sequence === detailSequence.current) setDetailError(e.message)
      return false
    } finally {
      if (sequence === detailSequence.current) setDetailLoading(false)
    }
  }, [])
  useEffect(() => {
    setFeedback(null)
    setEditor(null)
    editorSequence.current += 1
    if (experienceId) refreshDetail(experienceId)
    else {
      detailTarget.current = null
      setDetail(null)
      setDetailLoading(false)
      setDetailError('')
    }
    return () => {
      detailSequence.current += 1
      editorSequence.current += 1
      detailTarget.current = null
    }
  }, [experienceId, refreshDetail])
  useEffect(() => {
    const index = detail?.uses.findIndex(use => use.run_id === linkedRunId) ?? -1
    setUsagePage(index < 0 ? 1 : Math.floor(index / 5) + 1)
    setFeedback(null)
  }, [detail, linkedRunId])
  const openDetail = async item => {
    if (item.experience_id === experienceId) return refreshDetail(item.experience_id)
    // Invalidate before navigation so an older request cannot reopen a detail.
    detailSequence.current += 1
    detailTarget.current = item.experience_id
    setDetail(null)
    setFeedback(null)
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      next.set('experience', item.experience_id)
      return next
    })
    return true
  }
  const closeDetail = () => {
    detailSequence.current += 1
    detailTarget.current = null
    setDetail(null)
    setDetailLoading(false)
    setFeedback(null)
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      next.delete('experience')
      return next
    })
  }
  const act = async fn => {
    if (actionInFlight.current) return
    actionInFlight.current = true
    setBusy(true)
    try {
      const result = await fn()
      if (!await load()) message.warning('操作已完成，经验列表暂未刷新')
      return result
    } catch(e) { message.error(e.message) }
    finally { actionInFlight.current = false; setBusy(false) }
  }
  const openEditor = item => {
    editorSequence.current += 1
    setEditor({ item }); form.resetFields();
    form.setFieldsValue({ module_route: item?.module_route || 'code_audit', experience_kind: item?.experience_kind || 'operator_note',
      title: item?.title || '', summary: item?.summary || '', tags: toLines(item?.tags), conditions: toLines(item?.conditions),
      lessons: toLines(item?.lessons), steps: toLines(item?.steps), limitations: toLines(item?.limitations) })
  }
  const save = async () => {
    let values
    try { values = await form.validateFields() } catch { return }
    const editorToken = editorSequence.current
    const content = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, ['conditions', 'lessons', 'steps', 'limitations', 'tags'].includes(key) ? fromLines(value) : value]))
    await act(async () => {
      let result
      if (editor.item) { const { module_route, experience_kind, ...editable } = content; result = await editExperience(editor.item.experience_id, { ...editable, expected_version: editor.item.version }) }
      else result = await createExperience(content)
      if (editorToken === editorSequence.current) {
        setEditor(null)
        message.success('已保存为待审核版本，审核启用后才会进入任务检索')
        await openDetail(result.experience)
      }
    })
  }
  const review = async (item, decision) => { const sequence = detailSequence.current; return act(async () => { const result = await reviewExperience(item.experience_id, { decision, expected_version: item.version, note: '' }); message.success(statuses[result.experience.review_status]); if (sequence === detailSequence.current) await openDetail(result.experience) }) }
  const experience = detail?.experience.experience_id === experienceId ? detail.experience : null
  const linkedUses = experience ? detail.uses.filter(use => use.run_id === linkedRunId) : []
  const taskUrl = linkedRunId ? `/workbench?${new URLSearchParams({ run: linkedRunId })}` : ''
  const metric = (title, value) => <div className="catalog-metric" key={title}><Statistic title={title} value={value ?? '—'} /></div>
  return <div className="experience-page">
    <section className="page-intro"><div><Text className="panel-kicker">EVIDENCE → REVIEW → RETRIEVAL → USE</Text><Title level={2}>经验学习库</Title><p>从实际任务观测提炼经验，审核后按相关性检索进入后续规划；保留具体版本、使用任务与结果反馈。</p></div><Space wrap>
      {taskUrl && <Link data-testid="experience-return-task" to={taskUrl}>返回任务</Link>}
      <Button loading={busy} onClick={() => act(async () => { const r = await backfillExperiences(); message.success(`新建 ${r.created} · 更新 ${r.updated} · 未变化 ${r.unchanged} · 跳过 ${r.skipped}`) })}>提取历史任务经验</Button>
      <Button type="primary" onClick={() => openEditor(null)}>新增人工经验</Button><Button onClick={load}>刷新</Button></Space></section>
    {error && <Alert type="error" message={`读取失败：${error}`} />}
    <section className="catalog-metrics">{metric('筛选范围经验数', data?.statistics?.total)}{metric('待审核', data?.statistics?.draft)}{metric('已审核启用', data?.statistics?.verified)}{metric('实际注入规划次数', data?.statistics?.usage_count)}</section>
    <section className="glass-panel" style={{ padding: 20 }}><Title level={4}>相关性检索预览</Title><p>只检索已审核启用的同模块经验；无相关内容返回空。预览不会增加使用次数。</p><Space.Compact style={{ width: '100%' }}>
      <Select aria-label="检索模块" style={{ width: 140 }} value={previewModule} onChange={value => { previewSequence.current += 1; setPreviewModule(value); setMatches(null) }} options={Object.entries(modules).map(([value, label]) => ({ value, label }))} />
      <Input aria-label="检索任务目标" value={previewQuery} onChange={e => { previewSequence.current += 1; setPreviewQuery(e.target.value); setMatches(null) }} placeholder="输入下一次任务目标，例如检查 Python 命令注入" />
      <Button loading={busy} disabled={!previewQuery.trim()} onClick={() => act(async () => { const sequence = ++previewSequence.current; const result = await searchExperiences(previewModule, previewQuery); if (sequence === previewSequence.current) setMatches(result.experiences) })}>预览检索</Button></Space.Compact>
      {matches && <div style={{ marginTop: 12 }}>{matches.length ? matches.map(item => <div key={item.experience_id}><Button type="link" onClick={() => openDetail(item)}>{item.title} · v{item.version}</Button><span>相关度 {item.relevance_score} · {item.retrieval_reason}</span></div>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有已启用且相关的经验" />}</div>}
    </section>
    <section className="glass-panel" style={{ padding: 20, marginTop: 16 }}><Space wrap style={{ marginBottom: 16 }}>
      <Select aria-label="筛选模块" value={filters.module_route} style={{ width: 140 }} onChange={v => { setPage(1); setFilters(f => ({ ...f, module_route: v })) }} options={[{ value: '', label: '全部模块' }, ...Object.entries(modules).map(([value,label])=>({value,label}))]} />
      <Select aria-label="筛选审核状态" value={filters.review_status} style={{ width: 150 }} onChange={v => { setPage(1); setFilters(f => ({ ...f, review_status: v })) }} options={[{ value: '', label: '全部审核状态' }, ...Object.entries(statuses).map(([value,label])=>({value,label}))]} />
      <Input.Search aria-label="搜索经验" placeholder="搜索标题、条件或内容" onSearch={q => { setPage(1); setFilters(f=>({...f,q})) }} allowClear />
    </Space>
    <Table rowKey="experience_id" dataSource={data?.experiences || []} pagination={{ current: page, pageSize, total: data?.statistics?.total || 0, showTotal: total => `共 ${total} 条` }} onChange={pagination => setPage(pagination.current)} columns={[
      { title: '经验', render: (_, item) => <div><Button type="link" style={{ padding: 0 }} onClick={()=>openDetail(item)}>{item.title}</Button><p style={{ maxWidth: 480, margin: 0 }}>{item.summary.slice(0, 180)}</p><small>{modules[item.module_route]} · {kinds[item.experience_kind]} · {methods[item.extraction_method]}</small></div> },
      { title: '版本与状态', render: (_, item) => <><Tag color={item.review_status === 'approved' ? 'green' : 'default'}>{statuses[item.review_status]}</Tag><p>v{item.version} · {labelTime(item.updated_at)}</p></> },
      { title: '注入规划', dataIndex: 'usage_count' }, { title: '操作', render: (_, item) => <Space direction="vertical"><Button size="small" onClick={()=>openDetail(item)}>详情 / 审核</Button><Button size="small" onClick={()=>openEditor(item)}>编辑</Button>{item.source_run_id && <Button size="small" onClick={()=>navigate(`/workbench?run=${item.source_run_id}`)}>来源任务</Button>}<Popconfirm title="删除后，历史同步不会重新生成此经验。确认删除？" onConfirm={()=>act(async()=>{await deleteExperience(item.experience_id); if(detailTarget.current === item.experience_id) closeDetail()})}><Button size="small" danger>删除</Button></Popconfirm></Space> },
    ]} /></section>
    <Modal open={!!experienceId && !editor && !feedback} title="经验详情与使用证据" width={1000} onCancel={closeDetail} footer={null} data-testid="experience-detail">
      {taskUrl && <p><Link data-testid="experience-detail-return-task" to={taskUrl}>返回任务</Link></p>}
      {(detailLoading || (!experience && !detailError)) && <div role="status" data-testid="experience-detail-loading"><Spin /> 正在读取经验详情…</div>}
      {detailError && <Alert type="error" showIcon message="经验详情读取失败" description={detailError} data-testid="experience-detail-error"
        action={<Button data-testid="experience-detail-retry" onClick={() => refreshDetail(experienceId)}>重试</Button>} />}
      {experience && <><Title level={4}>{experience.title}</Title><Space wrap><Tag>{statuses[experience.review_status]}</Tag><Tag>当前版本 v{experience.version}</Tag><Tag>{methods[experience.extraction_method]}</Tag><Text>哈希 {experience.content_hash.slice(0,16)}</Text></Space><p>{experience.summary}</p>
      {linkedRunId && <Alert type={linkedUses.length ? 'info' : 'warning'} showIcon data-testid="experience-linked-use"
        message={linkedUses.length ? `此任务实际注入版本：${linkedUses.map(use => `v${use.version}`).join('、')}` : '未找到此任务的实际使用记录'}
        description={linkedUses.length ? '已定位并标记下方对应使用记录；反馈针对该次注入版本，不是经验当前版本。' : '不会创建使用记录或自动提交反馈。'} />}
      <Alert type="info" message="审核表示操作人允许将此版本作为历史参考，不等于验证了通用正确率。账本完整性、相关度与使用反馈分别记录。" />
      {distilling && <Alert type="info" showIcon style={{ marginTop: 12 }} message="AI 正在提炼经验" description="模型调用和证据校验可能需要约 2 分钟。完成或失败后会在这里提示结果。" />}
      {['conditions','lessons','steps','limitations'].map((key,i)=><section key={key}><Title level={5}>{['适用条件','可复用经验','实际步骤 / 建议步骤','适用限制'][i]}</Title><ol>{experience[key].map((text,index)=><li key={index}>{text}</li>)}</ol></section>)}
      <details><summary>实际来源证据（{experience.evidence.length}） · 账本{experience.chain_valid == null ? '不适用' : experience.chain_valid ? '完整' : '校验失败'}</summary><pre style={{whiteSpace:'pre-wrap',maxHeight:300,overflow:'auto'}}>{JSON.stringify(experience.evidence,null,2)}</pre></details>
      <Space wrap style={{margin:'16px 0'}}><Button onClick={()=>openEditor(experience)}>编辑此版本</Button>
      {experience.source_run_id && <Popconfirm title="使用当前配置的模型实际提炼？会产生模型调用用量，新版本仍需审核。" onConfirm={()=>{ const sequence = detailSequence.current; return act(async()=>{ setDistilling(true); try { const r=await distillExperience(experience.experience_id); message.success('模型提炼已保存，等待审核'); if (sequence === detailSequence.current) await openDetail(r.experience) } finally { setDistilling(false) } }) }}><Button loading={distilling} disabled={busy && !distilling}>AI 提炼</Button></Popconfirm>}
      {experience.review_status !== 'approved' && <Button type="primary" loading={busy} onClick={()=>review(experience,'approve')}>审核并启用</Button>}
      {experience.review_status === 'approved' ? <Button loading={busy} onClick={()=>review(experience,'retire')}>停用</Button> : <Button loading={busy} onClick={()=>review(experience,'reject')}>拒绝</Button>}</Space>
      <Title level={5}>实际使用记录</Title><p>计数只发生在模型成功接收经验并返回规划后。任务完成不直接证明经验有效，可对具体使用记录反馈。</p>
      <Table size="small" data-testid="experience-usage-table" rowKey={r=>`${r.run_id}-${r.version}`} dataSource={detail.uses}
        pagination={{current:usagePage,pageSize:5,showSizeChanger:false}} onChange={pagination=>setUsagePage(pagination.current)}
        onRow={r=>({ 'data-testid': `experience-use-${r.run_id}-${r.version}`, 'aria-current': r.run_id === linkedRunId ? 'true' : undefined,
          style: r.run_id === linkedRunId ? { background: 'rgba(22,119,255,0.12)' } : undefined })} columns={[
        {title:'任务 / 注入版本',render:(_,r)=><><Link to={`/workbench?${new URLSearchParams({run:r.run_id})}`}>{r.run_id.slice(0,12)} · v{r.version}</Link>{r.run_id === linkedRunId && <Tag color="blue">当前任务</Tag>}</>},
        {title:'使用情况',render:(_,r)=><span>{r.model_cited?'模型声明采用':'已注入；未声明采用'}<br/>{r.outcome} · {r.model_id}</span>},
        {title:'反馈',render:(_,r)=><Button data-testid={`experience-feedback-${r.run_id}-${r.version}`} onClick={()=>{setFeedback({...r,experience_id:experience.experience_id});setNote(r.feedback?.note || '')}}>{r.feedback ? {helpful:'有帮助',not_helpful:'无帮助',uncertain:'不确定'}[r.feedback.verdict] : '填写反馈'}</Button>},
      ]}/>
      <details><summary>版本与审核历史（{detail.history.length}）</summary>{detail.history.map((h,i)=><div key={i}><b>{h.action} · {labelTime(h.at)} · v{h.snapshot?.version || '旧版'}</b><p>{h.note}</p><pre style={{whiteSpace:'pre-wrap',maxHeight:150,overflow:'auto'}}>{JSON.stringify(h.snapshot,null,2)}</pre></div>)}</details>
      {experience.model_receipt && <details><summary>模型提炼回执</summary><pre>{JSON.stringify(experience.model_receipt,null,2)}</pre></details>}
      </>}
    </Modal>
    <Modal open={!!editor} title={editor?.item ? '编辑经验（保存后需重新审核）' : '新增人工经验'} width={850} onCancel={()=>{ if (!busy) { editorSequence.current += 1; setEditor(null) } }} closable={!busy} keyboard={!busy} maskClosable={!busy} cancelButtonProps={{ disabled: busy }} okButtonProps={{ disabled: busy }} onOk={save} confirmLoading={busy} okText="保存待审核版本">
      <Form form={form} layout="vertical" disabled={busy}><Form.Item name="title" label="标题" rules={[{required:true,min:2,max:240}]}><Input /></Form.Item><Form.Item name="summary" label="概要" rules={[{required:true,min:3,max:4000}]}><Input.TextArea rows={3}/></Form.Item>
      <Space><Form.Item name="module_route" label="模块"><Select style={{width:160}} disabled={!!editor?.item} options={Object.entries(modules).map(([value,label])=>({value,label}))}/></Form.Item><Form.Item name="experience_kind" label="类型"><Select style={{width:170}} disabled={!!editor?.item} options={Object.entries(kinds).map(([value,label])=>({value,label}))}/></Form.Item></Space>
      {['conditions','lessons','steps','limitations','tags'].map((key,i)=><Form.Item key={key} name={key} label={['适用条件（每行一条）','可复用经验（每行一条）','步骤（每行一条）','限制（每行一条）','标签（每行一条）'][i]} rules={i<2?[{required:true}]:[]}><Input.TextArea rows={i===1?5:2}/></Form.Item>)}</Form>
    </Modal>
    <Modal open={!!feedback && !!experience && feedback.experience_id === experience.experience_id} title="这次使用是否有帮助？" data-testid="experience-feedback-dialog"
      onCancel={()=>!busy && setFeedback(null)} closable={!busy} keyboard={!busy} maskClosable={!busy}
      footer={<Space>{['helpful','not_helpful','uncertain'].map(verdict=><Button key={verdict} data-testid={`experience-feedback-submit-${verdict}`} loading={busy} disabled={busy || !experience} onClick={()=>{
        if (!feedback || !experience || feedback.experience_id !== experience.experience_id) return
        const sequence=detailSequence.current
        return act(async()=>{
          await feedbackExperience(feedback.experience_id,{run_id:feedback.run_id,version:feedback.version,verdict,note})
          message.success('反馈已保存')
          if(sequence===detailSequence.current) { setFeedback(null); await refreshDetail(feedback.experience_id) }
        })
      }}>{ {helpful:'有帮助',not_helpful:'无帮助',uncertain:'不确定'}[verdict]}</Button>)}</Space>}>
      <p>任务 {feedback?.run_id} · 实际注入版本 v{feedback?.version}</p>
      <Input.TextArea data-testid="experience-feedback-note" aria-label="使用反馈原因" disabled={busy} rows={4} maxLength={2000} value={note} onChange={e=>setNote(e.target.value)} placeholder="请根据这次任务的实际结果填写原因" />
    </Modal>
  </div>
}
