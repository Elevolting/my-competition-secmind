import React, { useEffect, useRef, useState } from 'react'
import { parseTargetUrls, targetScopeFor } from './target-urls.js'
import { defaultTaskBudget, validTaskBudget } from './task-budget.js'
import { TaskBudgetFields } from './TaskBudgetFields.jsx'
import {
  constraintForNetworkPolicy,
  defaultNetworkPolicyFor,
  networkPolicyOptions,
  networkPolicyPreset,
  STATIC_ONLY_CONSTRAINT,
} from './network-policy-presets.js'
import { BranchesOutlined, CheckCircleOutlined, FileSearchOutlined, InboxOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { Alert, App, Button, Descriptions, Form, Input, Modal, Radio, Select, Spin, Table, Tag, Upload } from 'antd'
import {
  confirmQuestionBank,
  createBatch,
  createTask,
  getQuestionBankInspection,
  inspectQuestionBank,
  questionBankEventSocketUrl,
  uploadFile,
  classifyTask,
  getTaskBudgetDefaults,
} from '../api.js'

const { Dragger } = Upload

export function TaskModal({ open, onClose, onCreated }) {
  const { message } = App.useApp()
  const [form] = Form.useForm()
  const [mode, setMode] = useState('single_file')
  const [files, setFiles] = useState([])
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [error, setError] = useState('')
  const [questionBankInspection, setQuestionBankInspection] = useState(null)
  const [classification, setClassification] = useState(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [textMaterial, setTextMaterial] = useState('')
  const [createdResult, setCreatedResult] = useState(null)
  const creating = useRef(false)
  const createRequestId = useRef(null)
  const batchRequestId = useRef(null)
  useEffect(() => {
    const bankId = questionBankInspection?.bank_id
    if (!bankId || questionBankInspection.status !== 'inspecting') return undefined
    let alive = true
    const socket = new WebSocket(questionBankEventSocketUrl(bankId))
    const refresh = () => getQuestionBankInspection(bankId)
      .then((data) => alive && setQuestionBankInspection((current) => current?.bank_id === bankId ? { ...current, ...data } : current))
      .catch(() => {})
    socket.onmessage = (event) => {
      if (!alive) return
      let payload
      try { payload = JSON.parse(event.data)?.payload } catch { refresh(); return }
      if (payload?.status) {
        setQuestionBankInspection((current) => current?.bank_id === bankId ? { ...current, ...payload } : current)
      } else if (payload?.stage) {
        setQuestionBankInspection((current) => current?.bank_id === bankId ? { ...current, stage: payload.stage } : current)
      }
    }
    socket.onerror = refresh
    socket.onclose = refresh
    return () => { alive = false; socket.close() }
  }, [questionBankInspection?.bank_id, questionBankInspection?.status])

  async function submit(values) {
    setError('')
    const isQuestionBankMode = mode === 'ai_assisted' || mode === 'formatted_question_bank'
    let targetUrls = []
    const normalizedText = isQuestionBankMode ? '' : textMaterial.trim()
    try {
      targetUrls = isQuestionBankMode ? [] : parseTargetUrls(targetUrl)
    } catch (urlError) {
      setError(urlError.message)
      return
    }
    if (!files.length && !targetUrls.length && !normalizedText) {
      setError(isQuestionBankMode
        ? '请先上传题库文件或压缩包；没有输入材料时无法创建题库分析任务。'
        : '请先上传一个题目文件、源码或压缩包；没有输入材料时无法进行实际分析。')
      return
    }
    if (mode === 'single_file' && files.length > 1) {
      setError('单文件分析一次只能上传一个文件；多个题目请改用 AI辅助文件分析或题库格式化文件分析。')
      return
    }
    setBusy(true)
    try {
      const materialItems = [...files]
        for (const [index, url] of targetUrls.entries()) {
          materialItems.push({
            originFileObj: new File([url], targetUrls.length === 1 ? 'target-url.url' : `target-url-${index + 1}.url`, { type: 'text/plain' }),
          })
        }
        if (normalizedText) {
          materialItems.push({
            originFileObj: new File([normalizedText], 'input-context.md', { type: 'text/markdown' }),
          })
        }
        const attachments = []
        for (const [index, item] of materialItems.entries()) {
          const file = item.originFileObj || item
          setProgress(`正在上传 ${index + 1}/${materialItems.length}：${file.name}`)
          const uploaded = await uploadFile(file)
          attachments.push({ ref: uploaded.ref, name: uploaded.name })
        }
      if (isQuestionBankMode) {
        setProgress(mode === 'formatted_question_bank' ? '正在读取格式化元数据并分配模块' : '正在识别题目边界、数量与类型')
        const inspection = await inspectQuestionBank({
          name: values.name.trim(),
          attachments,
          analysis_mode: mode === 'formatted_question_bank' ? 'formatted' : 'ai_assisted',
        })
        setQuestionBankInspection({ ...inspection, attachments, values })
        setProgress('')
        return
      }
      setProgress('正在识别题型并选择分析模块')
      const [route, budgetConfig] = await Promise.all([classifyTask({
        objective: routingObjective(values.objective, normalizedText),
        attachments,
        target_scope: targetScopeFor(values, targetUrls),
        expected_outputs: ['security_report'],
        constraints: [],
      }), getTaskBudgetDefaults()])
      setClassification({
        ...route,
        budget: defaultTaskBudget(budgetConfig, route.primary_type),
        budgetLimits: budgetConfig.limits,
        // Keep the exact material-aware objective used during preview routing.
        // The backend receives the same context again when the task is confirmed.
        objective: routingObjective(values.objective, normalizedText),
        attachments,
        values,
        targetUrls,
        networkPolicy: defaultNetworkPolicyFor({
          primaryType: route.primary_type,
          constraints: values.constraints,
        }),
      })
      setProgress('')
      return
    } catch (submitError) {
      const detail = submitError instanceof Error ? submitError.message : String(submitError)
      setError(`提交失败：${detail}`)
      message.error(`任务未创建：${detail}`)
    } finally {
      setBusy(false)
      setProgress('')
    }
  }

  async function confirmAndCreateClassifiedTask() {
    if (!classification || creating.current || createdResult || !validTaskBudget(classification.budget, classification.budgetLimits)) return
    creating.current = true
    setBusy(true)
    setError('')
    try {
      const values = classification.values
      const httpPolicy = classification.primary_type === 'penetration' && networkPolicyPreset(classification.networkPolicy)
        ? classification.networkPolicy : 'none'
      const constraints = constraintForNetworkPolicy(httpPolicy, values.constraints)
      setProgress(`正在分发至${moduleLabel(classification.primary_type)}模块`)
      const taskPayload = {
        name: values.name.trim(),
        objective: classification.objective || values.objective.trim(),
        attachments: classification.attachments,
        target_scope: targetScopeFor(values, classification.targetUrls),
        constraints: constraints ? [constraints] : [],
        network_policy: httpPolicy,
        expected_outputs: ['security_report'], autonomy_policy: values.autonomyPolicy,
        analysis_backend: values.analysisBackend || 'auto',
        ...classification.budget,
      }
      createRequestId.current ||= crypto.randomUUID()
      const task = await createTask(taskPayload, createRequestId.current)
      if (!task?.run_id) throw new Error('后端没有返回任务 ID')
      const created = { runId: task.run_id, evaluationId: null }
      setCreatedResult(created)
      try { await onCreated(created) } catch (navigationError) {
        setError(`任务已创建（ID：${created.runId}），页面更新失败：${navigationError.message}`)
        return
      }
      setCreatedResult(null)
      createRequestId.current = null
      form.resetFields(); setFiles([]); setClassification(null); setMode('single_file'); setTargetUrl(''); setTextMaterial('')
    } catch (submitError) {
      const detail = submitError instanceof Error ? submitError.message : String(submitError)
      setError(createRequestId.current
        ? `任务创建结果尚未确认：${detail}。请重试同一请求，后端会返回原任务。`
        : `任务创建失败：${detail}`)
    } finally { creating.current = false; setBusy(false); setProgress('') }
  }

  async function confirmAndCreateQuestionBankTask() {
    if (!questionBankInspection || creating.current || createdResult) return
    creating.current = true
    setBusy(true)
    setError('')
    try {
      setProgress('正在确认题库识别结果')
      await confirmQuestionBank(questionBankInspection.bank_id, {
        questions: questionBankInspection.questions.map((item) => ({
          candidate_id: item.candidate_id,
          confirmed: true,
          name: item.name,
          root: item.root,
          question_type: item.question_type,
        })),
      })
      setProgress('正在创建题库批次与子任务')
      batchRequestId.current ||= crypto.randomUUID()
      const batch = await createBatch({ question_bank_id: questionBankInspection.bank_id }, batchRequestId.current)
      if (!batch?.batch_id) throw new Error('后端没有返回批次 ID')
      const firstRunId = batch.tasks?.find((item) => item.run_id)?.run_id || null
      const created = { runId: firstRunId, batchId: batch.batch_id, evaluationId: null }
      setCreatedResult(created)
      try { await onCreated(created) } catch (navigationError) {
        setError(`批次已创建（ID：${created.batchId}），页面更新失败：${navigationError.message}`)
        return
      }
      setCreatedResult(null)
      batchRequestId.current = null
      form.resetFields()
      setFiles([])
      setQuestionBankInspection(null)
      setMode('single_file')
    } catch (submitError) {
      const detail = submitError instanceof Error ? submitError.message : String(submitError)
      setError(batchRequestId.current
        ? `批次创建结果尚未确认：${detail}。请重试同一请求，后端会返回原批次。`
        : `题库确认失败：${detail}`)
    } finally {
      creating.current = false
      setBusy(false)
      setProgress('')
    }
  }

  function resetDraft() {
    form.resetFields()
    setQuestionBankInspection(null)
    setClassification(null)
    setFiles([])
    setTargetUrl('')
    setTextMaterial('')
    setMode('single_file')
    setCreatedResult(null)
    createRequestId.current = null
    batchRequestId.current = null
    setError('')
  }

  async function openCreatedResult() {
    if (!createdResult || creating.current) return
    creating.current = true
    setBusy(true)
    try {
      await onCreated(createdResult)
      setCreatedResult(null)
      resetDraft()
    } catch (navigationError) {
      setError(`任务已创建，页面更新失败：${navigationError.message}`)
    } finally { creating.current = false; setBusy(false) }
  }

  return <Modal
    title="新建安全任务"
    centered
    styles={{ body: { maxHeight: 'calc(100dvh - 180px)', overflowY: 'auto', overflowX: 'hidden' } }}
    open={open}
    closable={!busy}
    keyboard={!busy}
    maskClosable={!busy}
    onCancel={busy ? undefined : () => { if (!createRequestId.current && !batchRequestId.current) resetDraft(); onClose() }}
    cancelButtonProps={{ disabled: busy }}
    width={questionBankInspection ? 960 : classification ? 780 : 720}
    okText={createdResult ? '打开已创建任务' : questionBankInspection?.status === 'inspecting' ? '正在预检' : questionBankInspection ? '确认映射并创建任务' : classification ? '确认路由并启动' : mode === 'ai_assisted' ? '上传并预检' : mode === 'formatted_question_bank' ? '读取格式并分配' : '上传并识别'}
    cancelText={createRequestId.current || batchRequestId.current ? '关闭并保留草稿' : '取消'}
    confirmLoading={busy}
    onOk={createdResult ? openCreatedResult : questionBankInspection ? confirmAndCreateQuestionBankTask : classification ? confirmAndCreateClassifiedTask : undefined}
    okButtonProps={createdResult ? { disabled: busy } : questionBankInspection ? { disabled: busy || !['awaiting_confirmation', 'needs_manual_mapping'].includes(questionBankInspection.status) || !questionBankInspection.questions?.length } : classification ? { disabled: busy || !validTaskBudget(classification.budget, classification.budgetLimits) } : { htmlType: 'submit', form: 'task-form', disabled: busy }}
  >
    {createdResult ? <Alert type="success" showIcon title="任务已创建，请勿重复提交" description={`任务 ID：${createdResult.runId || '等待批次分发'}${createdResult.batchId ? `；批次 ID：${createdResult.batchId}` : ''}`} /> : questionBankInspection ? <QuestionBankInspection inspection={questionBankInspection} disabled={busy} onChange={(next) => { if (busy) return; batchRequestId.current = null; setQuestionBankInspection(next) }} /> : classification ? <RouteConfirmation classification={classification} disabled={busy} onBack={() => { if (busy) return; createRequestId.current = null; setClassification(null) }} onBudgetChange={(budget) => { if (busy) return; createRequestId.current = null; setClassification((current) => ({ ...current, budget })) }} onNetworkPolicyChange={(networkPolicy) => { if (busy) return; createRequestId.current = null; setClassification((current) => ({ ...current, networkPolicy })) }} /> :
    <Form
      id="task-form"
      form={form}
      layout="vertical"
      disabled={busy}
      initialValues={{
        name: '上传材料安全审计',
        objective: '审计上传材料并生成带证据的安全报告',
        autonomyPolicy: 'graded',
        analysisBackend: 'auto',
        targetScope: 'uploaded-source',
        constraints: STATIC_ONLY_CONSTRAINT,
      }}
      onFinish={submit}
    >
      <Form.Item label="运行模式">
        <Radio.Group
          optionType="button"
          buttonStyle="solid"
          value={mode}
          disabled={busy}
          onChange={(event) => { setMode(event.target.value); setError('') }}
          options={[
            { value: 'single_file', label: '单文件分析' },
            { value: 'ai_assisted', label: 'AI辅助文件分析' },
            { value: 'formatted_question_bank', label: '题库格式化文件分析' },
          ]}
        />
      </Form.Item>

      <Form.Item
        name="name"
        label="任务名称"
        rules={[
          { required: true, whitespace: true, message: '请输入任务名称' },
          { max: 120, message: '任务名称不能超过 120 个字符' },
        ]}
      >
        <Input placeholder="例如：支付接口权限审计" maxLength={120} showCount />
      </Form.Item>

      <>
        {(mode === 'ai_assisted' || mode === 'formatted_question_bank') && <Alert
          className="question-bank-notice"
          type="info"
          showIcon
          title={mode === 'formatted_question_bank' ? '题库格式化文件分析' : 'AI辅助文件分析'}
          description={mode === 'formatted_question_bank'
            ? '压缩包内放置 question-bank.json、metadata.json 或对应 TXT 文件，填写题目类型、数量、目标和目录；工具流将按类型自动分配到代码审计、逆向或渗透模块。'
            : '上传题库压缩包后，由工具流和模型辅助识别题目边界、数量与类型，再确认模块分配。'}
        />}
        <Form.Item name="objective" label="任务目标" rules={[{ required: true }, { min: 3 }]}>
          <Input.TextArea rows={3} maxLength={10000} showCount />
        </Form.Item>
        <div className="form-grid task-policy-grid">
          <Form.Item name="targetScope" label="授权范围"><Input /></Form.Item>
          <Form.Item name="autonomyPolicy" label="执行策略">
            <Select options={[
              { value: 'graded', label: '分级审批' },
              { value: 'approval_all', label: '全部审批' },
              { value: 'automatic', label: '自动执行（免 R2 审批）' },
              { value: 'automatic_r3', label: '自动执行（免除所有审批）' },
            ]} />
          </Form.Item>
        </div>
        {mode === 'single_file' && <Form.Item name="analysisBackend" label="代码审计引擎" extra="仅对代码审计生效；日志和逆向任务由独立分析引擎执行。">
          <Select options={[
            { value: 'auto', label: '自动：在线使用 SecMind，演示使用本地规则' },
            { value: 'secmind', label: 'SecMind 完整分析流程' },
            { value: 'local', label: '本地静态规则扫描' },
          ]} />
        </Form.Item>}
        <Form.Item name="constraints" label="约束"><Input.TextArea rows={2} /></Form.Item>
        <Form.Item label={mode === 'single_file' ? '单个输入文件' : '题库材料'}>
          <Dragger disabled={busy} multiple={mode !== 'single_file'} fileList={files} beforeUpload={() => false} onChange={({ fileList }) => setFiles(fileList)}>
            <InboxOutlined className="upload-icon" />
            <p>{mode === 'single_file' ? '点击或拖放一个文件到此处' : '点击或拖放题库压缩包到此处'}</p>
            {mode === 'ai_assisted' && <p className="ant-upload-hint">支持按题目分目录组织的 ZIP 压缩包</p>}
            {mode === 'formatted_question_bank' && <p className="ant-upload-hint">ZIP 内需包含 JSON 或 TXT 格式化元数据文件</p>}
          </Dragger>
        </Form.Item>
        {mode === 'single_file' && <div className="material-source-grid">
          <Form.Item label="靶场网址（可选，可填多个）" extra="多个地址请换行，也支持逗号、分号或“和”分隔；省略协议时使用 http://。仅提交地址，不会自动访问未授权目标。">
            <Input.TextArea disabled={busy} value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} rows={3} placeholder={'10.0.0.1:8080\nhttps://target.lab.local/'} />
          </Form.Item>
          <Form.Item label="文本材料（可选）" extra="可粘贴题目说明、接口信息或补充线索">
            <Input.TextArea disabled={busy} value={textMaterial} onChange={(event) => setTextMaterial(event.target.value)} rows={3} maxLength={20000} showCount placeholder="粘贴题目文本或测试说明" />
          </Form.Item>
        </div>}
      </>
    </Form>}
    {error && <Alert className="task-modal-feedback" type={createdResult || createRequestId.current || batchRequestId.current ? 'warning' : 'error'} showIcon title={createdResult ? '任务已创建，页面更新失败' : createRequestId.current || batchRequestId.current ? '创建结果待确认' : '任务没有提交'} description={error} closable onClose={() => setError('')} />}
    {(createRequestId.current || batchRequestId.current) && !createdResult && <Button danger disabled={busy} onClick={resetDraft}>放弃未确认请求并新建</Button>}
    {progress && <Alert className="task-modal-feedback" type="info" showIcon title={progress} />}
  </Modal>
}

function RouteConfirmation({ classification, disabled = false, onBack, onNetworkPolicyChange, onBudgetChange }) {
  const steps = ['上传材料', '规则识别', '模块分发', '受控执行', '证据验证', '生成报告']
  return <div className="route-confirmation">
    <Alert type={classification.needs_human_review ? 'warning' : 'success'} showIcon title={`已识别为${moduleLabel(classification.primary_type)}`} description={classification.needs_human_review ? '识别信号存在冲突，请核对依据后再启动任务。' : '规则、扩展名与题面信号一致，可以进入对应分析模块。'} />
    <div className="route-result-hero">
      <i><BranchesOutlined /></i>
      <div><small>PRIMARY ROUTE</small><b>{moduleLabel(classification.primary_type)}</b><span>适配器：{{ reverse: 'reverse_module', penetration: 'penetration_module', log_analysis: 'log_analysis_module', code_audit: 'workspace_security_audit' }[classification.primary_type] || '人工研判'}</span></div>
      <strong>{Math.round(classification.confidence * 100)}<small>%</small></strong>
    </div>
    <div className="route-evidence">
      <header><FileSearchOutlined /> 识别依据</header>
      {(classification.evidence?.length ? classification.evidence : ['未发现强信号，使用安全默认路由']).map((item) => <span key={item}><CheckCircleOutlined />{item}</span>)}
    </div>
    {!!classification.targetUrls?.length && <Descriptions size="small" column={1} bordered>
      {classification.targetUrls.map((url, index) => <Descriptions.Item key={url} label={`靶场 ${index + 1}`}>{url}</Descriptions.Item>)}
    </Descriptions>}
    {classification.primary_type === 'penetration' && <div>
      <p>网络访问范围</p>
      <Select disabled={disabled} style={{ width: '100%' }} value={classification.networkPolicy} onChange={onNetworkPolicyChange} options={networkPolicyOptions()} />
      <small>{networkPolicyPreset(classification.networkPolicy)?.description}</small>
    </div>}
    <TaskBudgetFields budget={classification.budget} limits={classification.budgetLimits} onChange={onBudgetChange} disabled={disabled} />
    <div className="route-pipeline">{steps.map((step, index) => <React.Fragment key={step}><span className={index < 3 ? 'is-ready' : ''}><b>{index + 1}</b><small>{step}</small></span>{index < steps.length - 1 && <i>→</i>}</React.Fragment>)}</div>
    <div className="route-guard"><SafetyCertificateOutlined /><span><b>执行边界</b><small>{classification.primary_type === 'penetration' && networkPolicyPreset(classification.networkPolicy) && classification.values?.constraints?.trim() === STATIC_ONLY_CONSTRAINT ? networkPolicyPreset(classification.networkPolicy).constraint : classification.values?.constraints || '所有操作均受审批策略、工作区范围与证据规则约束。'}</small></span><Button disabled={disabled} size="small" onClick={onBack}>返回修改</Button></div>
  </div>
}

function moduleLabel(type) {
  return ({ reverse: '逆向分析', penetration: '渗透测试', log_analysis: '日志分析', unsupported: '人工研判', code_audit: '代码审计' })[type] || '待识别'
}

function routingObjective(objective, textMaterial = '') {
  const objectivePart = String(objective || '').trim().slice(0, 6000)
  const textPart = String(textMaterial || '').trim().slice(0, 4000)
  return [objectivePart, textPart].filter(Boolean).join('\n')
}

function QuestionBankInspection({ inspection, disabled = false, onChange }) {
  const stats = inspection.statistics || {}
  if (inspection.status === 'inspecting') return <div className="question-bank-inspection is-inspecting">
    <Spin size="large" />
    <h3>正在执行题库智能预检</h3>
    <p>{INSPECTION_STAGE_LABELS[inspection.stage] || '正在准备安全文件清单'}</p>
    <small>预检完成后会自动展示模型建议或进入人工目录映射。</small>
  </div>
  if (inspection.status === 'failed') return <div className="question-bank-inspection">
    <Alert
      type="error"
      showIcon
      title="题库安全预检失败"
      description={(inspection.warnings || []).join('；') || '请检查压缩包格式和安全限制后重新上传。'}
    />
  </div>
  const columns = [
    {
      title: '题目', dataIndex: 'name', key: 'name',
      render: (value, item) => <Input disabled={disabled} size="small" value={value} onChange={(event) => updateQuestion(inspection, onChange, item.candidate_id, { name: event.target.value })} />,
    },
    {
      title: '目录边界', dataIndex: 'root', key: 'root', width: 260,
      render: (value, item) => <Select
        disabled={disabled} showSearch size="small" value={value} style={{ width: '100%' }}
        options={(inspection.directory_options || []).map((root) => ({ value: root, label: root }))}
        onChange={(root) => updateQuestion(inspection, onChange, item.candidate_id, { root })}
      />,
    },
    {
      title: '识别类型', dataIndex: 'question_type', key: 'question_type', width: 160,
      render: (value, item) => <Select
        disabled={disabled}
        size="small"
        value={value}
        style={{ width: '100%' }}
        options={QUESTION_TYPE_OPTIONS}
        onChange={(questionType) => updateQuestion(inspection, onChange, item.candidate_id, {
          question_type: questionType, question_type_label: QUESTION_TYPE_LABELS[questionType], type_confidence: 1,
        })}
      />,
    },
    { title: '类型置信度', dataIndex: 'type_confidence', key: 'type_confidence', render: (value) => `${Math.round(value * 100)}%` },
    { title: '文件', dataIndex: 'file_count', key: 'file_count', render: (value) => `${value} 个` },
    {
      title: '操作', key: 'actions', width: 72,
      render: (_, item) => <Button
        type="link" danger size="small"
        disabled={disabled}
        onClick={() => onChange({
          ...inspection,
          questions: inspection.questions.filter((question) => question.candidate_id !== item.candidate_id),
        })}
      >删除</Button>,
    },
  ]
  return <div className="question-bank-inspection">
    <Alert
      type={inspection.status === 'needs_manual_mapping' || stats.ambiguous_question_count ? 'warning' : 'success'}
      showIcon
      title={inspection.status === 'needs_manual_mapping' ? '需要人工映射题目目录' : inspection.analysis_mode === 'formatted' ? `格式化文件已声明 ${stats.detected_question_count || inspection.questions.length} 道题目` : `模型建议 ${stats.detected_question_count || inspection.questions.length} 道候选题目`}
      description={inspection.analysis_mode === 'formatted' ? '已读取压缩包内的 JSON/TXT 基础信息，并根据题型生成模块分配计划；请确认目录和类型后创建任务。' : '请逐项确认题目根目录和类型。根目录必须从安全展开后的真实目录中选择，不能互相包含。'}
    />
    {inspection.formatted_metadata && <div className="formatted-metadata-summary">
      <Tag color="blue">元数据：{inspection.formatted_metadata.source_path}</Tag>
      {inspection.formatted_metadata.target && <Tag>目标：{inspection.formatted_metadata.target}</Tag>}
      {(inspection.dispatch_plan || []).map((item) => <Tag color="geekblue" key={item.module_route}>{item.module_label} {item.question_count} 题</Tag>)}
    </div>}
    <Descriptions className="question-bank-statistics" size="small" column={3} bordered>
      <Descriptions.Item label="文件总数">{stats.total_file_count}</Descriptions.Item>
      <Descriptions.Item label="内层压缩包">{stats.nested_archive_count}</Descriptions.Item>
      <Descriptions.Item label="解压后大小">{formatBytes(stats.total_uncompressed_bytes)}</Descriptions.Item>
      <Descriptions.Item label="候选题目">{stats.detected_question_count}</Descriptions.Item>
      <Descriptions.Item label="待确认类型">{stats.ambiguous_question_count}</Descriptions.Item>
      <Descriptions.Item label="边界来源">{BOUNDARY_SOURCE_LABELS[inspection.boundary_source] || inspection.boundary_source}</Descriptions.Item>
    </Descriptions>
    {!!inspection.warnings?.length && <Alert type="warning" showIcon title="预检警告" description={inspection.warnings.join('；')} />}
    <div className="question-bank-mapping-actions">
      <Button disabled={disabled} onClick={() => addManualQuestion(inspection, onChange)}>添加题目根目录</Button>
      <small>可通过添加、删除和修改根目录完成题目拆分或合并；后端会拒绝重复和包含冲突。</small>
    </div>
    <Table rowKey="candidate_id" size="small" pagination={false} scroll={{ y: 330 }} columns={columns} dataSource={inspection.questions} />
    {!!inspection.unassigned_files?.length && <Alert type="warning" showIcon title={`${inspection.unassigned_files.length} 个文件未归属`} description={inspection.unassigned_files.slice(0, 8).join('；')} />}
  </div>
}

function updateQuestion(inspection, onChange, candidateId, patch) {
  onChange({
    ...inspection,
    questions: inspection.questions.map((question) => question.candidate_id === candidateId
      ? { ...question, ...patch }
      : question),
  })
}

function addManualQuestion(inspection, onChange) {
  const used = new Set(inspection.questions.map((item) => item.root))
  const root = (inspection.directory_options || []).find((item) => !used.has(item))
  if (!root) return
  const number = inspection.questions.length + 1
  onChange({
    ...inspection,
    questions: [...inspection.questions, {
      candidate_id: `manual-${number}-${Date.now()}`,
      name: `题目 ${number}`,
      root,
      question_type: 'unknown',
      question_type_label: '未知',
      type_confidence: 0,
      boundary_confidence: 1,
      file_count: 0,
      size_bytes: 0,
    }],
  })
}

const INSPECTION_STAGE_LABELS = {
  queued: '正在排队', inventory: '正在安全展开并生成脱敏目录清单',
  boundary_analysis: '正在由大模型辅助判断题目边界与类型', complete: '预检完成',
  manual_mapping: '自动判定不可用，请人工选择目录',
}
const BOUNDARY_SOURCE_LABELS = {
  manifest: 'Manifest 明确声明', llm_assisted: '大模型辅助建议',
  manual_required: '需要人工映射', user_confirmed: '用户已确认',
  formatted_metadata: '格式化元数据声明', legacy_invalidated: '旧版结果已失效', inventory_failed: '安全展开失败',
}

const QUESTION_TYPE_LABELS = {
  web: 'Web 安全', pwn: '二进制利用', reverse: '逆向工程', crypto: '密码学',
  forensics: '取证分析', mobile: '移动安全', blockchain: '区块链安全',
  ai_security: 'AI 安全', code_audit: '代码审计', misc: '综合题', unknown: '未知',
}
const QUESTION_TYPE_OPTIONS = Object.entries(QUESTION_TYPE_LABELS).map(([value, label]) => ({ value, label }))

function formatBytes(value) {
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(1)} GB`
}
