import React, { useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { createMcpServer, deleteMcpServer, getMcpCatalog, updateMcpServer, discoverMcp, invokeMcp } from '../api.js'
import { useNavigate } from 'react-router-dom'
const { Title, Text } = Typography
const defaults = { name: '', server_id: '', purpose: '', transport: 'stdio', command: '', args_text: '[]', url: '', enabled: false, icon: 'tool', category: 'local' }
export function McpRegistryPage() {
  const navigate = useNavigate()
  const { message } = App.useApp()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [editor, setEditor] = useState(null)
  const [call, setCall] = useState(null)
  const [argumentsText, setArgumentsText] = useState('{}')
  const [receipt, setReceipt] = useState(null)
  const callRequest = useRef(null)
  const executeInFlight = useRef(false)
  const operationInFlight = useRef(false)
  const loadSequence = useRef(0)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()
  const transport = Form.useWatch('transport', form)
  const manualPure = call && ({
    'secmind-local': ['decode_base64'],
    'local-burp': ['base64_encode', 'base64_decode', 'url_encode', 'url_decode'],
    'local-tscanplus': ['jwt_decode'],
  }[call.server.server_id] || []).includes(call.tool.name)
  const load = async () => {
    const sequence = ++loadSequence.current
    try {
      const next = await getMcpCatalog()
      if (sequence !== loadSequence.current) return true
      setData(next)
      setError('')
      return true
    } catch (e) {
      if (sequence !== loadSequence.current) return false
      setError(e.message)
      setData(null)
      return false
    }
  }
  useEffect(() => { load(); return () => { loadSequence.current += 1 } }, [])
  const edit = (server) => { form.setFieldsValue(server ? { ...defaults, ...server, args_text: JSON.stringify(server.args || []) } : defaults); setEditor({ server }) }
  const discover = async (server) => {
    if (operationInFlight.current || busy) return
    operationInFlight.current = true
    setBusy(true)
    try {
      const result = await discoverMcp(server.server_id)
      result.status === 'connected'
        ? message.success(`实际发现 ${Array.isArray(result.tools) ? result.tools.length : 0} 个工具`)
        : message.error(result.error || '连接失败')
      if (!await load()) message.warning('握手回执已返回，但连接列表暂未刷新')
    } catch (e) { message.error(e.message) }
    finally { operationInFlight.current = false; setBusy(false) }
  }
  const save = async () => {
    if (operationInFlight.current || busy) return
    operationInFlight.current = true
    setSaving(true)
    setBusy(true)
    try {
      const values = await form.validateFields()
      const args = JSON.parse(values.args_text || '[]')
      if (!Array.isArray(args) || args.some(x => typeof x !== 'string')) throw new Error('参数必须是字符串数组')
      const { args_text, ...rest } = values
      const payload = { ...rest, args }
      editor.server ? await updateMcpServer(editor.server.server_id, payload) : await createMcpServer(payload)
      setEditor(null)
      if (await load()) message.success('连接配置已保存，点击连接并发现工具进行验证')
      else message.warning('连接配置已保存，但连接列表暂未刷新')
    } catch (e) { if (!e.errorFields) message.error(e.message) }
    finally { operationInFlight.current = false; setSaving(false); setBusy(false) }
  }
  const remove = async (server) => {
    if (operationInFlight.current || busy) return
    operationInFlight.current = true
    setBusy(true)
    try {
      await deleteMcpServer(server.server_id)
      if (await load()) message.success('连接配置已删除')
      else message.warning('连接配置已删除，但列表暂未刷新')
    }
    catch (e) { message.error(e.message) }
    finally { operationInFlight.current = false; setBusy(false) }
  }
  const execute = async () => {
    if (operationInFlight.current || executeInFlight.current || !call) return
    let args
    try {
      args = JSON.parse(argumentsText)
      if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error('输入必须是 JSON 对象')
    } catch (e) { message.error(`参数无效：${e.message}`); return }
    executeInFlight.current = true
    operationInFlight.current = true
    setBusy(true)
    try {
      const signature = JSON.stringify([call.server.server_id, call.tool.name, args])
      if (callRequest.current?.signature !== signature) callRequest.current = { signature, id: crypto.randomUUID() }
      const result = await invokeMcp(call.server.server_id, { tool: call.tool.name, arguments: args, approved: true, request_id: callRequest.current.id })
      if (result.status !== 'running') callRequest.current = null
      setReceipt(result)
      if (result.status === 'completed') message.success('工具已实际执行，回执已保存')
      else if (result.status === 'running') message.info('工具仍在执行；再次点击查询本次调用会沿用请求 ID')
      else message.error(result.error || '工具返回执行失败，请查看回执')
      if (!await load()) message.warning('调用回执已返回，列表暂未刷新')
    } catch (e) { message.error(`调用结果未确认：${e.message}；重试将沿用本次请求 ID`) } finally { operationInFlight.current = false; executeInFlight.current = false; setBusy(false) }
  }
  return <div className="catalog-page"><section className="page-intro"><div><Text className="panel-kicker">MCP RUNTIME</Text><Title level={2}>MCP 连接与工具执行</Title><p>通过协议握手发现工具。任务内调用和审批记录请在任务工作台查看。</p></div><Space><Button disabled={busy} onClick={() => edit(null)}>新增 Server</Button><Button disabled={busy} onClick={load}>刷新</Button></Space></section>
    {error && <Alert type="error" message={error} />}
    <Alert type="info" message={data?.tool_registration === 'task_agent' ? '已启用的 MCP 工具已接入任务 Agent：任务规划时自动发现并选择相关工具，按任务审批策略执行，结果进入任务证据与报告。此处也可手动调用。Burp 和 Reqable 需要桌面程序运行。' : '任务 Agent 接入状态尚未确认。握手和实际执行结果请查看连接状态与调用回执。'} />
    {(data?.servers || []).map(server => <section className="glass-panel" key={server.server_id} style={{ padding: 20, marginTop: 16 }}>
      <Space wrap><Title level={4} style={{ margin: 0 }}>{server.name}</Title><Tag>{server.transport}</Tag><Tag color={server.connection?.status === 'connected' ? 'green' : server.connection?.status === 'untrusted' ? 'red' : 'default'}>{server.connection?.status === 'connected' ? '最近握手成功' : server.connection?.status === 'untrusted' ? '签名不可信' : server.connection?.status === 'unavailable' ? '连接失败' : '尚未验证'}</Tag></Space>
      <p>{server.purpose}</p><Space wrap><Button loading={busy} disabled={busy || !server.enabled} onClick={() => discover(server)}>连接并发现工具</Button>{!server.builtin && <><Button disabled={busy} onClick={() => edit(server)}>配置连接</Button><Popconfirm title="删除此连接配置？" okButtonProps={{ disabled: busy }} onConfirm={() => remove(server)}><Button danger disabled={busy}>删除</Button></Popconfirm></>}</Space>
      {!server.enabled && <p>尚未启用；请先配置实际连接。</p>}
      {server.connection?.error && <Alert style={{ marginTop: 12 }} type="error" message={server.connection.error} />}
      {server.connection?.checked_at && <p>验证时间：{new Date(server.connection.checked_at).toLocaleString()}</p>}
      {(data?.receipts || []).filter(row => row.server_id === server.server_id).slice(0, 1).map(row => <p key={row.call_id}>
        最近调用：<Tag color={row.status === 'completed' ? 'green' : row.status === 'failed' ? 'red' : 'default'}>{row.status === 'completed' ? '执行成功' : row.status === 'failed' ? '执行失败' : row.status}</Tag>
        {row.tool} · {new Date(row.started_at).toLocaleString()} <Button size="small" onClick={() => { setCall(null); setReceipt(row) }}>查看回执</Button>
      </p>)}
      <Table size="small" rowKey="name" scroll={{ x: 680 }} pagination={{ defaultPageSize: 10, hideOnSinglePage: true, showTotal: total => `共 ${total} 个工具` }} dataSource={server.connection?.tools || []} columns={[
        { title: '实际工具', dataIndex: 'name' }, { title: '说明', dataIndex: 'description' },
        { title: '操作', render: (_, tool) => <Button disabled={busy || !server.enabled} onClick={() => { callRequest.current = null; setCall({ server, tool }); setArgumentsText('{}'); setReceipt(null) }}>输入参数并调用</Button> },
      ]} />
    </section>)}
    <section className="glass-panel" style={{ padding: 20, marginTop: 20 }}><Title level={4}>最近调用回执</Title><Table rowKey="call_id" scroll={{ x: 680 }} dataSource={data?.receipts || []} pagination={{ pageSize: 6 }} columns={[
      { title: '时间', dataIndex: 'started_at', render: t => new Date(t).toLocaleString() }, { title: 'Server', dataIndex: 'server_id' }, { title: '工具', dataIndex: 'tool' }, { title: '状态', dataIndex: 'status' },
      { title: '结果', render: (_, row) => <Button onClick={() => { setCall(null); setReceipt(row) }}>查看回执</Button> },
    ]} /></section>
    <Modal open={!!editor} title="MCP 连接配置" onCancel={() => !busy && setEditor(null)} onOk={save} confirmLoading={saving} cancelButtonProps={{ disabled: busy }} okButtonProps={{ disabled: busy }} width={760} okText="保存"><Form form={form} layout="vertical" disabled={busy}>
      <Form.Item name="server_id" label="Server ID" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9_-]*$/ }]}><Input disabled={!!editor?.server} /></Form.Item>
      <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="purpose" label="用途" rules={[{ required: true }]}><Input /></Form.Item>
      <Form.Item name="transport" label="协议"><Select options={['stdio', 'streamable_http', 'sse'].map(value => ({ value, label: value }))} /></Form.Item>
      <Form.Item name="enabled" label="允许实际连接" valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="command" label="可执行程序（stdio）" hidden={transport !== 'stdio'}><Input placeholder="例如 C:\Python\python.exe；不填写 shell 命令串" /></Form.Item>
      <Form.Item name="args_text" label="参数数组（stdio）" hidden={transport !== 'stdio'}><Input.TextArea rows={3} placeholder='["-m", "your_mcp_server"]' /></Form.Item>
      <Form.Item name="url" label="MCP URL" hidden={transport === 'stdio'}><Input placeholder="http://127.0.0.1:9000/mcp" /></Form.Item>
    </Form></Modal>
    <Modal open={!!call} title={`调用 ${call?.tool?.name || ''}`} onCancel={() => !busy && setCall(null)} closable={!busy} keyboard={!busy} maskClosable={!busy} footer={null} width={860}>
      <p>{call?.tool?.description}</p><details><summary>输入参数 Schema</summary><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(call?.tool?.inputSchema, null, 2)}</pre></details>
      <Input.TextArea disabled={busy} aria-label="工具参数 JSON" rows={7} value={argumentsText} onChange={e => { callRequest.current = null; setReceipt(null); setArgumentsText(e.target.value) }} />
      {manualPure ? <Popconfirm title={receipt?.status === 'running' ? '查询本次调用的最新回执？' : '确认使用上述参数实际调用此工具？'} onConfirm={execute}><Button type="primary" loading={busy} disabled={busy}>{receipt?.status === 'running' ? '查询本次调用' : '执行工具'}</Button></Popconfirm>
        : <Button type="primary" onClick={() => navigate('/workbench')}>在任务中审批调用</Button>}
      {receipt && <pre style={{ whiteSpace: 'pre-wrap', maxHeight: 350, overflow: 'auto' }}>{JSON.stringify(receipt, null, 2)}</pre>}
    </Modal>
    <Modal open={!!receipt && !call} title="MCP 执行回执" footer={null} onCancel={() => setReceipt(null)} width={860}><pre style={{ whiteSpace: 'pre-wrap', maxHeight: '70vh', overflow: 'auto' }}>{JSON.stringify(receipt, null, 2)}</pre></Modal>
  </div>
}
