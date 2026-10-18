// Browser submission against disposable services and an offline model configuration.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const http = require('node:http')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn, spawnSync } = require('node:child_process')
const { chromium } = require(process.argv[2] || 'playwright')

const suite = path.resolve(__dirname, '..')
const backend = path.join(suite, 'an')
const frontend = path.join(backend, 'frontend')
const python = path.join(backend, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      server.close(() => resolve(port))
    })
  })
}

async function waitFor(url, processHandle) {
  for (let attempt = 0; attempt < 150; attempt++) {
    assert.equal(processHandle.exitCode, null, `${url} process exited before becoming ready`)
    try {
      if ((await fetch(url)).ok) return
    } catch { /* The service may still be starting. */ }
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error(`Service did not become ready: ${url}`)
}

async function waitForRun(url, runId) {
  for (let attempt = 0; attempt < 300; attempt++) {
    const response = await fetch(`${url}/api/v1/runs/${runId}`)
    assert.equal(response.status, 200)
    const run = await response.json()
    if (['completed', 'partial', 'failed', 'denied'].includes(run.status)) return run
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error(`Run did not finish: ${runId}`)
}

async function waitForApproval(url, runId) {
  for (let attempt = 0; attempt < 150; attempt++) {
    const response = await fetch(`${url}/api/v1/runs/${runId}`)
    assert.equal(response.status, 200)
    const run = await response.json()
    if (run.status === 'waiting_approval' && run.pending_approval) return run
    assert.ok(!['completed', 'partial', 'failed', 'denied'].includes(run.status),
      `Run ended without an approval request: ${run.status}`)
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error(`Run did not request approval: ${runId}`)
}

async function waitForBatch(url, batchId) {
  for (let attempt = 0; attempt < 300; attempt++) {
    const response = await fetch(`${url}/api/v1/batches/${batchId}`)
    assert.equal(response.status, 200)
    const batch = await response.json()
    if (['completed', 'partial_failed', 'failed'].includes(batch.status)) return batch
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error(`Batch did not finish: ${batchId}`)
}

function stop(processHandle) {
  if (processHandle.exitCode !== null) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Process did not exit: ${processHandle.pid}`)), 5000)
    processHandle.once('exit', () => { clearTimeout(timer); resolve() })
    processHandle.kill()
  })
}

;(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secmind-ui-isolated-'))
  const apiPort = await freePort()
  const uiPort = await freePort()
  const apiUrl = `http://127.0.0.1:${apiPort}`
  const uiUrl = `http://127.0.0.1:${uiPort}`
  const data = path.join(root, 'data')
  const env = { ...process.env,
    SECURITY_AGENT_DATABASE_URL: `sqlite:///${path.join(data, 'tasks.db').replaceAll('\\', '/')}`,
    SECURITY_AGENT_INPUT_ROOT: path.join(data, 'inputs'),
    SECURITY_AGENT_UPLOAD_ROOT: path.join(data, 'uploads'),
    SECURITY_AGENT_RUN_ROOT: path.join(data, 'runs'),
    SECURITY_AGENT_EVALUATION_ROOT: path.join(data, 'evaluations'),
    SECURITY_AGENT_QUESTION_BANK_ROOT: path.join(data, 'question-banks'),
    SECURITY_AGENT_MCP_GENERATED_ROOT: path.join(data, 'mcp'),
    SECURITY_AGENT_MODEL_API_KEY: '',
    SECURITY_AGENT_DEMO_MODE: 'true',
    SECURITY_AGENT_ALLOWED_BROWSER_ORIGINS: uiUrl,
    SECURITY_AGENT_REVERSE_BASE_URL: 'http://127.0.0.1:1',
    SECURITY_AGENT_PENETRATION_BASE_URL: 'http://127.0.0.1:1',
    SECURITY_AGENT_QDRANT_URL: 'http://127.0.0.1:1',
  }
  const processes = []
  let browser
  let modelProvider
  const providerCalls = []
  try {
    modelProvider = http.createServer((request, response) => {
      providerCalls.push({ method: request.method, path: request.url, authorization: request.headers.authorization })
      response.setHeader('Content-Type', 'application/json')
      if (request.headers.authorization !== 'Bearer isolated-test-key') {
        response.writeHead(401).end(JSON.stringify({ error: 'invalid test key' }))
      } else if (request.method === 'GET' && request.url === '/v1/models') {
        response.writeHead(200).end(JSON.stringify({ data: [{ id: 'isolated-model' }] }))
      } else if (request.method === 'POST' && request.url === '/v1/chat/completions') {
        response.writeHead(200).end(JSON.stringify({ choices: [{ message: { content: 'OK' } }],
          usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 } }))
      } else {
        response.writeHead(404).end(JSON.stringify({ error: 'unknown endpoint' }))
      }
    })
    await new Promise(resolve => modelProvider.listen(0, '127.0.0.1', resolve))
    const providerUrl = `http://127.0.0.1:${modelProvider.address().port}/v1`
    const api = spawn(python, ['-m', 'uvicorn', 'security_agent.api:create_app', '--factory',
      '--host', '127.0.0.1', '--port', String(apiPort)],
    { cwd: backend, env, windowsHide: true, stdio: 'ignore' })
    processes.push(api)
    await waitFor(`${apiUrl}/health`, api)
    assert.equal((await (await fetch(`${apiUrl}/health`)).json()).demo_mode, true)

    const vite = spawn(process.execPath, [path.join(frontend, 'node_modules/vite/bin/vite.js'),
      '--host', '127.0.0.1', '--port', String(uiPort)],
    { cwd: frontend, env: { ...process.env, VITE_DEV_BACKEND_TARGET: apiUrl }, windowsHide: true, stdio: 'ignore' })
    processes.push(vite)
    await waitFor(`${uiUrl}/health`, vite)

    const sample = path.join(root, 'sample.py')
    fs.writeFileSync(sample, "import subprocess\nsubprocess.run('echo test', shell=True)\n")
    browser = await chromium.launch({ channel: 'msedge', headless: true })
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    const attackerUrl = `http://127.0.0.1:${await freePort()}/attacker`
    await page.route(attackerUrl, route => route.fulfill({ status: 200, contentType: 'text/html', body: '<title>Outside page</title>' }))
    await page.goto(attackerUrl)
    const crossSite = await page.evaluate(async ({ apiUrl, apiPort }) => {
      const socketOpened = await new Promise(resolve => {
        const socket = new WebSocket(`ws://127.0.0.1:${apiPort}/api/v1/incident/events`)
        socket.onopen = () => { socket.close(); resolve(true) }
        socket.onerror = () => resolve(false)
        socket.onclose = () => resolve(false)
      })
      const form = new FormData()
      form.append('file', new Blob(['outside page']), 'cross-site.txt')
      await fetch(`${apiUrl}/api/v1/uploads`, { method: 'POST', mode: 'no-cors', body: form })
      return { socketOpened }
    }, { apiUrl, apiPort })
    assert.equal(crossSite.socketOpened, false)
    assert.deepEqual(fs.readdirSync(path.join(data, 'uploads')), [])
    await page.goto(`${uiUrl}/workbench`)
    await page.getByText('新建任务', { exact: true }).first().click()
    await page.locator('.ant-modal input[type="file"]').setInputFiles(sample)
    await page.locator('.ant-modal-footer').getByRole('button', { name: '上传并识别' }).click()
    await page.getByText('已识别为代码审计', { exact: false }).waitFor({ state: 'visible' })
    const [created] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/tasks') && response.request().method() === 'POST'),
      page.locator('.ant-modal-footer').getByRole('button', { name: '确认路由并启动' }).click(),
    ])
    assert.equal(created.status(), 202)
    const { run_id: runId } = await created.json()
    assert.ok(runId)
    const run = await waitForRun(apiUrl, runId)
    assert.equal(run.status, 'completed', JSON.stringify({ status: run.status, error: run.last_error }))
    assert.equal(run.module_route, 'code_audit')
    const reportResponse = await fetch(`${apiUrl}/api/v1/runs/${runId}/report`)
    assert.equal(reportResponse.status, 200)
    const report = await reportResponse.json()
    assert.ok(report.evidence.length > 0)
    await page.waitForURL(url => url.searchParams.get('run') === runId)

    await page.goto(`${uiUrl}/incident-response`)
    await page.getByText('采集已停止', { exact: true }).waitFor({ state: 'visible' })
    await page.getByRole('combobox', { name: '处置命令' }).click()
    await page.getByText('隔离上传的文件（需审批）', { exact: true }).click()
    const [sampleUploaded] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/incident/samples') && response.request().method() === 'POST'),
      page.locator('.incident-page input[type="file"]').setInputFiles(sample),
    ])
    assert.equal(sampleUploaded.status(), 200)
    const { path: uploadedSample } = await sampleUploaded.json()
    await page.getByRole('textbox', { name: '操作目标' }).waitFor({ state: 'visible' })
    await page.waitForFunction(() => Boolean(document.querySelector('input[aria-label="操作目标"]')?.value))
    const [approvalSubmitted] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/incident/command') && response.request().method() === 'POST'),
      page.getByRole('button', { name: '提交审批' }).click(),
    ])
    assert.equal(approvalSubmitted.status(), 200)
    assert.equal((await approvalSubmitted.json()).action.status, 'awaiting_approval')
    await page.getByRole('button', { name: /拒\s*绝/ }).click()
    await page.getByText('没有待审批动作', { exact: true }).waitFor({ state: 'visible' })
    assert.equal(fs.readFileSync(uploadedSample, 'utf8'), fs.readFileSync(sample, 'utf8'))
    assert.equal((await (await fetch(`${apiUrl}/api/v1/incident/pending-approvals`)).json()).approvals.length, 0)

    const [isolationSubmitted] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/incident/command') && response.request().method() === 'POST'),
      page.getByRole('button', { name: '提交审批' }).click(),
    ])
    assert.equal((await isolationSubmitted.json()).action.status, 'awaiting_approval')
    const [isolationApproved] = await Promise.all([
      page.waitForResponse(response => response.url().includes('/api/v1/incident/approvals/') && response.request().method() === 'POST'),
      page.getByRole('button', { name: /批准并执行/ }).click(),
    ])
    assert.equal(isolationApproved.status(), 200)
    const isolated = (await isolationApproved.json()).action
    assert.equal(isolated.status, 'completed', isolated.error)
    assert.equal(fs.existsSync(uploadedSample), false)
    const quarantineId = isolated.result.id
    assert.deepEqual(fs.readFileSync(path.join(data, 'incident', 'quarantine', quarantineId, 'sample.bin')),
      fs.readFileSync(sample))

    await page.getByRole('combobox', { name: '处置命令' }).click()
    await page.getByText('恢复已隔离文件（需审批）', { exact: true }).click()
    await page.getByRole('combobox', { name: '隔离记录' }).click()
    await page.locator('.ant-select-item-option').filter({ hasText: quarantineId }).click()
    const [restoreSubmitted] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/incident/command') && response.request().method() === 'POST'),
      page.getByRole('button', { name: '提交审批' }).click(),
    ])
    assert.equal((await restoreSubmitted.json()).action.status, 'awaiting_approval')
    const [restoreApproved] = await Promise.all([
      page.waitForResponse(response => response.url().includes('/api/v1/incident/approvals/') && response.request().method() === 'POST'),
      page.getByRole('button', { name: /批准并执行/ }).click(),
    ])
    assert.equal(restoreApproved.status(), 200)
    assert.equal((await restoreApproved.json()).action.status, 'completed')
    assert.deepEqual(fs.readFileSync(uploadedSample), fs.readFileSync(sample))

    const material = new FormData()
    material.append('file', new Blob([fs.readFileSync(sample)]), 'retry-sample.py')
    const uploadResponse = await fetch(`${apiUrl}/api/v1/uploads`, { method: 'POST', body: material })
    assert.equal(uploadResponse.status, 201)
    const { ref } = await uploadResponse.json()
    const failedSubmission = await fetch(`${apiUrl}/api/v1/tasks`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ objective: '审计上传的 Python 源码并生成安全报告', analysis_backend: 'secmind',
        attachments: [{ ref }], target_scope: ['uploaded-source'], constraints: ['仅允许只读静态分析'] }) })
    assert.equal(failedSubmission.status, 202)
    const failedRunId = (await failedSubmission.json()).run_id
    const failedRun = await waitForRun(apiUrl, failedRunId)
    assert.equal(failedRun.status, 'partial')
    assert.equal(failedRun.can_retry, true)
    await page.goto(`${uiUrl}/workbench?run=${failedRunId}`)
    await page.getByRole('button', { name: '重试任务' }).click()
    const [retryResponse] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith(`/api/v1/runs/${failedRunId}/retry`) && response.request().method() === 'POST'),
      page.getByRole('button', { name: '开始重试' }).click(),
    ])
    assert.equal(retryResponse.status(), 202)
    const retriedRunId = (await retryResponse.json()).run_id
    assert.notEqual(retriedRunId, failedRunId)
    assert.equal((await waitForRun(apiUrl, retriedRunId)).retry_of, failedRunId)

    const approvalPayload = { objective: '审计上传的 Python 源码并生成安全报告',
      attachments: [{ ref }], target_scope: ['uploaded-source'],
      constraints: ['仅允许只读静态分析'], autonomy_policy: 'approval_all' }
    for (const [decision, expectedStatus] of [['deny', 'denied'], ['approve', 'completed']]) {
      const submitted = await fetch(`${apiUrl}/api/v1/tasks`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(approvalPayload) })
      assert.equal(submitted.status, 202)
      const approvalRunId = (await submitted.json()).run_id
      const waiting = await waitForApproval(apiUrl, approvalRunId)
      await page.goto(`${uiUrl}/workbench?run=${approvalRunId}`)
      await page.locator('.approval-alert').getByText(`步骤 ${waiting.pending_approval.step_id} 等待审批`).waitFor({ state: 'visible' })
      const [resolved] = await Promise.all([
        page.waitForResponse(response => response.url().endsWith(`/api/v1/runs/${approvalRunId}/approvals/${waiting.pending_approval.request_id}`)
          && response.request().method() === 'POST'),
        page.locator('.approval-alert').getByRole('button', { name: decision === 'deny' ? /拒\s*绝/ : /批\s*准/ }).click(),
      ])
      assert.equal(resolved.status(), 202)
      const finished = await waitForRun(apiUrl, approvalRunId)
      assert.equal(finished.status, expectedStatus, JSON.stringify({ status: finished.status, error: finished.last_error }))
      const approvalLedger = await (await fetch(`${apiUrl}/api/v1/runs/${approvalRunId}/ledger`)).json()
      assert.ok(approvalLedger.events.some(event => event.event_type === 'approval.resolved'))
      if (decision === 'deny') assert.equal(approvalLedger.events.some(event => event.event_type === 'tool.completed'), false)
    }

    const bankZip = path.join(root, 'bank.zip')
    const packed = spawnSync(python, ['-c',
      "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.writestr('metadata.json','{\"questions\":[{\"id\":\"q1\",\"name\":\"Code audit\",\"type\":\"code_audit\",\"root\":\"questions/q1\"}]}'); z.writestr('questions/q1/app.py','import subprocess\\nsubprocess.run(\\\"echo test\\\", shell=True)\\n'); z.close()",
      bankZip], { cwd: root, env, windowsHide: true })
    assert.equal(packed.status, 0, packed.stderr?.toString())
    await page.goto(`${uiUrl}/workbench`)
    await page.getByText('新建任务', { exact: true }).first().click()
    await page.getByText('题库格式化文件分析', { exact: true }).first().click()
    await page.locator('.ant-modal input[type="file"]').setInputFiles(bankZip)
    await page.locator('.ant-modal-footer').getByRole('button', { name: '读取格式并分配' }).click()
    await page.getByText(/格式化文件已声明 1 道题目/).waitFor({ state: 'visible' })
    const [batchResponse] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/batches') && response.request().method() === 'POST'),
      page.locator('.ant-modal-footer').getByRole('button', { name: '确认映射并创建任务' }).click(),
    ])
    assert.equal(batchResponse.status(), 202)
    const { batch_id: batchId } = await batchResponse.json()
    assert.ok(batchId)
    const batch = await waitForBatch(apiUrl, batchId)
    assert.equal(batch.status, 'completed', JSON.stringify(batch.summary))
    assert.equal(batch.tasks.length, 1)
    assert.equal(batch.tasks[0].status, 'succeeded')

    await page.goto(`${uiUrl}/prompts`)
    await page.locator('.prompt-card-action').filter({ hasText: '最终报告' }).click()
    const promptEditor = page.getByRole('textbox', { name: '运行 Prompt 内容' })
    const originalPrompt = await promptEditor.inputValue()
    const editedPrompt = `${originalPrompt}\n隔离浏览器验证：保留证据引用。`
    await promptEditor.fill(editedPrompt)
    const [promptSaved] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/prompts/report') && response.request().method() === 'PUT'),
      page.getByRole('button', { name: '保存并用于后续调用' }).click(),
    ])
    assert.equal(promptSaved.status(), 200)
    assert.equal((await promptSaved.json()).content, editedPrompt)
    await page.reload()
    await page.locator('.prompt-card-action').filter({ hasText: '最终报告' }).click()
    assert.equal(await page.getByRole('textbox', { name: '运行 Prompt 内容' }).inputValue(), editedPrompt)
    assert.equal((await (await fetch(`${apiUrl}/api/v1/prompts/report/history`)).json()).history.length, 1)

    await page.goto(`${uiUrl}/mcp`)
    await page.getByRole('button', { name: '新增 Server' }).click()
    const serverEditor = page.getByRole('dialog', { name: 'MCP 连接配置' })
    await serverEditor.getByRole('textbox', { name: 'Server ID' }).fill('isolated-check')
    await serverEditor.getByRole('textbox', { name: '名称' }).fill('隔离验证连接')
    await serverEditor.getByRole('textbox', { name: '用途' }).fill('验证本地连接配置')
    const [serverCreated] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/mcp/servers') && response.request().method() === 'POST'),
      serverEditor.getByRole('button', { name: /保\s*存/ }).click(),
    ])
    assert.equal(serverCreated.status(), 201)
    const serverSection = page.locator('section.glass-panel').filter({ has: page.getByRole('heading', { name: '隔离验证连接' }) })
    await serverSection.getByRole('button', { name: /删\s*除/ }).click()
    const [serverDeleted] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/mcp/servers/isolated-check') && response.request().method() === 'DELETE'),
      page.locator('.ant-popconfirm button.ant-btn-primary').click(),
    ])
    assert.equal(serverDeleted.status(), 204)
    assert.equal((await (await fetch(`${apiUrl}/api/v1/mcp/catalog`)).json()).servers.some(server => server.server_id === 'isolated-check'), false)

    await page.goto(`${uiUrl}/models`)
    await page.getByText('连接与模型配置', { exact: true }).first().click()
    await page.getByRole('textbox', { name: 'Base URL' }).fill(providerUrl)
    await page.getByRole('textbox', { name: 'API Key' }).fill('isolated-test-key')
    const [modelList] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/model-config/models') && response.request().method() === 'POST'),
      page.getByRole('button', { name: '自动获取模型列表' }).click(),
    ])
    assert.equal(modelList.status(), 200)
    assert.deepEqual((await modelList.json()).models, ['isolated-model'])
    const [modelTest] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/model-config/test') && response.request().method() === 'POST'),
      page.getByRole('button', { name: '测试连接' }).click(),
    ])
    assert.equal(modelTest.status(), 200)
    const modelTestResult = await modelTest.json()
    assert.equal(modelTestResult.model_count, new Set(modelTestResult.model_ids).size)
    assert.ok(modelTestResult.model_count >= 1)
    assert.equal(providerCalls.filter(call => call.path === '/v1/models').length, 1)
    assert.equal(providerCalls.filter(call => call.path === '/v1/chat/completions').length, modelTestResult.model_count)
    const [modelSaved] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/model-config') && response.request().method() === 'PUT'),
      page.getByRole('button', { name: '应用配置' }).click(),
    ])
    assert.equal(modelSaved.status(), 200)
    assert.equal((await modelSaved.json()).api_key_configured, true)
    assert.equal((await (await fetch(`${apiUrl}/api/v1/model-config`)).json()).demo_mode, false)
    await page.getByRole('button', { name: '清除密钥' }).click()
    const [keyCleared] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/model-config') && response.request().method() === 'PUT'),
      page.getByRole('button', { name: /清\s*除/ }).last().click(),
    ])
    assert.equal(keyCleared.status(), 200)
    assert.equal((await keyCleared.json()).demo_mode, true)
    assert.ok((await (await fetch(`${apiUrl}/api/v1/model-usage`)).json()).total_tokens >= 12 * modelTestResult.model_count)

    await page.goto(`${uiUrl}/audit/${runId}`)
    await page.getByText('账本链校验通过', { exact: true }).waitFor({ state: 'visible' })
    await page.getByRole('button', { name: /单\s*步/ }).click()
    await page.getByText(/1 \/ \d+ 个事件/).waitFor({ state: 'visible' })
    const ledgerExport = await fetch(`${apiUrl}/api/v1/runs/${runId}/ledger/export`)
    assert.equal(ledgerExport.status, 200)
    assert.match(await ledgerExport.text(), /"event_type"/)
    const thoughtExport = await fetch(`${apiUrl}/api/v1/runs/${runId}/thoughts/export`)
    assert.equal(thoughtExport.status, 200)
    assert.ok((await thoughtExport.text()).length > 100)

    await page.goto(`${uiUrl}/experiences`)
    await page.getByRole('button', { name: '新增人工经验' }).click()
    const experienceEditor = page.getByRole('dialog', { name: '新增人工经验' })
    await experienceEditor.getByRole('textbox', { name: '标题' }).fill('Python 命令注入审计经验')
    await experienceEditor.getByRole('textbox', { name: '概要' }).fill('检查 Python subprocess 调用中 shell=True 与外部输入组合。')
    await experienceEditor.getByRole('textbox', { name: '适用条件（每行一条）' }).fill('Python 源码审计')
    await experienceEditor.getByRole('textbox', { name: '可复用经验（每行一条）' }).fill('检查 subprocess.run 的参数来源与 shell 参数')
    const [experienceCreated] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/v1/experiences') && response.request().method() === 'POST'),
      experienceEditor.getByRole('button', { name: '保存待审核版本' }).click(),
    ])
    assert.equal(experienceCreated.status(), 201)
    const experienceId = (await experienceCreated.json()).experience.experience_id
    await page.getByRole('dialog', { name: '经验详情与使用证据' }).getByText('待审核', { exact: true }).waitFor({ state: 'visible' })
    const [experienceApproved] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith(`/api/v1/experiences/${experienceId}/review`) && response.request().method() === 'POST'),
      page.getByRole('button', { name: '审核并启用' }).click(),
    ])
    assert.equal(experienceApproved.status(), 200)
    await page.getByRole('dialog', { name: '经验详情与使用证据' }).getByText('已审核启用', { exact: true }).waitFor({ state: 'visible' })
    await page.getByRole('dialog', { name: '经验详情与使用证据' }).getByRole('button', { name: 'Close' }).click()
    await page.getByRole('textbox', { name: '检索任务目标' }).fill('审计 Python subprocess 命令注入')
    const [experienceSearch] = await Promise.all([
      page.waitForResponse(response => response.url().includes('/api/v1/experiences/search') && response.request().method() === 'GET'),
      page.getByRole('button', { name: '预览检索' }).click(),
    ])
    assert.equal(experienceSearch.status(), 200)
    assert.ok((await experienceSearch.json()).experiences.some(item => item.experience_id === experienceId))
    const experienceRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Python 命令注入审计经验' }) })
    await experienceRow.getByRole('button', { name: /删\s*除/ }).click()
    const [experienceDeleted] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith(`/api/v1/experiences/${experienceId}`) && response.request().method() === 'DELETE'),
      page.locator('.ant-popconfirm button.ant-btn-primary').click(),
    ])
    assert.equal(experienceDeleted.status(), 204)
    assert.equal((await fetch(`${apiUrl}/api/v1/experiences/${experienceId}`)).status, 404)
    assert.deepEqual(errors, [])
    console.log(JSON.stringify({ passed: true, run_id: runId, status: run.status,
      evidence: report.evidence.length, incident_approval: 'denied_then_restored', retry_of: failedRunId,
      batch_id: batchId, cross_site_browser: 'blocked', prompt_edit: 'persisted',
      mcp_server: 'created_then_deleted', model_key: 'tested_saved_then_cleared',
      audit_export: 'verified', experience: 'reviewed_searched_deleted',
      task_approval: 'denied_then_approved', data_directory: root }))
  } finally {
    await browser?.close()
    for (const processHandle of processes.reverse()) await stop(processHandle)
    if (modelProvider) await new Promise(resolve => modelProvider.close(resolve))
  }
})().catch(error => { console.error(error); process.exitCode = 1 })
