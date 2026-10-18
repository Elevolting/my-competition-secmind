// Read-only UI smoke test. Pass a Playwright module path if it is not installed locally.
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const assert = require('node:assert/strict')
const { chromium } = require(process.argv[2] || 'playwright')

;(async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'secmind-ui-'))
  const browser = await chromium.launch({ channel: 'msedge', headless: true })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.goto('http://127.0.0.1:5173/workbench')
    await page.getByText('新建任务', { exact: true }).first().click()
    const engine = page.locator('#analysisBackend')
    await engine.waitFor({ state: 'visible' })
    await engine.click()
    await page.getByText('本地静态规则扫描', { exact: true }).last().click()
    assert.match(await page.locator('.ant-modal').innerText(), /本地静态规则扫描/)
    await engine.press('Escape')
    await page.waitForTimeout(250)
    const footer = await page.locator('.ant-modal-footer').boundingBox()
    assert.ok(footer && footer.y + footer.height <= 1000, 'task submission controls must stay in the viewport')
    await page.screenshot({ path: path.join(out, 'task-modal.png'), fullPage: true })
    await page.locator('.ant-modal-footer button').first().click()
    await page.goto('http://127.0.0.1:5173/models')
    await page.getByText('连接与模型配置', { exact: true }).click()
    await page.getByText('统一管理规划模型和 Pi Worker', { exact: true }).waitFor({ state: 'visible' })
    assert.match(await page.locator('.model-config-card .ant-alert').first().innerText(), /SecMind 分析引擎仍单独配置/)
    await page.screenshot({ path: path.join(out, 'model-scope.png'), fullPage: true })
    for (const route of ['cockpit', 'audit', 'experiences', 'incident-response', 'prompts', 'mcp']) {
      await page.goto(`http://127.0.0.1:5173/${route}`)
      await page.locator('.route-loading').waitFor({ state: 'hidden' })
      assert.ok(await page.locator('.feature-content').innerText(), `${route} rendered empty content`)
    }
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('http://127.0.0.1:5173/workbench')
    await page.getByRole('button', { name: '切换导航' }).click()
    await page.getByText('模型与用量', { exact: true }).first().click()
    assert.match(page.url(), /\/models$/)
    await page.locator('.feature-shell.is-mobile-open').waitFor({ state: 'hidden' })
    await page.locator('.route-loading').waitFor({ state: 'hidden' })
    await page.getByText('用量信息', { exact: true }).waitFor({ state: 'visible' })
    await page.locator('.usage-card .ant-table').waitFor({ state: 'visible' })
    assert.equal(await page.locator('.usage-card .ant-table-content').evaluate((table) => table.scrollWidth > table.clientWidth), true,
      'mobile usage table should scroll within its panel')
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false,
      'mobile page must not overflow horizontally')
    await page.screenshot({ path: path.join(out, 'mobile-models.png'), fullPage: true })
    assert.deepEqual(errors, [])
    console.log(JSON.stringify({ passed: true, checks: ['engine selector', 'model scope', 'main routes', 'mobile navigation', 'no uncaught page errors'],
      screenshots: out, submittedTasks: 0 }))
  } finally {
    await browser.close()
  }
})().catch((error) => { console.error(error); process.exitCode = 1 })
