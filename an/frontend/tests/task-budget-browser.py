"""Isolated browser checks for selected budgets and retry request identities."""
import base64
import importlib.util
import json
from pathlib import Path


FIXTURE = r"""
window.__blackboardQA.runDelay = 10;
window.__budgetQA = { retries: [], tasks: [], paths: [], failRetry: true, failCreate: true };
const budgetFetch = window.fetch;
window.fetch = async (input, options = {}) => {
  const url = new URL(typeof input === 'string' ? input : input.url, location.origin);
  window.__budgetQA.paths.push(url.pathname);
  const answer = (body) => new Response(JSON.stringify(body), {
    status: 200, headers: {'content-type': 'application/json'}
  });
  if (url.pathname === '/api/v1/task-budget-defaults') return answer({
    defaults: {max_runtime_seconds:1800, penetration_max_runtime_seconds:7200,
      max_tool_calls:800, max_model_calls:250},
    limits: {max_runtime_seconds:{min:60,max:7200}, max_tool_calls:{min:1,max:100000},
      max_model_calls:{min:1,max:10000}}
  });
  if (url.pathname.endsWith('/retry')) {
    window.__budgetQA.retries.push(JSON.parse(options.body));
    if (window.__budgetQA.failRetry) throw new Error('Simulated lost response');
    return answer({run_id:'run-b'});
  }
  if (url.pathname === '/api/v1/tasks/classify') return answer({
    primary_type:'penetration', confidence:.95, evidence:['授权登录接口测试'],
    needs_human_review:false
  });
  if (url.pathname === '/api/v1/uploads') return answer({ref:'fixture.url',name:'target-url.url'});
  if (url.pathname === '/api/v1/tasks') {
    window.__budgetQA.tasks.push({body:JSON.parse(options.body),id:options.headers['X-Request-Id']});
    if (window.__budgetQA.failCreate) throw new Error('Simulated lost response');
    return answer({run_id:'run-b'});
  }
  const response = await budgetFetch(input, options);
  if (url.pathname === '/api/v1/runs' || /^\/api\/v1\/runs\/[^/]+$/.test(url.pathname)) {
    const body = await response.json();
    for (const entry of body.runs || [body]) Object.assign(entry, {
      status:'partial', can_retry:true, stop_reason:'原工具预算耗尽',
      budget:{max_runtime_seconds:7200,runtime_seconds_used:60,max_tool_calls:12,max_model_calls:20}
    });
    return answer(body);
  }
  return response;
};
"""


def checks(command, evaluate, until):

    def click(text):
        evaluate("[...document.querySelectorAll('button')].find(n=>n.textContent.trim()===" +
                 json.dumps(text) + ").click()")

    def set_input(selector, value):
        evaluate("(() => {const n=document.querySelector(" + json.dumps(selector) +
                 "); n.focus(); n.select();})()")
        command('Input.dispatchKeyEvent', type='keyDown', key='Backspace', code='Backspace', windowsVirtualKeyCode=8)
        command('Input.dispatchKeyEvent', type='keyUp', key='Backspace', code='Backspace', windowsVirtualKeyCode=8)
        if value:
            command('Input.insertText', text=value)
        evaluate('document.activeElement.blur()')

    def budget_values():
        return evaluate("[...document.querySelectorAll('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算] input')].map(n=>n.value)")

    def set_budget(index, value):
        selector = f'.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算] > div > div:nth-child({index + 1}) input'
        set_input(selector, value)

    def ready_button(text):
        until("[...document.querySelectorAll('button')].some(n=>n.textContent.trim()===" +
              json.dumps(text) + " && !n.disabled && !n.classList.contains('ant-btn-loading'))")

    command('Emulation.setDeviceMetricsOverride', width=1440, height=1000,
            deviceScaleFactor=1, mobile=False)
    until("document.querySelector('[aria-label=重试任务]:not([disabled])') !== null")
    click('重试任务')
    until("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算]') !== null")
    assert budget_values() == ['120', '800', '250'], budget_values()
    set_budget(0, '90')
    set_budget(1, '900')
    set_budget(2, '275')
    click('开始重试')
    until('window.__budgetQA.retries.length === 1')
    ready_button('开始重试')
    click('开始重试')
    until('window.__budgetQA.retries.length === 2')
    retries = evaluate('window.__budgetQA.retries')
    assert retries[0] == retries[1], retries
    assert retries[0]['max_runtime_seconds'] == 5400
    assert retries[0]['max_tool_calls'] == 900 and retries[0]['max_model_calls'] == 275
    ready_button('开始重试')
    set_budget(1, '1000')
    evaluate('window.__budgetQA.failRetry = false')
    click('开始重试')
    until('window.__budgetQA.retries.length === 3')
    retries = evaluate('window.__budgetQA.retries')
    assert retries[2]['request_id'] != retries[1]['request_id']
    until("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算]') === null")
    until("location.search.includes('run-b') && document.querySelector('[aria-label=重试任务]')?.classList.contains('ant-btn-loading') === false")
    print('PASS: retry suggests server budgets; lost response keeps identity; changed budget gets a new identity', flush=True)

    click('新建任务')
    until("document.querySelector('textarea[placeholder*=target]') !== null")
    evaluate("(() => {const n=document.querySelector('textarea[placeholder*=target]');"
             "Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(n,'https://authorized.test/login');"
             "n.dispatchEvent(new Event('input',{bubbles:true}));})()")
    ready_button('上传并识别')
    click('上传并识别')
    try:
        until("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算]') !== null")
    except AssertionError:
        print(evaluate("[...document.querySelectorAll('.ant-modal-wrap')].map(n=>n.textContent)"), flush=True)
        print(evaluate('window.__blackboardQA.errors'), flush=True)
        print(evaluate('window.__budgetQA.paths'), flush=True)
        raise
    assert budget_values() == ['120', '800', '250'], budget_values()
    ready_button('确认路由并启动')
    set_budget(1, '')
    try:
        until("[...document.querySelectorAll('button')].find(n=>n.textContent.trim()==='确认路由并启动').disabled")
    except AssertionError:
        print(budget_values(), flush=True)
        print(evaluate("[...document.querySelectorAll('button')].filter(n=>n.textContent.includes('确认路由')).map(n=>({text:n.textContent,disabled:n.disabled}))"), flush=True)
        raise
    assert evaluate('window.__budgetQA.tasks.length') == 0
    set_budget(0, '60')
    set_budget(1, '42')
    set_budget(2, '35')
    ready_button('确认路由并启动')
    for light in [True, False]:
        evaluate(f"document.body.classList.toggle('light-theme', {str(light).lower()})")
        command('Emulation.setDeviceMetricsOverride', width=390, height=844,
                deviceScaleFactor=1, mobile=True)
        try:
            until("[...document.querySelectorAll('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算] input')].every(n=>{const r=n.getBoundingClientRect();return r.width>100 && r.left>=0 && r.right<=390})")
        except AssertionError:
            print(evaluate("[...document.querySelectorAll('.ant-modal-wrap:not([style*=\"display: none\"]) [aria-label=探索预算] input')].map(n=>n.getBoundingClientRect().toJSON())"), flush=True)
            (Path(__file__).parent / 'task-budget-mobile.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            raise
    output = Path(__file__).parent / 'task-budget-mobile.png'
    output.write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
    click('确认路由并启动')
    until('window.__budgetQA.tasks.length === 1')
    ready_button('确认路由并启动')
    evaluate('window.__budgetQA.failCreate = false')
    click('确认路由并启动')
    until('window.__budgetQA.tasks.length === 2')
    tasks = evaluate('window.__budgetQA.tasks')
    assert tasks[0] == tasks[1], tasks
    assert tasks[0]['body']['max_runtime_seconds'] == 3600
    assert tasks[0]['body']['max_tool_calls'] == 42 and tasks[0]['body']['max_model_calls'] == 35
    assert evaluate('window.__blackboardQA.errors') == []
    print('PASS: creation sends edited budgets; empty value blocks submit; both themes fit mobile; response-loss replay is stable', flush=True)
    command('Browser.close')


if __name__ == '__main__':
    spec = importlib.util.spec_from_file_location('blackboard_browser', Path(__file__).with_name('blackboard-browser.py'))
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    harness.main(FIXTURE, checks)
