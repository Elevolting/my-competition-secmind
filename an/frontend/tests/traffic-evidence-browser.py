"""Exercise the finding panel with isolated HTTP fixtures in installed Chrome."""
import base64
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("blackboard-browser.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

fixture = r'''
window.__trafficQA = { created: [], bound: [] };
const trafficNativeFetch = window.fetch.bind(window);
const trafficFinding = { finding_id:'finding-1', rule_id:'TEST', title:'响应头候选', description:'需核对请求与响应',
  path:'/app', severity:'LOW', evidence_ids:[], raw:{} };
const trafficRun = { run_id:'run-a', name:'流量证据测试', status:'completed', module_route:'penetration',
  scenario:'penetration_test', external_execution:{blackboard:{planning_mode:'workbench'}}, budget:{} };
const trafficEvidence = { evidence_id:'evidence-1', sha256:'a'.repeat(64), snapshot:{
  source:{kind:'ledger', reference:'http-event-1'}, captured_at:'2026-10-15T00:00:00Z', method:'GET',
  url:'https://target.test/app', status_code:200, truncated:false,
  missing:{request_body:false, response_body:false},
  request:{headers:[{name:'Cookie',value:'[REDACTED]'}],body:''},
  response:{headers:[{name:'Content-Type',value:'text/plain'}],body:'Recorded response'},
} };
window.fetch = async (input, options={}) => {
  const url = new URL(typeof input==='string' ? input : input.url, location.origin);
  let body;
  if (url.pathname === '/api/v1/runs') body={runs:[trafficRun],total:1};
  else if (url.pathname === '/api/v1/runs/run-a') body=trafficRun;
  else if (url.pathname.endsWith('/report')) body={run_id:'run-a',executive_summary:'流量证据测试报告',
    candidate_findings:[trafficFinding],confirmed_findings:[],findings:[trafficFinding],limitations:[],
    evidence:window.__trafficQA.created.length ? [{evidence_id:'evidence-1',summary:'GET /app',metadata:{kind:'traffic'}}] : []};
  else if (url.pathname.endsWith('/ledger')) body={events:[{event_id:'http-event-1',sequence:1,
    event_type:'tool.completed',timestamp:'2026-10-15T00:00:00Z',payload:{}}],chain_valid:true};
  else if (url.pathname.endsWith('/traffic-evidence') && options.method === 'POST') {
    window.__trafficQA.created.push(JSON.parse(options.body)); body=trafficEvidence;
  } else if (url.pathname.endsWith('/traffic-bindings')) {
    const binding=JSON.parse(options.body); window.__trafficQA.bound.push(binding);
    trafficFinding.evidence_ids=['evidence-1']; trafficFinding.raw.traffic_bindings=[binding]; body=binding;
  } else if (url.pathname.endsWith('/traffic-evidence/evidence-1')) body=trafficEvidence;
  else return trafficNativeFetch(input,options);
  return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
};
'''


def checks(command, evaluate, until):
    until("document.querySelector('.ant-segmented-item-label') !== null")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(e=>e.textContent.includes('任务结果')).click()")
    until("document.querySelector('.finding-card') !== null")
    evaluate("[...document.querySelectorAll('button')].find(e=>e.textContent.includes('关联流量证据')).click()")
    until("document.querySelector('.traffic-evidence-modal') !== null")
    evaluate("[...document.querySelectorAll('.ant-modal .ant-segmented-item')].find(e=>e.textContent.includes('账本记录')).click()")
    evaluate("const input=document.querySelector('.ant-modal input[role=combobox]'); const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; setter.call(input,'http-event-1'); input.dispatchEvent(new Event('input',{bubbles:true}));")
    until("[...document.querySelectorAll('.ant-modal button')].some(e=>e.textContent.includes('保存快照')&&!e.disabled)")
    evaluate("[...document.querySelectorAll('.ant-modal button')].find(e=>e.textContent.includes('保存快照')).click()")
    until("document.querySelector('.traffic-exchange pre')?.textContent.includes('[REDACTED]')")
    assert evaluate("window.__trafficQA.created[0].source_ref") == "http-event-1"
    assert evaluate("window.__trafficQA.created[0].source_kind") == "ledger"
    assert evaluate("document.querySelector('.traffic-evidence-summary').textContent.includes('记录完整')")
    assert evaluate("document.querySelector('.ant-modal a').getAttribute('href')") == "/api/v1/runs/run-a/traffic-evidence/evidence-1/export"
    evaluate("[...document.querySelectorAll('.ant-modal button')].find(e=>e.textContent.includes('关联到当前发现')).click()")
    until("window.__trafficQA.bound.length===1")
    assert evaluate("window.__trafficQA.bound[0].role") == "proof"
    until("document.querySelector('.finding-card').textContent.includes('漏洞证明')")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    until("document.querySelector('.traffic-evidence-exchanges').getBoundingClientRect().width<390")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    assert evaluate("document.querySelector('.traffic-evidence-modal').scrollHeight > document.querySelector('.traffic-evidence-modal').clientHeight")
    evaluate("document.querySelector('.traffic-evidence-modal').scrollTop = document.querySelector('.traffic-evidence-modal').scrollHeight")
    assert evaluate("document.querySelector('.ant-modal a').getBoundingClientRect().bottom <= window.innerHeight")
    assert evaluate("window.__blackboardQA.errors") == []
    destination = Path(__file__).parents[2] / 'data/artex-dev/traffic-evidence-browser.png'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    print('PASS: import, redacted preview, integrity, binding, export link and mobile layout', flush=True)


if __name__ == '__main__':
    runner.main(fixture_extra=fixture, checks=checks)
