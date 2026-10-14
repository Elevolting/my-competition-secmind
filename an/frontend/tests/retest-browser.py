"""Exercise focused retest controls in an isolated Chrome fixture."""
import base64
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("blackboard-browser.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

fixture = r'''
window.__blackboardQA.runDelay=0;
window.__retestQA={created:[],results:[],record:null};
const retestNativeFetch=window.fetch.bind(window);
const retestFinding={finding_id:'finding-1',rule_id:'TEST',title:'会话校验问题',description:'原缺陷仍需核对',
  path:'src/auth.py',severity:'MEDIUM',evidence_ids:['original-evidence'],raw:{}};
const retestRun={run_id:'run-a',name:'复核测试',status:'completed',module_route:'code_audit',
  scenario:'code_audit',external_execution:{blackboard:{planning_mode:'workbench'}},budget:{}};
window.fetch=async(input,options={})=>{
  const url=new URL(typeof input==='string'?input:input.url,location.origin);
  const pathname=url.pathname;
  let body;
  if(pathname==='/api/v1/runs') body={runs:[retestRun],total:1};
  else if(pathname==='/api/v1/runs/run-a') body=retestRun;
  else if(pathname==='/api/v1/runs/run-a/report') body={run_id:'run-a',executive_summary:'原始审计报告',
    candidate_findings:[retestFinding],confirmed_findings:[],findings:[retestFinding],
    evidence:[{evidence_id:'original-evidence',summary:'原始证据'}],limitations:[]};
  else if(pathname==='/api/v1/runs/run-a/ledger') body={events:[],chain_valid:true};
  else if(pathname==='/api/v1/runs/child-run/report') body={run_id:'child-run',executive_summary:'复核完成',
    evidence:[{evidence_id:'new-evidence',summary:'本次校验结果'}]};
  else if(pathname==='/api/v1/runs/run-a/retests'&&options.method==='POST') {
    window.__retestQA.created.push(JSON.parse(options.body));
    window.__retestQA.record={retest_id:'retest-1',source_run_id:'run-a',source_kind:'finding',
      source_ref:'finding-1',child_run_id:'child-run',created_at:'2026-10-15T00:00:00Z',
      status:'running',evidence_ids:[],snapshot:{evidence:[{evidence_id:'original-evidence'}]}};
    body=window.__retestQA.record;
    setTimeout(()=>{window.__retestQA.record.status='awaiting_result'},700);
  } else if(pathname==='/api/v1/runs/run-a/retests') body={retests:window.__retestQA.record?[window.__retestQA.record]:[]};
  else if(pathname==='/api/v1/runs/run-a/retests/retest-1/result') {
    window.__retestQA.results.push(JSON.parse(options.body));
    Object.assign(window.__retestQA.record,{status:'completed',verdict:'inconclusive',
      summary:window.__retestQA.results.at(-1).summary});
    body=window.__retestQA.record;
  } else if(pathname==='/api/v1/runs/run-a/retests/retest-1') body=window.__retestQA.record;
  else return retestNativeFetch(input,options);
  return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
};
'''


def checks(command, evaluate, until):
    until("[...document.querySelectorAll('.ant-segmented-item')].some(e=>e.textContent.includes('任务结果'))")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(e=>e.textContent.includes('任务结果')).click()")
    until("document.querySelector('.finding-card .retest-entry button')!==null")
    evaluate("document.querySelector('.finding-card .retest-entry button').click()")
    until("document.querySelector('.retest-create')!==null")
    assert evaluate("document.querySelector('.retest-source').textContent.includes('原发现')")
    evaluate("[...document.querySelectorAll('.ant-modal button')].find(e=>e.textContent.includes('发起复核')).click()")
    until("window.__retestQA.created.length===1")
    assert evaluate("window.__retestQA.created[0].source_ref") == 'finding-1'
    until("document.querySelector('.retest-detail')?.textContent.includes('待登记结论')", 15)
    assert evaluate("document.querySelector('.retest-detail').textContent.includes('new-evidence')")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    until("document.querySelector('.ant-modal')?.getBoundingClientRect().width<=390")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    destination = Path(__file__).parents[2] / 'data/artex-dev/retest-browser-mobile.png'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    evaluate("const input=document.querySelector('.retest-result textarea'); const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set; setter.call(input,'材料尚不足以确认'); input.dispatchEvent(new Event('input',{bubbles:true}));")
    until("[...document.querySelectorAll('.retest-result button')].some(e=>e.textContent.includes('保存结论')&&!e.disabled)")
    evaluate("[...document.querySelectorAll('.retest-result button')].find(e=>e.textContent.includes('保存结论')).click()")
    until("window.__retestQA.results.length===1")
    assert evaluate("window.__retestQA.results[0].verdict") == 'inconclusive'
    assert evaluate("window.__blackboardQA.errors") == []
    print('PASS: retest creation, child progress, original/current evidence, mobile layout and result registration', flush=True)


if __name__ == '__main__':
    runner.main(fixture_extra=fixture, checks=checks)
