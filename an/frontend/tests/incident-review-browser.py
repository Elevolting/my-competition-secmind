"""Verify incident receipts open a retestable workbench report in Chrome."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("blackboard-browser.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

fixture = r'''
window.__blackboardQA.runDelay=0;
window.__incidentReviewQA={opened:0};
const incidentReviewBaseFetch=window.fetch.bind(window);
window.fetch=async(input,options={})=>{
  const url=new URL(typeof input==='string'?input:input.url,location.origin);
  const path=url.pathname;
  let body;
  if(path==='/api/v1/incident/status') body={running:false,inventory:null,pending_approvals:0,allowed_roots:[]};
  else if(path==='/api/v1/incident/logs') body={logs:[],total:0};
  else if(path==='/api/v1/incident/actions') body={actions:[{action_id:'action-1',command:'collect_indicators',
    label:'检查监听暴露与基线变化',target:'local',status:'completed',result:{findings:[]}}],total:1};
  else if(path==='/api/v1/incident/pending-approvals') body={approvals:[]};
  else if(path==='/api/v1/incident/commands') body={groups:[]};
  else if(path==='/api/v1/incident/eligible-unblocks') body={actions:[]};
  else if(path==='/api/v1/incident/actions/action-1/review-source') {
    window.__incidentReviewQA.opened++; body={run_id:'incident-source',action_id:'action-1'};
  } else if(path==='/api/v1/runs') body={runs:[{run_id:'incident-source',name:'应急动作来源',
    status:'completed',module_route:'incident_response',scenario:'incident_response',budget:{}}],total:1};
  else if(path==='/api/v1/runs/incident-source') body={run_id:'incident-source',name:'应急动作来源',
    status:'completed',module_route:'incident_response',scenario:'incident_response',budget:{}};
  else if(path==='/api/v1/runs/incident-source/report') body={run_id:'incident-source',
    executive_summary:'本机应急动作回执',findings:[],evidence:[{evidence_id:'incident-evidence'}],limitations:[]};
  else if(path==='/api/v1/runs/incident-source/ledger') body={events:[],chain_valid:true};
  else return incidentReviewBaseFetch(input,options);
  return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
};
'''


def checks(command, evaluate, until):
    command('Page.navigate', url='http://127.0.0.1:5173/incident-response')
    until("[...document.querySelectorAll('button')].some(e=>e.textContent.includes('复核研判'))")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    until("document.querySelector('button')!==null")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    evaluate("[...document.querySelectorAll('button')].find(e=>e.textContent.includes('复核研判')).click()")
    until("location.pathname==='/workbench'&&new URLSearchParams(location.search).get('view')==='result'")
    until("document.querySelector('.report-hero')?.textContent.includes('本机应急动作回执')")
    assert evaluate("window.__incidentReviewQA.opened") == 1
    assert evaluate("document.querySelector('.report-hero .retest-entry button')!==null")
    assert evaluate("window.__blackboardQA.errors") == []
    print('PASS: incident receipt opens its immutable source report and retest entry', flush=True)


if __name__ == '__main__':
    runner.main(fixture_extra=fixture, checks=checks)
