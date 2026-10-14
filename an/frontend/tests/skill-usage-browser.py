"""Skill usage UI regression with isolated API fixtures and installed Chrome."""

import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("blackboard-browser.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

fixture = r"""
window.__skillsQA={queries:[],failList:false,failDetail:false,slowDetail:false,late:false};
const skillsNativeFetch=window.fetch.bind(window);
const skillEvents=Array.from({length:22},(_,i)=>({event_id:`event-${i}`,run_id:'remote-a',sequence:i+1,
 timestamp:'2026-10-15T00:00:00Z',event_type:i===21?'skill.load_failed':'tool.invoked',
 skill_ids:['python-security-audit'],role:'sast-investigator',workbench_run_ids:['run-a'],
 payload:{skill_usage:{usage_id:`operation-${i}`,step_id:'scan',invocation_attempt:1,
 attribution:'verified_work_contract'}},hash:'a'.repeat(64)}));
window.fetch=async(input,options={})=>{
 const url=new URL(typeof input==='string'?input:input.url,location.origin),qa=window.__skillsQA;
 if(!url.pathname.startsWith('/api/v1/skills/usage')) return skillsNativeFetch(input,options);
 if(url.pathname==='/api/v1/skills/usage') {
  qa.queries.push(Object.fromEntries(url.searchParams));
  if(qa.failList) return new Response(JSON.stringify({detail:'统计查询失败'}),{status:503});
  const skill=url.searchParams.get('skill_id'),type=url.searchParams.get('event_type');
  if(skill==='slow') {await new Promise(r=>setTimeout(r,800));qa.late=true;}
  let rows=skillEvents;
  if(skill&&!['slow','python-security-audit'].includes(skill)) rows=[];
  if(type) rows=rows.filter(e=>e.event_type===type);
  const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||20);
  return new Response(JSON.stringify({skills:rows.length?[{skill_id:'python-security-audit',loads:4,
   load_failures:1,calls:21,succeeded:20,failed:0,pending:1}]:[],totals:{loads:4,load_failures:1,calls:21},
   events:rows.slice(offset,offset+limit),total_events:rows.length,
   unavailable_reason:url.searchParams.get('run_id')==='legacy'?'此任务没有独立分析引擎任务引用':null}));
 }
 if(qa.failDetail) return new Response(JSON.stringify({detail:'详情查询失败'}),{status:503});
 if(qa.slowDetail) await new Promise(r=>setTimeout(r,800));
 return new Response(JSON.stringify(skillEvents.find(e=>e.event_id===url.pathname.split('/').at(-1))));
};
"""


def checks(command, evaluate, until):
    def search(label, value):
        selector = "document.querySelector(" + json.dumps(f'input[aria-label="{label}"]') + ")"
        evaluate(f"{selector}.focus(); {selector}.select()")
        command("Input.dispatchKeyEvent", type="keyDown", key="Backspace", code="Backspace", windowsVirtualKeyCode=8)
        command("Input.dispatchKeyEvent", type="keyUp", key="Backspace", code="Backspace", windowsVirtualKeyCode=8)
        if value:
            command("Input.insertText", text=value)
        assert evaluate(f"{selector}.value") == value
        evaluate(f'{selector}.closest(".ant-input-search").querySelector("button.ant-btn").click()')

    until(
        "document.querySelectorAll('.skill-usage .ant-table-tbody')[1]"
        "?.querySelectorAll('tr[data-row-key]').length===20"
    )
    evaluate("document.querySelector('.skill-usage .ant-pagination-item-2').click()")
    until("window.__skillsQA.queries.at(-1).offset==='20'")
    until(
        "document.querySelectorAll('.skill-usage .ant-table-tbody')[1]?.querySelectorAll('tr[data-row-key]').length===2"
    )
    search("按技能筛选", "slow")
    until("window.__skillsQA.queries.at(-1).skill_id==='slow'")
    search("按技能筛选", "missing")
    until("document.querySelector('.skill-usage .ant-empty-description')?.textContent==='没有可统计的技能事件'")
    until("window.__skillsQA.late")
    assert evaluate(
        "document.querySelector('.skill-usage .ant-empty-description')?.textContent==='没有可统计的技能事件'"
    )
    search("按技能筛选", "python-security-audit")
    until("document.querySelector('.skill-usage tr[data-row-key=\"event-0\"]')!==null")
    search("按角色筛选", "sast-investigator")
    until("window.__skillsQA.queries.at(-1).role==='sast-investigator'")
    search("按任务筛选技能", "legacy")
    until("document.querySelector('.skill-usage .ant-alert-warning')!==null")
    search("按任务筛选技能", "run-a")
    until("document.querySelector('.skill-usage .ant-alert-warning')===null")
    until("document.querySelector('.skill-usage-heading button:not(.ant-btn-loading)')!==null")
    evaluate("window.__skillsQA.failList=true; document.querySelector('.skill-usage-heading button').click()")
    until("document.querySelector('.skill-usage .ant-alert-error')!==null")
    evaluate("window.__skillsQA.failList=false; document.querySelector('.skill-usage .ant-alert-error button').click()")
    until("document.querySelector('.skill-usage tr[data-row-key=\"event-0\"]')!==null")
    evaluate(
        "window.__skillsQA.failDetail=true; "
        "document.querySelector('.skill-usage tr[data-row-key=\"event-0\"] button').click()"
    )
    until("document.querySelector('.ant-modal-body .ant-alert-error')!==null")
    evaluate(
        "window.__skillsQA.failDetail=false; document.querySelector('.ant-modal-body .ant-alert-error button').click()"
    )
    until("document.querySelector('.skill-usage-detail pre')!==null")
    assert evaluate("document.querySelector('.skill-usage-detail pre').textContent.includes('operation-0')")
    assert evaluate("document.querySelector('.skill-usage-detail a').getAttribute('href')==='/audit/run-a'")
    evaluate("document.querySelector('.ant-modal-close').click()")
    until("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"])')===null")
    evaluate(
        "window.__skillsQA.slowDetail=true; "
        "document.querySelector('.skill-usage tr[data-row-key=\"event-0\"] button').click()"
    )
    until("document.querySelector('.ant-modal-body [role=status]')!==null")
    evaluate("document.querySelector('.ant-modal-close').click()")
    command("Runtime.evaluate", expression="new Promise(r=>setTimeout(r,1000))", awaitPromise=True)
    assert evaluate("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"])')===null")
    command("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth+1")
    evaluate("document.querySelector('.skill-usage tr[data-row-key=\"event-0\"] a').click()")
    until("location.pathname==='/workbench'&&new URLSearchParams(location.search).get('run')==='run-a'")
    assert evaluate("window.__blackboardQA.errors") == []
    print(
        "PASS: skill pagination, filters, response ordering, retry, source detail, task links and mobile layout",
        flush=True,
    )


if __name__ == "__main__":
    os.environ.setdefault("SECMIND_BROWSER_TEST_URL", "http://127.0.0.1:5173/skills")
    runner.main(fixture_extra=fixture, checks=checks)
