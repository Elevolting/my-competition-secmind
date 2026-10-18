"""Exercise the asset library in Chrome with isolated API fixtures."""
import base64
import importlib.util
import json
import os
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("blackboard-browser.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

fixture = r'''
window.__assetsQA={queries:[],failList:false,failDetail:false,slow:false,slowSearch:null,lateListFinished:false};
const assetNativeFetch=window.fetch.bind(window);
const assetRows=Array.from({length:22},(_,i)=>({asset_id:`asset-${i}`,kind:i===21?'domain':'endpoint',
  label:i===0?'https://lab.test/app/login':`https://lab.test/app/health-${i}`,run_count:2,
  observed_run_count:i===0?1:0,finding_count:i===0?1:0}));
window.fetch=async(input,options={})=>{
  const url=new URL(typeof input==='string'?input:input.url,location.origin);
  if(!url.pathname.startsWith('/api/v1/assets')) return assetNativeFetch(input,options);
  const qa=window.__assetsQA;
  if(url.pathname==='/api/v1/assets/graph') {
    const base=assetRows.slice(0,3).map(row=>({...row,id:row.asset_id,type:row.kind,rawId:row.label,status:'discovered',sources:['tool'],runs:[{run_id:'run-a',coverage:'observed',status:'discovered'}]}));
    const host={...assetRows[21],id:'asset-21',type:'domain',rawId:'lab.test',label:'lab.test',status:'scoped',sources:['scope'],runs:[{run_id:'run-a',coverage:'unobserved',status:'scoped'}]};
    const service={...host,id:'service-1',asset_id:'service-1',type:'service',kind:'service',rawId:'https://lab.test',label:'https://lab.test'};
    const edges=[{id:'host-service',source:host.id,target:service.id,type:'contains'},...base.map(row=>({id:`service-${row.id}`,source:service.id,target:row.id,type:'contains'}))];
    return new Response(JSON.stringify({nodes:[host,service,...base],edges,total:5,limit:2000,truncated:false}),{status:200});
  }
  if(url.pathname==='/api/v1/assets') {
    qa.queries.push(Object.fromEntries(url.searchParams));
    if(qa.failList) return new Response(JSON.stringify({detail:'列表暂时不可用'}),{status:503});
    let rows=assetRows.filter(row=>row.label.includes(url.searchParams.get('search')||''));
    const kind=url.searchParams.get('kind'),coverage=url.searchParams.get('coverage');
    if(kind) rows=rows.filter(row=>row.kind===kind);
    if(coverage==='observed') rows=rows.filter(row=>row.observed_run_count>0);
    const runId=url.searchParams.get('run_id');
    if(runId&&!['run-a','run-b'].includes(runId)) rows=[];
    const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||20);
    if(qa.slowSearch!==null&&url.searchParams.get('search')===qa.slowSearch) {
      await new Promise(resolve=>setTimeout(resolve,800));
      qa.lateListFinished=true;
    }
    return new Response(JSON.stringify({assets:rows.slice(offset,offset+limit),total:rows.length}),{status:200});
  }
  const id=url.pathname.split('/').at(-1),row=assetRows.find(row=>row.asset_id===id);
  if(qa.failDetail) return new Response(JSON.stringify({detail:'详情暂时不可用'}),{status:503});
  if(qa.slow&&id==='asset-0') await new Promise(resolve=>setTimeout(resolve,800));
  return new Response(JSON.stringify({...row,runs:[
    {run_id:'run-a',coverage:'observed',status:'discovered',scope_display:['https://lab.test/app'],
     sources:['scope','tool'],finding_ids:['finding-1'],first_seen:'2026-10-15T00:00:00+00:00',
     last_seen:'2026-10-15T01:00:00+00:00',provenance:[{source:'tool',ref:'probe-1',confidence:0.8}]},
    {run_id:'run-b',coverage:'unobserved',status:'scoped',scope_display:[row.label],
     sources:['scope'],finding_ids:[],first_seen:'2026-10-15T00:00:00+00:00',
     last_seen:'2026-10-15T01:00:00+00:00',provenance:[{source:'scope',ref:'scope:1'}]}
  ]}),{status:200});
};
'''


def checks(command, evaluate, until):
    def click(expression):
        position = evaluate(f'(() => {{const element={expression}; element.scrollIntoView({{block:"center"}}); '
                            'const box=element.getBoundingClientRect(); '
                            'return {x:box.x+box.width/2,y:box.y+box.height/2};})()')
        command('Input.dispatchMouseEvent', type='mousePressed', button='left', clickCount=1, **position)
        command('Input.dispatchMouseEvent', type='mouseReleased', button='left', clickCount=1, **position)

    def search(label, value):
        until("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"])')===null")
        input_selector = json.dumps('input[aria-label="' + label + '"]')
        selector = f'document.querySelector({input_selector})'
        evaluate(f'(() => {{const input={selector}; input.focus(); input.select();}})()')
        assert evaluate(f'document.activeElement==={selector}'), 'Search input did not receive focus'
        command('Input.dispatchKeyEvent', type='keyDown', key='Backspace', code='Backspace', windowsVirtualKeyCode=8)
        command('Input.dispatchKeyEvent', type='keyUp', key='Backspace', code='Backspace', windowsVirtualKeyCode=8)
        if value:
            command('Input.insertText', text=value)
        assert evaluate(f'{selector}.value') == value, 'Search input value did not change'
        evaluate(f'{selector}.closest(".ant-input-search").querySelector("button.ant-btn").click()')

    try:
        until("document.querySelectorAll('.asset-library-label').length===20")
    except AssertionError:
        print('Browser state:', evaluate("({url:location.href,body:document.body.innerText.slice(0,500),"
              "queries:window.__assetsQA?.queries,errors:window.__blackboardQA?.errors})"), flush=True)
        raise
    assert evaluate("document.querySelector('.header-module').textContent.includes('跨任务资产库')")
    evaluate("document.querySelector('.ant-pagination-next button').click()")
    until("window.__assetsQA.queries.at(-1).offset==='20'")
    search('搜索资产', 'login')
    until("window.__assetsQA.queries.at(-1).search==='login'&&window.__assetsQA.queries.at(-1).offset==='0'")
    until("document.querySelectorAll('.asset-library-label').length===1")
    evaluate("document.querySelector('.asset-library-label').click()")
    until("document.querySelector('.asset-library-detail h4')?.textContent.includes('login')")
    assert evaluate("document.querySelectorAll('.asset-library-run').length") == 2
    assert evaluate("document.querySelector('.asset-library-detail').textContent.includes('finding-1')")
    assert evaluate("document.querySelector('.asset-library-detail').textContent.includes('https://lab.test/app')")
    evaluate("document.querySelector('.asset-library-run summary').click()")
    assert evaluate("document.querySelector('.asset-library-run').textContent.includes('probe-1')")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    until("document.querySelector('.ant-modal')?.getBoundingClientRect().width<=390")
    until("document.querySelector('.ant-modal').getAnimations({subtree:true}).length===0")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    destination = Path(__file__).parents[2] / 'data/artex-dev/asset-library-mobile.png'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    evaluate("document.querySelector('.ant-modal-close').click()")
    until("location.pathname==='/assets'")
    search('搜索资产', '')
    until("document.querySelectorAll('.asset-library-label').length===20")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    command('Emulation.setDeviceMetricsOverride', width=1440, height=1000, deviceScaleFactor=1, mobile=False)
    evaluate("window.__assetsQA.slowSearch='login'")
    search('搜索资产', 'login')
    until("window.__assetsQA.queries.at(-1).search==='login'")
    search('搜索资产', 'health')
    until("document.querySelectorAll('.asset-library-label').length===20")
    until("window.__assetsQA.lateListFinished")
    assert evaluate("[...document.querySelectorAll('.asset-library-label')].every(e=>e.textContent.includes('health'))")
    evaluate("window.__assetsQA.slowSearch=null")
    search('搜索资产', '')
    until("window.__assetsQA.queries.at(-1).search===undefined")
    until("document.querySelector('.asset-library-label')?.textContent.includes('login')")
    click("document.querySelector('[aria-label=资产类型]')")
    until("document.querySelector('.ant-select-dropdown:not(.ant-select-dropdown-hidden)')!==null")
    evaluate("[...document.querySelectorAll('.ant-select-item-option')].find(e=>e.textContent==='端点').click()")
    until("window.__assetsQA.queries.at(-1).kind==='endpoint'")
    click("document.querySelector('[aria-label=观测状态]')")
    until("[...document.querySelectorAll('.ant-select-item-option')].some(e=>e.textContent==='有成功观测的任务')")
    evaluate("[...document.querySelectorAll('.ant-select-item-option')].find(e=>e.textContent==='有成功观测的任务').click()")
    until("window.__assetsQA.queries.at(-1).coverage==='observed'")
    search('按任务筛选资产', 'run-a')
    until("window.__assetsQA.queries.at(-1).run_id==='run-a'")
    search('按任务筛选资产', 'missing-run')
    until("document.querySelector('.asset-library-results').textContent.includes('没有匹配的资产')")
    search('按任务筛选资产', 'run-a')
    until("document.querySelector('.asset-library-label')!==null")
    until("document.querySelector('.asset-library-heading button:not(.ant-btn-loading)')!==null")
    evaluate("window.__assetsQA.failList=true; document.querySelector('.asset-library-heading button').click()")
    try:
        until("document.querySelector('.asset-library-results .ant-alert-error')!==null")
    except AssertionError:
        print('List retry state:', evaluate("({queries:window.__assetsQA.queries,"
              "busy:!!document.querySelector('.asset-library-heading .ant-btn-loading'),"
              "body:document.querySelector('.asset-library-results')?.innerText.slice(0,300)})"), flush=True)
        raise
    evaluate("window.__assetsQA.failList=false; "
             "document.querySelector('.asset-library-results .ant-alert-error button').click()")
    until("document.querySelector('.asset-library-label')!==null")
    evaluate("window.__assetsQA.failDetail=true; document.querySelector('.asset-library-label').click()")
    until("document.querySelector('.asset-library-detail .ant-alert-error')!==null")
    evaluate("window.__assetsQA.failDetail=false; "
             "document.querySelector('.asset-library-detail .ant-alert-error button').click()")
    until("document.querySelector('.asset-library-detail h4')!==null")
    evaluate("document.querySelector('.ant-modal-close').click()")
    until("location.pathname==='/assets'")
    evaluate("window.__assetsQA.slow=true; document.querySelector('.asset-library-label').click()")
    until("document.querySelector('.asset-library-detail [role=status]')!==null")
    evaluate("document.querySelector('.ant-modal-close').click()")
    until("location.pathname==='/assets'")
    # The fixture ignores abort, ensuring a late response cannot reopen details.
    command('Runtime.evaluate', expression="new Promise(r=>setTimeout(r,1000))", awaitPromise=True)
    assert evaluate("document.querySelector('.ant-modal-wrap:not([style*=\"display: none\"])')===null")
    evaluate("window.__assetsQA.slow=false; document.querySelector('.asset-library-label').click()")
    until("document.querySelector('.asset-library-detail h4')!==null")
    evaluate("document.querySelector('.asset-library-run a').click()")
    until("location.pathname==='/workbench'&&new URLSearchParams(location.search).get('run')==='run-a'")
    assert evaluate("window.__blackboardQA.errors") == []
    print('PASS: asset pagination, filters, provenance, task scopes, mobile layout and task link', flush=True)


def map_checks(command, evaluate, until):
    command('Emulation.setDeviceMetricsOverride', width=1440, height=1050, deviceScaleFactor=1, mobile=False)
    until("document.querySelectorAll('.asset-library-label').length===20")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(el=>el.textContent.includes('资产地图')).click()")
    until("document.querySelectorAll('.asset-library-map .ar-node-card').length===5")
    assert evaluate("document.querySelector('.asset-library-map .ar-map-legend').open===false")
    screenshots = Path(tempfile.mkdtemp(prefix='secmind-library-map-'))
    evaluate("document.querySelector('.asset-library-map .ar-stage').scrollIntoView({block:'start'})")
    command('Runtime.evaluate', expression="new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))", awaitPromise=True)
    (screenshots / 'desktop.png').write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    evaluate("document.body.classList.add('light-theme')")
    (screenshots / 'desktop-light.png').write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    evaluate("document.body.classList.remove('light-theme')")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    command('Page.reload', ignoreCache=True)
    until("document.querySelectorAll('.asset-library-label').length===20")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(el=>el.textContent.includes('资产地图')).click()")
    until("document.querySelectorAll('.asset-library-map .ar-node-card').length===5")
    until("document.querySelector('.asset-library-map .ar-mobile-tabs')?.getBoundingClientRect().height>0")
    assert evaluate("document.documentElement.scrollWidth<=window.innerWidth")
    evaluate("document.querySelector('.asset-library-map .ar-stage').scrollIntoView({block:'start'})")
    until("(() => {const box=document.querySelector('.asset-library-map .ar-cy').getBoundingClientRect(); return [...document.querySelectorAll('.asset-library-map .ar-node-card')].every(el=>{const r=el.getBoundingClientRect(); return r.left>=box.left && r.right<=box.right && r.top>=box.top && r.bottom<=box.bottom})})()")
    (screenshots / 'mobile.png').write_bytes(base64.b64decode(command('Page.captureScreenshot', format='png')['data']))
    command('Emulation.setDeviceMetricsOverride', width=1440, height=1000, deviceScaleFactor=1, mobile=False)
    command('Page.reload', ignoreCache=True)
    until("document.querySelectorAll('.asset-library-label').length===20")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(el=>el.textContent.includes('资产地图')).click()")
    until("document.querySelectorAll('.asset-library-map .ar-node-card').length===5")
    evaluate("document.querySelector('.asset-library-map .ar-asset-row:nth-child(3)').click()")
    until("document.querySelector('.asset-library-map .ar-detail h3')?.textContent.includes('login')")
    evaluate("document.querySelector('.asset-library-map .ar-open-asset').click()")
    until("document.querySelector('.asset-library-detail h4')?.textContent.includes('login')")
    print(f'Asset map screenshots: {screenshots}', flush=True)
    print('PASS: asset map renders, selects nodes and opens source details', flush=True)


if __name__ == '__main__':
    os.environ.setdefault('SECMIND_BROWSER_TEST_URL', 'http://127.0.0.1:5173/assets')
    runner.main(fixture_extra=fixture, checks=checks)
    runner.main(fixture_extra=fixture, checks=map_checks)
