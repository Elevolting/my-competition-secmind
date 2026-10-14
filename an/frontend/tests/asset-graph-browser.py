"""Read-only asset UI regression against an isolated mock API on the Vite server."""
import base64
import importlib.util
import json
import time
from pathlib import Path

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('browser_harness', ROOT / 'blackboard-browser.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

def checks(command, evaluate, until):
    command('Emulation.setDeviceMetricsOverride',width=1440,height=1050,deviceScaleFactor=1,mobile=False)
    until("[...document.querySelectorAll('.ant-segmented-item')].some(el=>el.textContent.includes('资产引用图'))")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(el=>el.textContent.includes('资产引用图')).click()")
    until("document.querySelector('.ar-node-card.type-bundle') !== null")
    until("!document.querySelector('[aria-label=刷新资产图]').disabled")
    cy = "document.querySelector('.ar-cy')._cyreg.cy"
    assert evaluate(f'{cy}.nodes().length') == 4
    assert evaluate("document.querySelectorAll('.ar-asset-row').length") == 17
    assert evaluate("document.querySelector('.ar-detail-scroll').textContent.includes('call-1')")
    print('PASS: initial folded host branch, directory and real call provenance',flush=True)

    def search(term):
        evaluate("(() => { const input=document.querySelector('[aria-label=搜索资产]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,"+json.dumps(term)+"); input.dispatchEvent(new Event('input',{bubbles:true})); })()")
    search('route-0-11')
    until("document.querySelectorAll('.ar-asset-row').length === 1")
    evaluate("document.querySelector('.ar-asset-row').click()")
    until(f"{cy}.getElementById('run-a:e0-11').length===1")
    assert evaluate("document.querySelector('.ar-detail h3').textContent.includes('/route-0-11')")
    assert evaluate(f"{cy}.edges('.is-lineage').length") == 2
    search('')
    print('PASS: folded endpoint search expands its branch and highlights actual ancestry',flush=True)

    evaluate("[...document.querySelectorAll('.ar-map-actions button')].find(el=>el.textContent==='收起端点').click()")
    until(f'{cy}.nodes().length === 4')
    evaluate("document.querySelector('[aria-label=适配资产图]').click(); document.querySelector('.asset-reference-view').scrollIntoView({block:'start'})")
    time.sleep(.3)
    def screenshot(name):
        (ROOT / name).write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
    screenshot('asset-graph-desktop-dark.png')
    evaluate("document.querySelector('[aria-label=放大资产图]').click()")
    before = evaluate(f"[...{cy}.nodes().map(n=>[n.id(),n.position()]),{cy}.zoom(),{cy}.pan()]")
    evaluate("window.__assetQA.revision++; document.querySelector('[aria-label=刷新资产图]').click()")
    until("!document.querySelector('[aria-label=刷新资产图]').disabled")
    after = evaluate(f"[...{cy}.nodes().map(n=>[n.id(),n.position()]),{cy}.zoom(),{cy}.pan()]")
    assert before==after, 'Refresh changed user view'
    evaluate("window.__assetQA.fail=true; document.querySelector('[aria-label=刷新资产图]').click()")
    until("document.querySelector('.ar-error') !== null")
    assert evaluate(f'{cy}.nodes().length')==4
    evaluate("window.__assetQA.fail=false; document.querySelector('.ar-error button').click()")
    until("document.querySelector('.ar-error') === null")
    assert evaluate('window.__assetQA.max')==1
    print('PASS: refresh preserves positions/zoom/pan; sync failure retains last records; retry recovers',flush=True)

    evaluate("document.body.classList.add('light-theme'); document.querySelector('[aria-label=适配资产图]').click()")
    time.sleep(.3)
    assert evaluate("getComputedStyle(document.querySelector('.ar-node-card')).backgroundColor")=='rgb(255, 255, 255)'
    screenshot('asset-graph-desktop-light.png')
    card = evaluate("(() => { const r=document.querySelector('[data-asset-id=\"run-a:host\"]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2} })()")
    old = evaluate(f"{cy}.getElementById('run-a:host').position()")
    command('Input.dispatchMouseEvent',type='mouseMoved',**card)
    command('Input.dispatchMouseEvent',type='mousePressed',button='left',clickCount=1,**card)
    command('Input.dispatchMouseEvent',type='mouseMoved',buttons=1,x=card['x']+30,y=card['y']+25)
    command('Input.dispatchMouseEvent',type='mouseReleased',button='left',clickCount=1,x=card['x']+30,y=card['y']+25)
    time.sleep(.2)
    new = evaluate(f"{cy}.getElementById('run-a:host').position()")
    assert new['x']>old['x'] and new['y']>old['y'], 'Card dragging failed'
    alignment = evaluate(f"(() => {{ const n={cy}.getElementById('run-a:host'),r=document.querySelector('[data-asset-id=\"run-a:host\"]').getBoundingClientRect(),c=document.querySelector('.ar-cy').getBoundingClientRect(),p=n.renderedPosition();return Math.abs(r.x+r.width/2-c.x-p.x)<1 && Math.abs(r.y+r.height/2-c.y-p.y)<1 }})()")
    assert alignment,'Cards separated from graph edges'
    print('PASS: light theme, card drag and graph/card alignment',flush=True)

    search('auth-routes.json')
    until("document.querySelectorAll('.ar-asset-row').length===1")
    evaluate("document.querySelector('.ar-asset-row').click()")
    until(f'{cy}.nodes().length===1')
    assert evaluate(f'{cy}.edges().length')==0
    search('')
    evaluate("[...document.querySelectorAll('.ar-asset-row')].find(el=>el.textContent.includes('auth.run-a.test')).click()")
    until(f'{cy}.nodes().length===4')
    command('Emulation.setEmulatedMedia',features=[{'name':'prefers-reduced-motion','value':'reduce'}])
    command('Emulation.setDeviceMetricsOverride',width=390,height=844,deviceScaleFactor=1,mobile=True)
    time.sleep(.4)
    assert evaluate("getComputedStyle(document.querySelector('.ar-directory')).display")=='flex'
    assert evaluate('document.documentElement.scrollWidth<=390'), 'Mobile page overflow'
    evaluate("document.querySelector('.asset-reference-view').scrollIntoView({block:'start'})")
    screenshot('asset-graph-mobile-directory.png')
    evaluate("[...document.querySelectorAll('.ar-mobile-tabs button')].find(el=>el.textContent==='关系图').click()")
    time.sleep(.4)
    assert evaluate(f'{cy}.width()>0')
    screenshot('asset-graph-mobile-map.png')
    evaluate("[...document.querySelectorAll('.ar-mobile-tabs button')].find(el=>el.textContent==='详情').click()")
    time.sleep(.2)
    assert evaluate("getComputedStyle(document.querySelector('.ar-detail')).display")=='flex'
    print('PASS: independent input files, narrow screen tabs, no overflow and reduced motion',flush=True)

    command('Emulation.setDeviceMetricsOverride',width=1440,height=1050,deviceScaleFactor=1,mobile=False)
    evaluate("window.__assetQA.large=true; document.querySelector('[aria-label=刷新资产图]').click()")
    until("document.querySelectorAll('.ar-asset-row').length===333")
    assert evaluate(f'{cy}.nodes().length')==61
    search('route-29-9')
    until("document.querySelectorAll('.ar-asset-row').length===1")
    evaluate("document.querySelector('.ar-asset-row').click()")
    until(f"{cy}.getElementById('run-a:e29-9').length===1")
    assert evaluate(f'{cy}.nodes().length')==70
    print('PASS: 300 endpoint/30 service fixture folds to 61 cards; hidden endpoint remains searchable',flush=True)
    evaluate("window.__assetQA.delay=500; document.querySelector('[aria-label=刷新资产图]').click(); [...document.querySelectorAll('.session-item')].find(el=>el.textContent.includes('run-b')).click()")
    until("document.querySelector('.ar-footer') !== null && document.querySelector('.ar-detail h3')?.textContent.includes('run-b')")
    assert evaluate(f"{cy}.nodes().every(n=>n.id().includes('run-b'))")
    assert evaluate('window.__blackboardQA.errors')==[],evaluate('window.__blackboardQA.errors')
    print('PASS: switching tasks during refresh aborts stale requests and never mixes assets; no browser errors',flush=True)

if __name__=='__main__':
    harness.main((ROOT / 'asset-graph-browser-fixture.js').read_text(encoding='utf-8'),checks)
