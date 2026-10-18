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
    assert evaluate("[...document.querySelectorAll('.ar-node-card')].every(el=>getComputedStyle(el).borderRadius==='50%' && el.querySelector('.ar-node-symbol svg') && el.querySelector('.ar-node-label strong'))")
    assert evaluate(f"document.querySelectorAll('.ar-legend-kinds>span').length === new Set({cy}.nodes().map(n=>n.data('type'))).size")
    assert evaluate(f"document.querySelectorAll('.ar-legend-status>span').length === new Set({cy}.nodes().map(n=>n.data('status'))).size")
    assert evaluate("(() => { const legend=document.querySelector('.ar-map-legend'),canvas=document.querySelector('.ar-cy').getBoundingClientRect(),body=document.querySelector('.ar-map-body').getBoundingClientRect(); return !legend.open && legend.getBoundingClientRect().width<canvas.width/3 && Math.abs(canvas.top-body.top)<1 && Math.abs(canvas.bottom-body.bottom)<1 })()"), 'The legend still reserves a blank band'
    evaluate("document.querySelector('.ar-legend-toggle').click()")
    assert evaluate("document.querySelector('.ar-map-legend').open"), 'Legend did not expand'
    evaluate("document.querySelector('.ar-legend-toggle').click()")
    assert evaluate("getComputedStyle(document.querySelector('.ar-map-body')).backgroundColor") == 'rgb(11, 17, 21)'
    assert evaluate("getComputedStyle(document.querySelector('.ar-map-body')).backgroundImage.includes('radial-gradient')")
    assert evaluate("getComputedStyle(document.querySelector('.ar-map-body')).backgroundSize") == '20px 20px'
    assert evaluate(f"{cy}.edges().every(e=>e.style('curve-style')==='straight')")
    assert evaluate("getComputedStyle(document.querySelector('.ar-node-card.type-service')).color !== getComputedStyle(document.querySelector('.ar-node-card.type-domain')).color")
    print('PASS: initial folded host branch, directory and real call provenance',flush=True)

    def search(term):
        evaluate("(() => { const input=document.querySelector('[aria-label=搜索资产]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,"+json.dumps(term)+"); input.dispatchEvent(new Event('input',{bubbles:true})); })()")
    search('route-0-11')
    until("document.querySelectorAll('.ar-asset-row').length === 1")
    evaluate("document.querySelector('.ar-asset-row').click()")
    until(f"{cy}.getElementById('run-a:e0-11').length===1")
    assert evaluate(f"document.querySelectorAll('.ar-legend-kinds>span').length === new Set({cy}.nodes().map(n=>n.data('type'))).size")
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
    previous_zoom = evaluate(f'{cy}.zoom()')
    evaluate("document.querySelector('[aria-label=放大资产图]').click()")
    until(f"document.querySelector('.ar-zoom-percent').textContent === Math.round({cy}.zoom()*100)+'%'")
    assert evaluate(f'{cy}.zoom()') > previous_zoom
    evaluate("document.querySelector('[aria-label=缩小资产图]').click()")
    until(f"document.querySelector('.ar-zoom-percent').textContent === Math.round({cy}.zoom()*100)+'%'")
    assert abs(evaluate(f'{cy}.zoom()') - previous_zoom) < .0001
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
    assert evaluate("getComputedStyle(document.querySelector('.ar-map-body')).backgroundColor")=='rgb(247, 250, 252)'
    assert evaluate("getComputedStyle(document.querySelector('.ar-map-body')).backgroundImage.includes('radial-gradient')")
    assert evaluate("getComputedStyle(document.querySelector('.ar-node-card.status-invoked')).borderColor !== getComputedStyle(document.querySelector('.ar-node-card.status-discovered')).borderColor")
    screenshot('asset-graph-desktop-light.png')
    card = evaluate("(() => { const r=document.querySelector('[data-asset-id=\"run-a:host\"]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2} })()")
    old = evaluate(f"{cy}.getElementById('run-a:host').position()")
    command('Input.dispatchMouseEvent',type='mouseMoved',**card)
    command('Input.dispatchMouseEvent',type='mousePressed',button='left',clickCount=1,**card)
    command('Input.dispatchMouseEvent',type='mouseMoved',buttons=1,x=card['x']+30,y=card['y']+25)
    command('Input.dispatchMouseEvent',type='mouseReleased',button='left',clickCount=1,x=card['x']+30,y=card['y']+25)
    time.sleep(.2)
    new = evaluate(f"{cy}.getElementById('run-a:host').position()")
    assert new['x']>old['x'] and new['y']>old['y'], f'Card dragging failed: {old} -> {new}, point={card}'
    alignment = evaluate(f"(() => {{ const n={cy}.getElementById('run-a:host'),r=document.querySelector('[data-asset-id=\"run-a:host\"]').getBoundingClientRect(),c=document.querySelector('.ar-cy').getBoundingClientRect(),p=n.renderedPosition();return Math.abs(r.x+r.width/2-c.x-p.x)<1 && Math.abs(r.y+r.height/2-c.y-p.y)<1 }})()")
    assert alignment,'Cards separated from graph edges'
    # Refresh after a real pointer drag must preserve the custom arrangement.
    before = evaluate(f"[{cy}.getElementById('run-a:host').position(),{cy}.zoom(),{cy}.pan()]")
    evaluate("window.__assetQA.revision++; document.querySelector('[aria-label=刷新资产图]').click()")
    until("!document.querySelector('[aria-label=刷新资产图]').disabled")
    assert before == evaluate(f"[{cy}.getElementById('run-a:host').position(),{cy}.zoom(),{cy}.pan()]")
    previous_zoom = evaluate(f'{cy}.zoom()')
    evaluate("document.querySelector('[data-asset-id=\"run-a:host\"]').dispatchEvent(new WheelEvent('wheel',{deltaY:-100,clientX:500,clientY:500,bubbles:true,cancelable:true}))")
    assert evaluate(f'{cy}.zoom()') > previous_zoom
    until(f"document.querySelector('.ar-zoom-percent').textContent === Math.round({cy}.zoom()*100)+'%'")
    evaluate("document.querySelector('[aria-label=适配资产图]').click()")
    print('PASS: circular icons, type colors/status borders, light theme, wheel zoom, drag alignment and dragged-view refresh',flush=True)

    # Exercise a real click on the new small circle, rather than only the directory.
    time.sleep(.2)
    point = evaluate("(() => {const r=document.querySelector('[data-asset-id=\"run-a:s0\"]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()")
    command('Input.dispatchMouseEvent',type='mousePressed',button='left',clickCount=1,**point)
    command('Input.dispatchMouseEvent',type='mouseReleased',button='left',clickCount=1,**point)
    until("document.querySelector('[data-asset-id=\"run-a:s0\"]').getAttribute('aria-pressed')==='true'")
    assert evaluate("document.querySelector('.ar-detail-scroll').textContent.includes('call-1')")
    evaluate("document.querySelector('[data-asset-id=\"run-a:host\"]').focus()")
    command('Input.dispatchKeyEvent',type='keyDown',key='Enter',code='Enter',windowsVirtualKeyCode=13)
    command('Input.dispatchKeyEvent',type='keyUp',key='Enter',code='Enter',windowsVirtualKeyCode=13)
    until("document.querySelector('[data-asset-id=\"run-a:host\"]').getAttribute('aria-pressed')==='true'")
    print('PASS: pointer and keyboard circle selection still opens the actual source and tool details',flush=True)

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
    assert evaluate('document.documentElement.scrollWidth<=390'), 'Mobile map overflow'
    assert evaluate("(() => { const legend=document.querySelector('.ar-map-legend').getBoundingClientRect(),canvas=document.querySelector('.ar-cy').getBoundingClientRect(); return legend.width<canvas.width/2 && legend.right<=canvas.right && Math.abs(canvas.top-document.querySelector('.ar-map-body').getBoundingClientRect().top)<1 })()"), 'Mobile legend reserves map space'
    screenshot('asset-graph-mobile-map.png')
    evaluate("[...document.querySelectorAll('.ar-mobile-tabs button')].find(el=>el.textContent==='详情').click()")
    time.sleep(.2)
    assert evaluate("getComputedStyle(document.querySelector('.ar-detail')).display")=='flex'
    assert evaluate('document.documentElement.scrollWidth<=390'), 'Mobile detail overflow'
    print('PASS: independent input files, narrow screen tabs, no overflow and reduced motion',flush=True)

    command('Emulation.setDeviceMetricsOverride',width=1440,height=1050,deviceScaleFactor=1,mobile=False)
    evaluate("window.__assetQA.large=true; document.querySelector('[aria-label=刷新资产图]').click()")
    until("document.querySelectorAll('.ar-asset-row').length===333")
    assert evaluate(f'{cy}.nodes().length')==61
    evaluate("document.querySelector('[aria-label=适配资产图]').click()")
    assert evaluate(f"(() => {{ const box={cy}.nodes().renderedBoundingBox();return box.x1>=0 && box.y1>=0 && box.x2<={cy}.width() && box.y2<={cy}.height() }})()"), 'Large graph does not fit the viewport'
    search('route-29-9')
    until("document.querySelectorAll('.ar-asset-row').length===1")
    evaluate("document.querySelector('.ar-asset-row').click()")
    until(f"{cy}.getElementById('run-a:e29-9').length===1")
    assert evaluate(f'{cy}.nodes().length')==70
    assert evaluate(f'{cy}.zoom()')>=.55, 'Searched endpoint is too small to read'
    print('PASS: 300 endpoint/30 service fixture folds to 61 cards; hidden endpoint remains searchable',flush=True)
    evaluate("window.__assetQA.delay=500; document.querySelector('[aria-label=刷新资产图]').click(); [...document.querySelectorAll('.session-item')].find(el=>el.textContent.includes('run-b')).click()")
    until("document.querySelector('.ar-footer') !== null && document.querySelector('.ar-detail h3')?.textContent.includes('run-b')")
    assert evaluate(f"{cy}.nodes().every(n=>n.id().includes('run-b'))")
    assert evaluate('window.__blackboardQA.errors')==[],evaluate('window.__blackboardQA.errors')
    print('PASS: switching tasks during refresh aborts stale requests and never mixes assets; no browser errors',flush=True)

if __name__=='__main__':
    harness.main((ROOT / 'asset-graph-browser-fixture.js').read_text(encoding='utf-8'),checks)
