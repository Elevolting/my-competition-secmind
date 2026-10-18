"""Browser regression: run the Vite dev server, then python this file.

Uses the installed Chrome and websocket-client, without a browser download.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

import websocket


def main(fixture_extra='', checks=None):
    chrome = Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'Google/Chrome/Application/chrome.exe'
    # Chrome children may release Windows cache handles after the browser exits.
    # A locked temporary cache must not turn successful UI assertions into failure.
    with tempfile.TemporaryDirectory(prefix='secmind-browser-test-', ignore_cleanup_errors=True) as profile:
        process = subprocess.Popen([str(chrome), '--headless=new', '--disable-gpu', '--no-first-run',
                                    '--remote-debugging-port=0', '--remote-allow-origins=*',
                                    f'--user-data-dir={profile}', 'about:blank'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        connection = None
        try:
            port_file = Path(profile) / 'DevToolsActivePort'
            deadline = time.monotonic() + 15
            port = None
            while time.monotonic() < deadline:
                try:
                    port = port_file.read_text().splitlines()[0]
                    break
                except (OSError, IndexError):
                    time.sleep(0.1)
            assert port, 'Chrome did not open a debug port'
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list') as response:
                target = next(item for item in json.load(response) if item['type'] == 'page')
            connection = websocket.create_connection(target['webSocketDebuggerUrl'], suppress_origin=True, timeout=20)
            serial = 0

            def command(method, **params):
                nonlocal serial
                serial += 1
                connection.send(json.dumps({'id': serial, 'method': method, 'params': params}))
                while True:
                    message = json.loads(connection.recv())
                    if message.get('id') == serial:
                        if 'error' in message:
                            raise AssertionError(message['error'])
                        return message.get('result', {})

            def evaluate(expression):
                result = command('Runtime.evaluate', expression=expression, returnByValue=True)
                if 'exceptionDetails' in result:
                    raise AssertionError(result['exceptionDetails'])
                return result['result'].get('value')

            def until(expression, timeout=20):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if evaluate(expression):
                        return
                    time.sleep(0.1)
                raise AssertionError(f'Timed out: {expression}')

            command('Page.enable')
            command('Page.addScriptToEvaluateOnNewDocument', source=Path(__file__).with_name('blackboard-browser-fixture.js').read_text(encoding='utf-8'))
            if fixture_extra:
                command('Page.addScriptToEvaluateOnNewDocument', source=fixture_extra)
            command('Page.navigate', url=os.environ.get('SECMIND_BROWSER_TEST_URL', 'http://127.0.0.1:5173/workbench?run=run-a'))
            if checks:
                checks(command, evaluate, until)
                return
            until("[...document.querySelectorAll('.ant-segmented-item')].some(el => el.textContent.includes('探索路径'))")
            evaluate("[...document.querySelectorAll('.ant-segmented-item')].find(el => el.textContent.includes('探索路径')).click()")
            until("document.querySelector('.execution-view') !== null")
            until("document.querySelector('.execution-cytoscape canvas') !== null")
            until("!document.querySelector('[aria-label=同步画布]').classList.contains('ant-btn-loading')")
            print('PASS: a blackboard mounted before its run data initializes the canvas', flush=True)

            evaluate("window.__pulse = setInterval(() => window.__blackboardQA.emit(20 + window.__blackboardQA.graphCalls), 80)")
            until("window.__blackboardQA.graphActive === 1")
            evaluate("document.querySelector('[aria-label=同步画布]').click()")
            time.sleep(1.8)
            evaluate('clearInterval(window.__pulse)')
            until("!document.querySelector('[aria-label=同步画布]').classList.contains('ant-btn-loading')")
            assert evaluate('window.__blackboardQA.graphMax') == 1
            assert evaluate('window.__blackboardQA.graphCalls') >= 2
            until("window.__blackboardQA.ledgerCursors.some(item => item.cursor === 10)")
            cursors = evaluate("window.__blackboardQA.ledgerCursors.filter(item => item.id === 'run-a').map(item => item.cursor)")
            assert 0 in cursors and 3 in cursors and 10 in cursors, cursors
            print('PASS: event bursts and manual refresh share requests; loading clears; ledger catches up from its own cursor', flush=True)

            evaluate("window.__blackboardQA.hangGraph = true; document.querySelector('[aria-label=同步画布]').click()")
            until("document.querySelector('.execution-error') !== null")
            until("!document.querySelector('[aria-label=同步画布]').classList.contains('ant-btn-loading')")
            evaluate("window.__blackboardQA.hangGraph = false; document.querySelector('[aria-label=同步画布]').click()")
            until("document.querySelector('.execution-error') === null")
            print('PASS: timeout exits loading and retry recovers', flush=True)

            cy = "document.querySelector('.execution-cytoscape')._cyreg.cy"
            evaluate("document.querySelector('.execution-history-toggle').click()")
            until(f"{cy}.nodes().length === 61")
            evaluate("document.querySelector('.execution-list-item').click()")
            until("document.querySelector('.execution-detail-scroll')?.textContent.includes('验证目标')")
            assert evaluate(f"{cy}.elements('.is-dim').length > 0")
            command('Emulation.setDeviceMetricsOverride', width=1440, height=1000, deviceScaleFactor=1, mobile=False)
            evaluate("document.querySelector('.execution-view').scrollIntoView({block:'start'})")
            evaluate(f"void {cy}.stop().center({cy}.getElementById('intent:run-a:0'))")
            time.sleep(.3)
            alignment = f"(() => {{ const n={cy}.getElementById('intent:run-a:0'), c=document.querySelector('[data-node-id=\"intent:run-a:0\"]').getBoundingClientRect(), r=document.querySelector('.execution-cytoscape').getBoundingClientRect(), p=n.renderedPosition(); return Math.abs(c.x+c.width/2-r.x-p.x)<1 && Math.abs(c.y+c.height/2-r.y-p.y)<1 }})()"
            assert evaluate(alignment), 'HTML card does not align with its graph node'
            card_style = f"(() => {{ const c=document.querySelector('[data-node-id=\"intent:run-a:0\"]'); return {{transform:getComputedStyle(c).transform,fontSize:parseFloat(getComputedStyle(c.querySelector('strong')).fontSize),zoom:{cy}.zoom()}} }})()"
            rendered = evaluate(card_style)
            assert rendered['transform'] == 'none', 'Scaled card layer blurs the node text'
            assert abs(rendered['fontSize'] - 12 * rendered['zoom']) < .1, 'Node text does not follow canvas zoom'
            drag_before = evaluate(f"{cy}.getElementById('intent:run-a:0').position()")
            card = evaluate("(() => {const r=document.querySelector('[data-node-id=\"intent:run-a:0\"]').getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2}})()")
            command('Input.dispatchMouseEvent', type='mouseMoved', **card)
            command('Input.dispatchMouseEvent', type='mousePressed', button='left', clickCount=1, **card)
            command('Input.dispatchMouseEvent', type='mouseMoved', buttons=1, x=card['x']+40, y=card['y']+30)
            command('Input.dispatchMouseEvent', type='mouseReleased', button='left', clickCount=1, x=card['x']+40, y=card['y']+30)
            time.sleep(.2)
            drag_after = evaluate(f"{cy}.getElementById('intent:run-a:0').position()")
            assert drag_after['x'] > drag_before['x'] and drag_after['y'] > drag_before['y'], 'HTML card drag failed'
            assert evaluate(alignment), 'Dragging separated the HTML card from its edges'
            assert not evaluate("document.querySelector('[aria-label=跟随执行]').classList.contains('is-active')")
            print('PASS: HTML cards align with graph coordinates and drag with their edges; dragging pauses follow', flush=True)
            evaluate("document.querySelector('[aria-label=放大画布]').click()")
            before = evaluate(f"[...{cy}.nodes().map(n=>[n.id(),n.position()]),{cy}.zoom(),{cy}.pan()]")
            evaluate("window.__blackboardQA.graphRevision++; document.querySelector('[aria-label=同步画布]').click()")
            until("!document.querySelector('[aria-label=同步画布]').classList.contains('ant-btn-loading')")
            after = evaluate(f"[...{cy}.nodes().map(n=>[n.id(),n.position()]),{cy}.zoom(),{cy}.pan()]")
            assert before == after, 'Refresh changed the user view'
            evaluate(f"void {cy}.getElementById('fact:run-a:29').emit('tap')")
            until("document.querySelector('.execution-bundle-heading')?.textContent.includes('10')")
            evaluate("document.querySelector('.execution-bundle-heading button').click()")
            until(f"{cy}.nodes().length === 71")
            evaluate("document.querySelector('.execution-result-item').click()")
            until("document.querySelector('.execution-detail-scroll')?.textContent.includes('证据引用')")
            evaluate("[...document.querySelectorAll('.execution-detail-scroll button')].find(n=>n.textContent.includes('evidence-')).click()")
            until("document.querySelector('.ant-modal-body')?.textContent.includes('响应差异')")
            evaluate("document.querySelector('.ant-modal-confirm-btns button').click()")
            command('Emulation.setEmulatedMedia', features=[{'name':'prefers-reduced-motion','value':'reduce'}])
            time.sleep(.3)
            assert evaluate(f"{cy}.nodes().length") == 71
            evaluate("document.body.classList.add('light-theme')")
            time.sleep(.3)
            assert evaluate("getComputedStyle(document.querySelector('.execution-node-card.kind-intent')).backgroundColor") == 'rgb(255, 255, 255)'
            assert evaluate("getComputedStyle(document.querySelector('.execution-viewport')).backgroundImage.includes('radial-gradient')")
            assert evaluate("[...document.querySelectorAll('.execution-node-card.state-running')].every(n=>getComputedStyle(n).animationName === 'none')")
            command('Emulation.setDeviceMetricsOverride', width=1440, height=1000, deviceScaleFactor=1, mobile=False)
            time.sleep(.5)
            evaluate(f"void {cy}.center({cy}.nodes(':selected'))")
            time.sleep(.3)
            print('Canvas viewport:', evaluate(f"[{{width:{cy}.width(),height:{cy}.height(),zoom:{cy}.zoom(),pan:{cy}.pan()}},{cy}.nodes(':selected').renderedPosition()]"), flush=True)
            import base64
            (Path(__file__).parent / 'execution-canvas-desktop.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
            time.sleep(.4)
            assert evaluate("getComputedStyle(document.querySelector('.execution-list')).display") == 'flex'
            evaluate("[...document.querySelectorAll('.execution-mobile-tabs button')].find(n=>n.textContent==='画布').click()")
            time.sleep(.4)
            assert evaluate(f"{cy}.width() > 0")
            assert evaluate("document.documentElement.scrollWidth <= 390")
            assert evaluate(f"(() => {{ const b={cy}.nodes(':selected').renderedBoundingBox(); return b.x1 >= 0 && b.x2 <= {cy}.width() }})()"), 'Mobile selection is clipped'
            evaluate("document.querySelector('.execution-view').scrollIntoView({block:'start'})")
            time.sleep(.2)
            (Path(__file__).parent / 'execution-canvas-mobile.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            print('PASS: 300 items bundled; causal selection, evidence, viewport preservation, light theme, reduced motion and mobile', flush=True)
            command('Emulation.setDeviceMetricsOverride', width=1920, height=1000, deviceScaleFactor=1, mobile=False)
            def search(value):
                evaluate("(() => { const input=document.querySelector('.execution-list input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input," + json.dumps(value) + "); input.dispatchEvent(new Event('input',{bubbles:true})); })()")
            search('evidence-29-9')
            until(f"{cy}.nodes().length === 13")
            evaluate(f"void {cy}.getElementById('item:f29:f29:item-9').emit('tap')")
            until("document.querySelector('.execution-detail-scroll')?.textContent.includes('待验证')")
            search('分支 0')
            until(f"{cy}.nodes().length === 3")
            evaluate("document.querySelector('.execution-list-item').click(); document.querySelector('[aria-label=重新整理]').click(); document.querySelector('[aria-label=查看全图]').click()")
            time.sleep(.5)
            evaluate("document.querySelector('.execution-view').scrollIntoView({block:'start'})")
            (Path(__file__).parent / 'execution-canvas-overview.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            print('PASS: evidence search finds folded history and its complete source path; readable overview captured', flush=True)
            evaluate("window.__blackboardQA.presentation=true; document.querySelector('[aria-label=同步画布]').click()")
            search('')
            until("!document.querySelector('[aria-label=同步画布]').classList.contains('ant-btn-loading')")
            until(f"{cy}.nodes().length === 7")
            evaluate("document.querySelector('[aria-label=重新整理]').click()")
            time.sleep(.5)
            evaluate(f"void {cy}.getElementById('intent:run-a:1').emit('tap')")
            evaluate(f"void {cy}.stop().fit({cy}.elements(),35)")
            time.sleep(.3)
            (Path(__file__).parent / 'execution-canvas-preview.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            selected_card = evaluate("(() => {const r=document.querySelector('[data-node-id=\"intent:run-a:1\"]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()")
            old_zoom = evaluate(f"{cy}.zoom()")
            command('Input.dispatchMouseEvent', type='mouseWheel', deltaX=0, deltaY=-80, **selected_card)
            time.sleep(.2)
            assert evaluate(f"{cy}.zoom()") > old_zoom, 'Wheel over an HTML card does not zoom'
            evaluate("document.body.classList.remove('light-theme')")
            time.sleep(.2)
            assert evaluate("getComputedStyle(document.querySelector('.execution-node-card.kind-intent')).backgroundColor") == 'rgb(17, 22, 26)'
            (Path(__file__).parent / 'execution-canvas-dark.png').write_bytes(base64.b64decode(command('Page.captureScreenshot')['data']))
            print('PASS: reference card appearance in both themes; wheel zoom works over cards; representative branches captured', flush=True)
            evaluate("[...document.querySelectorAll('.session-item')].find(el => el.textContent.includes('run-b')).click()")
            until("document.querySelector('.execution-footer')?.textContent.includes('project-run-b')")
            until("document.querySelector('.execution-cytoscape canvas') !== null")
            assert evaluate('window.__blackboardQA.errors') == [], evaluate('window.__blackboardQA.errors')
            print('PASS: switching tasks recreates the canvas; no browser errors', flush=True)
            print(json.dumps({'graph_max_concurrency': evaluate('window.__blackboardQA.graphMax'), 'ledger_cursors': cursors}))
            command('Browser.close')
        finally:
            if connection:
                connection.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
