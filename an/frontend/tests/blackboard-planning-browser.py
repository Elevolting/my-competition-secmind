"""Browser check for dependency details using an isolated graph API fixture."""
import runpy
from pathlib import Path

EXTRA = """
const planningFetch = window.fetch;
window.fetch = async (input, options) => {
  const response = await planningFetch(input, options);
  const url = new URL(typeof input === 'string' ? input : input.url, location.origin);
  if (!url.pathname.endsWith('/blackboard-graph')) return response;
  const graph = await response.json();
  const first = graph.nodes.find(node => node.raw_id === 'i0');
  const second = graph.nodes.find(node => node.raw_id === 'i1');
  if (first && second) {
    first.step_id = 'A';
    first.validated_outputs = [];
    second.step_id = 'B';
    second.depends_on = ['A'];
    second.required_outputs = { A: ['session'] };
    second.blocked_reasons = ['A: missing verified outputs session'];
    second.status = 'waiting';
  }
  return new Response(JSON.stringify(graph), {status: response.status,
    headers: {'content-type': 'application/json'}});
};
"""


def checks(command, evaluate, until):
    until("[...document.querySelectorAll('.ant-segmented-item')].some(el => el.textContent.includes('探索路径'))")
    evaluate("[...document.querySelectorAll('.ant-segmented-item')]"
             ".find(el => el.textContent.includes('探索路径')).click()")
    until("document.querySelector('.execution-list-item')?.textContent.includes('A')")
    until("[...document.querySelectorAll('.execution-list-item')].some(el => el.textContent.includes('B'))")
    evaluate("[...document.querySelectorAll('.execution-list-item')].find(el => el.textContent.includes('B')).click()")
    until("document.querySelector('.execution-detail-scroll')?.textContent.includes('需要 session')")
    assert evaluate("document.querySelector('.execution-detail-scroll').textContent"
                    ".includes('missing verified outputs session')")
    evaluate("[...document.querySelectorAll('.execution-source-reference')]"
             ".find(el => el.textContent.includes('A')).click()")
    until("document.querySelector('.execution-detail-scroll')?.textContent.includes('A')")
    assert evaluate("document.querySelector('.execution-detail-scroll').textContent.includes('规划步骤')")
    command('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    until("document.querySelector('.execution-mobile-tabs button') !== null")
    evaluate("document.querySelector('.execution-mobile-tabs button').click()")
    until("[...document.querySelectorAll('.execution-list-item')].some(el => el.textContent.includes('B'))")
    assert evaluate('document.documentElement.scrollWidth <= 390')
    assert evaluate('window.__blackboardQA.errors.length === 0')
    print('PASS: dependency status, predecessor navigation, mobile queue and old task fixture')
    command('Browser.close')


if __name__ == '__main__':
    browser = runpy.run_path(str(Path(__file__).with_name('blackboard-browser.py')))
    browser['main'](fixture_extra=EXTRA, checks=checks)
