import test from 'node:test'
import assert from 'node:assert/strict'
import { parseTargetUrls, targetScopeFor } from '../src/app/target-urls.js'

test('accepts the screenshot input as two separate HTTP targets', () => {
  const urls = parseTargetUrls('10.0.186.160:10086和10.0.186.160:22')
  assert.deepEqual(urls, ['http://10.0.186.160:10086/', 'http://10.0.186.160:22/'])
  assert.deepEqual(targetScopeFor({ targetScope: ' uploaded-source ' }, urls), [
    'uploaded-source', 'http://10.0.186.160:10086/', 'http://10.0.186.160:22/',
  ])
})

test('accepts line breaks, spaces and common list punctuation', () => {
  for (const separator of ['\n', '\r\n', ' ', ', ', '，', ';', '；', '、', '和']) {
    assert.deepEqual(parseTargetUrls(`10.0.0.1:8080${separator}https://lab.local/test`), [
      'http://10.0.0.1:8080/', 'https://lab.local/test',
    ])
  }
})

test('preserves URL paths, queries, fragments and punctuation', () => {
  const url = 'https://lab.local/a;b?q=x,y&next=a和b#result'
  assert.deepEqual(parseTargetUrls(url), [new URL(url).href])
  assert.deepEqual(parseTargetUrls('https://lab.local/%E5%92%8C?q=a%2Cb'), [
    'https://lab.local/%E5%92%8C?q=a%2Cb',
  ])
})

test('handles empty input, duplicate targets, localhost and IPv6', () => {
  assert.deepEqual(parseTargetUrls('  '), [])
  assert.deepEqual(parseTargetUrls('lab.local http://lab.local/'), ['http://lab.local/'])
  assert.deepEqual(parseTargetUrls('localhost:8080\n[::1]:3000'), [
    'http://localhost:8080/', 'http://[::1]:3000/',
  ])
  assert.deepEqual(targetScopeFor({}, []), [])
})

test('reports the failing entry in Chinese before submission', () => {
  assert.throws(() => parseTargetUrls('lab.local\n10.0.0.1:99999'), /第 2 个靶场网址无效：请检查主机和端口/)
  for (const invalid of ['ftp://lab.local', 'javascript:alert(1)', 'file:///tmp/test']) {
    assert.throws(() => parseTargetUrls(invalid), /仅支持 http 或 https 地址/)
  }
  for (const invalid of ['http://', 'http://10.0.0.1:abc', 'http://user:pass@lab.local', '/relative', 'http://lab.local\\path']) {
    assert.throws(() => parseTargetUrls(invalid), /第 1 个靶场网址无效/)
  }
  assert.throws(() => parseTargetUrls('https://lab.local/https://lab.local/'), /路径中包含另一个网址/)
})
