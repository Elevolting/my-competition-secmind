import test from 'node:test'
import assert from 'node:assert/strict'
import { assetDirectory, assetIndex, assetMapPositions, assetPath, focusRoot, projectAssetView, relatedCalls } from '../src/app/asset-graph-view.js'

function fixture(count = 12) {
  const nodes = [
    { id:'scope', type:'company', label:'业务系统' },
    { id:'h1', type:'domain', label:'auth.example.test', rawId:'auth.example.test', status:'invoked' },
    { id:'h2', type:'domain', label:'other.example.test' },
    { id:'s1', type:'service', label:'https://auth.example.test' },
    { id:'file', type:'artifact', label:'routes.json', status:'input' },
  ]
  const edges = [{ id:'scope1', source:'scope', target:'h1' }, { id:'scope2', source:'scope', target:'h2' }, { id:'service', source:'h1', target:'s1' }]
  for (let i=0; i<count; i++) {
    nodes.push({ id:`e${i}`, type:'endpoint', label:`https://auth.example.test/route-${i}`, status:'discovered' })
    edges.push({ id:`r${i}`, source:'s1', target:`e${i}` })
  }
  return { nodes, edges }
}

test('focus includes explicit ancestry, isolates sibling hosts, and never invents file links', () => {
  const graph = fixture(), index = assetIndex(graph)
  assert.equal(focusRoot(index, 'e0'), 'h1')
  const view = projectAssetView(graph, 'h1')
  assert.deepEqual(view.nodes.map((n) => n.id).sort(), ['bundle:s1','h1','s1','scope'])
  assert.equal(view.hiddenCount, 12)
  const fileView = projectAssetView(graph, 'file')
  assert.deepEqual(fileView.nodes.map((n) => n.id), ['file'])
  assert.deepEqual(fileView.edges, [])
})

test('all folded endpoints remain searchable, and selecting one restores its real branch', () => {
  const graph = fixture(300)
  assert.equal(projectAssetView(graph, 'h1').nodes.length, 4)
  assert.equal(assetDirectory(graph, 'route-299')[0].id, 'e299')
  const view = projectAssetView(graph, 'h1', [], 'e299')
  assert.equal(view.hiddenCount, 0)
  assert.equal(view.nodes.length, 303)
  assert.deepEqual(assetPath(assetIndex(graph), 'e299').map((n) => n.id), ['scope','h1','s1','e299'])
  assert.equal(assetDirectory(graph, '', 'discovered').length, 300)
})

test('shared endpoints remain visible through an expanded parent, dangling edges and cycles are safe', () => {
  const graph = fixture(6)
  graph.nodes.push({ id:'s2', type:'service', label:'http://auth.example.test' })
  graph.edges.push({ id:'s2', source:'h1', target:'s2' }, { id:'shared', source:'s2', target:'e0' }, { id:'dangling', source:'missing', target:'e0' })
  const view = projectAssetView(graph, 'h1')
  assert(view.nodes.some((n) => n.id === 'e0'))
  assert.equal(view.hiddenCount, 5)
  assert(view.edges.some((e) => e.id === 'shared'))
  assert(!view.edges.some((e) => e.id === 'dangling'))
  graph.edges.push({ id:'cycle', source:'s2', target:'h1' })
  assert(assetPath(assetIndex(graph), 's2').length <= graph.nodes.length)
  assert(projectAssetView(graph, 'h1').nodes.length < graph.nodes.length + 2)
})

test('tool calls match host boundaries, origins and case-sensitive endpoint paths', () => {
  const calls = [
    { call_id:'yes', target_values:['https://auth.example.test/login?next=a'] },
    { call_id:'suffix', target_values:['https://auth.example.test.evil.test/login'] },
    { call_id:'prefix', target_values:['https://notauth.example.test/login'] },
    { call_id:'case', target_values:['https://auth.example.test/Login?next=a'] },
    { call_id:'other-origin', target_values:['http://auth.example.test/login?next=a'] },
  ]
  assert.deepEqual(relatedCalls({ type:'domain', rawId:'auth.example.test' }, calls).map((c) => c.call_id), ['yes','case','other-origin'])
  assert.deepEqual(relatedCalls({ type:'service', rawId:'https://auth.example.test' }, calls).map((c) => c.call_id), ['yes','case'])
  assert.deepEqual(relatedCalls({ type:'endpoint', rawId:'https://auth.example.test/login?next=a' }, calls).map((c) => c.call_id), ['yes'])
})

test('selecting a shared endpoint includes every explicit upstream host without sibling branches', () => {
  const graph = fixture(6)
  graph.nodes.push({id:'remote-service',type:'service',label:'https://other.example.test'})
  graph.edges.push({id:'remote-host',source:'h2',target:'remote-service'}, {id:'remote-ref',source:'remote-service',target:'e0'})
  const view = projectAssetView(graph, 'h1', [], 'e0')
  assert(view.nodes.some((node) => node.id === 'h2'))
  assert(view.nodes.some((node) => node.id === 'remote-service'))
  assert(view.edges.some((edge) => edge.id === 'remote-ref'))
  assert(view.nodes.every((node) => node.type !== 'artifact'))
})

test('old nodes without status, empty graphs and unknown selections remain readable', () => {
  assert.equal(focusRoot(assetIndex({nodes:[]}), 'unknown'), null)
  assert.deepEqual(projectAssetView({ nodes:[], edges:[] }, null).nodes, [])
  const graph = { nodes:[{ id:'old', type:'domain', label:'legacy.test' }], edges:[] }
  assert.equal(projectAssetView(graph, 'missing').root, 'old')
  assert.equal(assetDirectory(graph, 'legacy').length, 1)
})

test('map layout is deterministic with reordered data, cycles and shared references', () => {
  const graph = fixture(12)
  graph.edges.push({ id:'cycle', source:'e0', target:'h1' }, { id:'shared', source:'h2', target:'e1' })
  const positions = assetMapPositions(graph.nodes, graph.edges, 'h1')
  const reordered = assetMapPositions([...graph.nodes].reverse(), [...graph.edges].reverse(), 'h1')
  assert.deepEqual([...positions].sort(), [...reordered].sort())
  assert.deepEqual(positions.get('h1'), { x:0, y:0 })
  assert.equal(positions.size, graph.nodes.length)
  assert([...positions.values()].every(({ x,y }) => Number.isFinite(x) && Number.isFinite(y)))
  const points = [...positions.values()]
  for (let i = 0; i < points.length; i++) for (let j = i + 1; j < points.length; j++) {
    assert(Math.abs(points[i].x - points[j].x) >= 166 || Math.abs(points[i].y - points[j].y) >= 104, 'Labels collide')
  }
})

test('expanding and discovering assets preserves dragged positions and only places new nodes', () => {
  const graph = fixture(300), folded = projectAssetView(graph, 'h1')
  const before = assetMapPositions(folded.nodes, folded.edges, 'h1')
  before.set('h1', { x:123, y:-45 })
  before.set('s1', { x:456, y:200 })
  const expanded = projectAssetView(graph, 'h1', ['s1'])
  const after = assetMapPositions(expanded.nodes, expanded.edges, 'h1', before)
  for (const [id, position] of before) if (after.has(id)) assert.deepEqual(after.get(id), position)
  assert.equal(after.size, expanded.nodes.length)
  assert(!after.has('bundle:s1'))
  assert.deepEqual(assetMapPositions([], [], null), new Map())
})
