// Installed after the common mock API. No real target or task is created.
(() => {
  const previousFetch = window.fetch
  const qa = window.__assetQA = { fail:false, delay:40, revision:0, large:false, active:0, max:0, calls:0 }
  function makeGraph(runId) {
    const host = `auth.${runId}.test`, other = `other.${runId}.test`
    const provenance = (source, ref) => [{ source, ref, observed_at:'2026-10-13T01:20:00Z', confidence:source==='tool' ? .92 : null }]
    const node = (id,type,label,status='scoped',source='scope',ref='scope:1') => ({ id:`${runId}:${id}`, type,label,rawId:label,status, sources:[source],provenance:provenance(source,ref) })
    const nodes = [node('host','domain',host,'invoked','invocation','call-1'), node('other','domain',other), node('file','artifact','auth-routes.json','input','artifact','artifact-1')]
    const edges = []
    const serviceCount = qa.large ? 30 : 2
    for (let s=0; s<serviceCount; s++) {
      const serviceUrl = `https://${host}:${443+s}`
      const service = node(`s${s}`,'service',serviceUrl,s===0?'discovered':'scoped',s===0?'tool':'scope',s===0?'call-1':'scope:1')
      nodes.push(service); edges.push({ id:`${runId}:hs${s}`,source:`${runId}:host`,target:service.id,type:'serves',label:'服务于' })
      const count = qa.large ? 10 : s===0 ? 12 : 0
      for(let e=0;e<count;e++) {
        const path = e===0 ? '/login' : e===1 ? '/session' : `/route-${s}-${e}`
        const endpoint = node(`e${s}-${e}`,'endpoint',`${serviceUrl}${path}`,'discovered','tool','call-1')
        nodes.push(endpoint); edges.push({ id:`${runId}:se${s}-${e}`,source:service.id,target:endpoint.id,type:'exposes',label:'暴露' })
      }
    }
    if (qa.revision) nodes.find((n) => n.type==='domain').provenance.push({source:'scope',ref:`scope:revision-${qa.revision}`})
    return {schema_version:'1.0',run_id:runId,nodes,edges,calls:[{call_id:'call-1',status:'completed',tool:'http_probe',worker:'Worker-A',target_values:[`https://${host}:443/login`],completed_at:'2026-10-13T01:20:00Z'}],sources:{scope:2,invocation:1,tool:12,artifact:1},stats:{}}
  }
  window.fetch = async (input,options={}) => {
    const url = new URL(typeof input==='string' ? input : input.url,location.origin)
    if (!url.pathname.endsWith('/asset-graph')) return previousFetch(input,options)
    const runId = url.pathname.split('/')[4]
    qa.active++; qa.max=Math.max(qa.max,qa.active); qa.calls++
    try { await delay(qa.delay,options.signal) } finally { qa.active-- }
    return new Response(JSON.stringify(qa.fail ? {detail:'Mock asset sync failed'} : makeGraph(runId)),{status:qa.fail?503:200,headers:{'content-type':'application/json'}})
  }
})()
