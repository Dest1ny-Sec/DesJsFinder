// ============================================================
// Content — 注入页面,提取路径,发送background
// ============================================================
(function () {
  if (window.__apifuzzerRan) return; window.__apifuzzerRan = true
  const host = location.host, protocol = location.protocol, html = document.documentElement.outerHTML
  const tasks = [], apiFilter = new APIFilter(), fwDetect = new FrameworkDetect()

  // 收集外部JS URL
  document.querySelectorAll('script[src]').forEach(s => tasks.push(_normalize(s.src)))
  document.querySelectorAll('link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]').forEach(l => tasks.push(_normalize(l.href)))

  // 内联脚本 — 直接传文本不base64
  const inlineScripts = []
  document.querySelectorAll('script:not([src])').forEach(s => {
    if (s.textContent?.length > 100) inlineScripts.push(s.textContent)
  })

  // 从HTML和内联提取API
  let inlineAPIs = []
  inlineScripts.forEach(t => inlineAPIs.push(...apiFilter.extract(t)))
  inlineAPIs.push(...apiFilter.extract(html))
  const seen = new Set(), apiList = []
  for (const p of inlineAPIs) { if (!seen.has(p)) { seen.add(p); apiList.push({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }) } }

  // 框架
  let fw = fwDetect.detect(html)
  if (!fw.length) fw = fwDetect.detect(inlineScripts.join('\n')) || []

  // 配置
  let cfg = {}
  inlineScripts.forEach(t => Object.assign(cfg, fwDetect.extractConfig(t) || {}))

  // 表单
  const forms = [...document.querySelectorAll('input[name], select[name]')].map(e => e.name)

  function _normalize(u) {
    if (!u || u.startsWith('data:') || u.startsWith('blob:')) return u
    if (u.startsWith('//')) return protocol + u
    if (u.startsWith('/')) return protocol + '//' + host + u
    if (!u.startsWith('http')) { const b = location.href.split('#')[0]; return b.substring(0, b.lastIndexOf('/') + 1) + u }
    return u
  }

  chrome.runtime.sendMessage({
    action: 'passive',
    tasks: [...new Set(tasks.filter(Boolean))].slice(0, 20),
    inlineScripts: inlineScripts.slice(0, 5),
    apis: apiList.slice(0, 400),
    fw, cfg, forms: [...new Set(forms)],
    url: location.href, title: document.title
  })
})()
