// ============================================================
// DesJsFinder Popup — 红队实战优化版
// ============================================================
let data = {}, fuzzing = false, fuzzRes = [], total = 0, timer = 0, activeTab = 'apis'
let _fuzzGen = 0 // 每次启动 fuzz 自增, 用于 in-flight callback 判定 stale, 避免清空/重启后旧请求污染
let proxyUrl = '', proxyEnabled = false, fwExploits = {}, fwKeyMap = {}

// 第三方域名列表（用于过滤）
const THIRD_PARTY_DOMAINS = [
  'google-analytics.com','googletagmanager.com','doubleclick.net','googleadservices.com',
  'baidu.com','hm.baidu.com',
  'facebook.net','fbcdn.net','facebook.com',
  'hotjar.com','mouseflow.com','crazyegg.com','fullstory.com',
  'newrelic.com','datadoghq.com','sentry.io','bugsnag.com',
  'mixpanel.com','amplitude.com','segment.com',
  'hubspot.com','marketo.com','pardot.com','eloqua.com',
  'addthis.com','sharethis.com','addtoany.com',
  'livechatinc.com','zendesk.com','intercom.io','intercomcdn.com',
  'cloudflare.com','cdnjs.cloudflare.com','jsdelivr.net','unpkg.com',
  'polyfill.io','bootstrapcdn.com','stackpath.bootstrapcdn.com',
  'jquery.com','code.jquery.com','ajax.googleapis.com',
  'cnzz.com','51.la','tongji.linezing.com','ta.qq.com',
  'bytedance.com','bytecdn.cn','zijieapi.com','bytednsdoc.com','pstatp.com',
  'baidustatic.com','bdstatic.com','bdimg.com',
  'github.com','githubusercontent.com','github.io',
  'amazonaws.com','cloudfront.net',
  'akamai.net','akamaiedge.net','akamai.com',
  'cloudfront.com',
  'crisp.live','tawk.to','drift.com','intercom.io',
  'segment.io','mparticle.jp',
  'newrelic.com','nr-data.net',
  'appsflyer.com','adjust.com','branch.io',
  'onesignal.com','pusher.com','socket.io',
  'firebase.com','googleapis.com','gstatic.com',
  'doubleclick.net','googlesyndication.com',
  'taboola.com','outbrain.com','criteo.com',
  'scorecardresearch.com','quantserve.com',
  'facebook.com','fbcdn.net','instagram.com','tiktok.com',
  'linkedin.com','twitter.com','x.com',
  'youtube.com','ytimg.com','googlevideo.com',
  'vimeo.com','dailymotion.com',
  'twimg.com','cdntwitter.com',
  'wix.com','squarespace.com','webflow.io',
  'shopify.com','bigcommerce.com','magento.com',
  'wordpress.com','wp.com','automattic.com',
  'cloudflareinsights.com',
  'browser-intake-datadoghq.com','browser-datadoghq.com',
  'analytics.google.com','stats.g.doubleclick.net',
  'adservice.google.com','pagead2.googlesyndication.com',
  'securepubads.g.doubleclick.net',
  'spother.top', 'spother.com',
  'xiaomi.com', 'miniapps.xxx',
]

function isThirdParty(url) {
  if (!url) return false
  try {
    const hostname = new URL(url).hostname
    for (const d of THIRD_PARTY_DOMAINS) {
      if (hostname === d || hostname.endsWith('.' + d)) return true
    }
  } catch(e) {}
  return false
}

chrome.storage.local.get(['proxyUrl', 'proxyEnabled'], r => {
  proxyUrl = r.proxyUrl || ''; proxyEnabled = r.proxyEnabled === true
})

// ====== 秒开缓存 ======
chrome.storage.local.get(['lastData', 'lastFuzzRes', 'lastFuzzTotal', 'fuzzTruncated', 'fuzzTruncatedCount'], r => {
  if (r.lastData?.apis?.length) { data = r.lastData; render(); updateBar() }
  if (r.lastFuzzRes?.length) { fuzzRes = r.lastFuzzRes; total = r.lastFuzzTotal || 0 }
  if (r.fuzzTruncated && r.fuzzTruncatedCount) {
    showTip(`上次Fuzz结果已截断: 显示200/${r.fuzzTruncatedCount}条`)
  }
  // always default to APIs tab, even if saved fuzz results exist
})

// ====== Tab 切换 ======
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => {
    x.classList.remove('active')
    x.setAttribute('aria-selected', 'false')
  })
  t.classList.add('active')
  t.setAttribute('aria-selected', 'true')
  activeTab = t.dataset.tab
  render()
})

// ====== 后台轮询 ======
function refresh() {
  if (fuzzing) return
  chrome.runtime.sendMessage({action:'getData'}, d => {
    if (!d) return
    const fields = ['apis','domains','ips','jwts','creds','storageItems','runtimeReqs','params']
    if (!fields.some(k => (d[k]||[]).length) && !(d.fw||[]).length) return
    if (d.fwExploits) fwExploits = d.fwExploits
    if (d.fwKeyMap) fwKeyMap = d.fwKeyMap
    data = d
    data.tabId = data.tabId || d.tabId
    chrome.storage.local.set({ lastData: data })
    // auto-fill captured token
    if (d.capturedToken && !document.getElementById('hdrs').value) {
      document.getElementById('hdrs').value = d.capturedToken
      showTip('截获认证头，已自动填入')
    }
    updateBar()
    render()
  })
}
refresh(); timer = setInterval(refresh, 1500)

// ====== 顶栏更新 ======
function updateBar() {
  document.getElementById('apiC').textContent = (data.apis||[]).length
  // 最多显示 2 个框架标签
  const fwNames = [...new Set((data.fw||[]).map(f => f.name))]
  const shown = fwNames.slice(0, 2)
  const more = fwNames.length - 2
  document.getElementById('fwT').innerHTML = shown.map(n => `<span class="fw">${n}</span>`).join('') +
    (more > 0 ? `<span class="fw" style="opacity:.5">+${more}</span>` : '')
  const dot = document.getElementById('statusDot')
  if (dot) dot.className = 'dot' + (data.processing ? '' : ' idle')
  if (data.apis?.length && !fuzzing) {
    const est = Math.min(data.apis.length * 3 + 150, 500)
    document.getElementById('fuzzPreview').textContent = '~' + est + '条'
  }
}

// ====== 渲染 ======
const TABS = [
  { key: 'apis', label: '接口', isApi: true },
  { key: 'runtimeReqs', label: '实时', isRuntime: true },
  { key: 'secrets', label: '凭据' },
]

function renderSecrets() {
  const c = document.getElementById('tab-content')
  const all = [
    ...(data.creds||[]).map(v => ({ tag: 'CRED', val: Array.isArray(v)?v[0]:v })),
    ...(data.jwts||[]).map(v => ({ tag: 'JWT', val: Array.isArray(v)?v[0]:v })),
    ...(data.storageItems||[]).map(v => ({ tag: 'STORE', val: typeof v === 'string'?v:'' })),
  ]
  if (!all.length) { c.innerHTML = '<div class="empty">暂无数据 — 浏览目标时自动收集</div>'; return }
  let html = '<div class="section"><div class="section-hdr"><span>凭据 <b>'+all.length+'</b></span><button class="cp-all" data-key="secrets">复制全部</button></div><div class="list">'
  for (const item of all) {
    html += `<div class="row" data-val="${esc(item.val||'')}">
      <span class="method" style="color:var(--amber)">${item.tag}</span>
      <span class="path mono">${esc(String(item.val||'').substring(0,180))}</span>
    </div>`
  }
  html += '</div></div>'
  c.innerHTML = html
  // 凭据 tab 的 cp-all 行为: 复制 val 列表 (不走通用 copyAllByKey, 因为这里 val 来自混合 creds/jwts/storageItems)
  c.querySelector('.cp-all')?.addEventListener('click', e => {
    e.stopPropagation()
    const text = all.map(x => x.val).filter(Boolean).join('\n')
    if (text) { navigator.clipboard.writeText(text).catch(() => {}); showTip('已复制全部') }
  })
}

// ====== 参数 Tab (采纳 ParamX: JS 参数提取 + 构造请求) ======
function renderParams() {
  const c = document.getElementById('tab-content')
  const items = (data.params || []).slice(0, 800)
  if (!items.length) { c.innerHTML = '<div class="empty">暂无参数 — 浏览目标时自动从 JS 提取（对象属性/解构/函数参数/URL参数/路由参数等）</div>'; return }
  const prioColor = { 5: 'var(--red)', 4: 'var(--amber)', 3: 'var(--blue)', 2: 'var(--grn)', 1: 'var(--dim)' }
  const cats = {}
  for (const p of items) cats[p.category] = (cats[p.category] || 0) + 1

  let html = `<div class="section"><div class="section-hdr"><span>参数 <b>${items.length}</b></span>
    <button id="btnJsonBody" style="padding:2px 8px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--dim);cursor:pointer;font-size:9px">构造JSON</button>
    <button id="btnGetQuery" style="padding:2px 8px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--dim);cursor:pointer;font-size:9px">构造GET</button>
    <button class="cp-all" data-key="params">复制全部</button></div>
    <div class="cfg-desc">${Object.entries(cats).map(([k, v]) => `<span style="margin-right:6px">${k}:<b>${v}</b></span>`).join('')} — 点击行复制参数名</div><div class="list">`
  for (const p of items) {
    html += `<div class="row" data-val="${esc(p.value)}" title="来源: ${esc(p.source)} | 分类: ${esc(p.category)}">
      <span class="method" style="color:${prioColor[p.priority] || 'var(--dim)'};font-weight:700;min-width:24px">P${p.priority}</span>
      <span class="path mono">${esc(p.value)}</span>
      <span class="badge ${p.priority >= 4 ? 'b-HIGH' : (p.priority >= 2 ? 'b-MEDIUM' : 'b-INFO')}">${esc(p.category)}</span>
      <span class="lbl" style="min-width:auto;font-size:8px;color:var(--dim)">${esc(p.source)}</span>
    </div>`
  }
  html += '</div></div>'
  c.innerHTML = html
  // 事件委托 (cp-all / row click) 已在脚本顶部绑好, 这里只处理 params tab 专属的"构造 JSON/GET" 按钮

  const isId = (p) => p.category === 'identifier' || p.value.toLowerCase().includes('id')
  const buildJson = () => {
    const obj = {}
    items.forEach(p => { obj[p.value] = isId(p) ? 1 : '1' })
    return JSON.stringify(obj, null, 2)
  }
  const buildGet = () => items.map(p => `${p.value}=1`).join('&')
  const btnJson = c.querySelector('#btnJsonBody')
  if (btnJson) btnJson.onclick = (e) => {
    e.stopPropagation()
    const text = buildJson()
    navigator.clipboard.writeText(text).catch(()=>{})
    showTip(`已复制JSON body (${items.length}参数, ${text.length}字符)`)
  }
  const btnGet = c.querySelector('#btnGetQuery')
  if (btnGet) btnGet.onclick = (e) => {
    e.stopPropagation()
    const text = buildGet()
    const warn = text.length > 5000 ? ' 超长(GET可能被截断)' : (text.length > 2000 ? ' 较长' : '')
    navigator.clipboard.writeText(text).catch(()=>{})
    showTip(`已复制GET参数 (${items.length}参数, ${text.length}字符${warn})`)
  }
}

function render() {
  const c = document.getElementById('tab-content')
  if (!c) return
  if (activeTab === 'fuzz') { renderFuzz(); return }
  if (activeTab === 'fingerprint') { renderFingerprint(); return }
  if (activeTab === 'config') { renderConfig(); return }
  if (activeTab === 'secrets') { renderSecrets(); return }
  if (activeTab === 'params') { renderParams(); return }

  let html = ''
  for (const def of TABS) {
    if (activeTab !== def.key) continue
    const raw = data[def.key] || []
    const items = def.isApi ? raw.filter(x => x && x.path) : (def.isRuntime ? raw.filter(x => x && x.url) : raw)
    if (!items.length) { html += '<div class="empty">浏览目标时自动收集</div>'; continue }

    html += `<div class="section"><div class="section-hdr"><span>${def.label} <b>${items.length}</b></span><input class="tab-search" placeholder="过滤..." style="width:100px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:2px 6px;font-size:9px;border-radius:3px"><button class="cp-all" data-key="${def.key}">复制全部</button></div><div class="list">`
    for (const item of items) {
      if (def.isApi) {
        const risk = item.classify?.risk || 'INFO'
        // cross-ref fuzz results: show status if this path was tested
        const fr = fuzzRes.find(r => {
          try { return new URL(r.url).pathname === item.path } catch(e) { return r.url === item.path }
        })
        let fuzzTag = ''
        if (fr && fr.status !== 404 && fr.status !== 0 && fr.status !== 501) {
          const s = fr.status; const cls = s >= 200 && s < 300 ? 's-2xx' : (s >= 400 ? 's-4xx' : 's-3xx')
          fuzzTag = `<span class="${cls}" style="font-size:9px;font-weight:600;margin-right:4px">${s}</span>`
        }
        html += `<div class="row api-row" data-val="${esc(item.path)}" data-src="">
          <span class="path mono">${esc(item.path)}</span>
          <span class="badge b-${risk}">${esc(item.classify?.label||'API')}</span>
          <span class="method">${esc(item.method)}</span>
          ${fuzzTag}
        </div>`
      } else if (def.isRuntime) {
        const r = item
        let path = r.url || '', query = ''
        try { const u = new URL(r.url); path = u.pathname; query = u.search } catch(e) {}
        const hasParams = query.length > 1
        const display = hasParams ? path + '?' + query.substring(1, 50) + (query.length > 50 ? '...' : '') : path
        const preview = (r.respBody||'').slice(0, 200)
        html += `<div class="row rt-row" data-val="${esc(r.url)}" title="${esc(preview)}">
          <span class="s-${~~((r.status||200)/100)}xx">${r.status||'?'}</span>
          <span class="method">${esc(r.method)}</span>
          <span class="path mono">${esc(display)}</span>
        </div>`
      } else {
        const val = Array.isArray(item) ? item[0] : (typeof item === 'string' ? item : '')
        const src = Array.isArray(item) ? (item[1]||'') : ''
        html += `<div class="row" data-val="${esc(val)}" data-src="${esc(src)}" title="来源: ${esc(src)}">
          <span class="path mono">${esc(String(val).substring(0,120))}</span>
        </div>`
      }
    }
    html += '</div></div>'
  }
  c.innerHTML = html || '<div class="empty">选择 Tab 查看</div>'
  // 事件委托 (cp-all / row click) 已在脚本顶部绑好
  // tab search
  c.querySelectorAll('.tab-search').forEach(inp => {
    inp.oninput = () => {
      const q = inp.value.toLowerCase()
      c.querySelectorAll('.row').forEach(el => { el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none' })
    }
  })
}

// 事件委托: tab-content 容器上绑一次 click/contextmenu, render 时不再 rebind
// fuzz-row 走自己的显式绑定 (toggle panel), 这里用 closest 排除避免双触发
;(function bindDelegatedEvents() {
  const c = document.getElementById('tab-content')
  if (!c) return
  const copyVal = (val) => {
    if (!val) return
    navigator.clipboard.writeText(val).catch(() => {})
    showTip('已复制')
  }
  const copyAllByKey = (key) => {
    let text
    if (key === 'apis') text = (data[key] || []).map(a => a.path).join('\n')
    else if (key === 'runtimeReqs') text = (data[key] || []).map(r => r.url).join('\n')
    else if (key === 'params') text = (data[key] || []).map(x => x.value || '').filter(Boolean).join('\n')
    else text = (data[key] || []).map(x => Array.isArray(x) ? x[0] : (typeof x === 'string' ? x : '')).filter(Boolean).join('\n')
    if (!text) return
    navigator.clipboard.writeText(text).catch(() => {})
    showTip('已复制全部')
  }
  c.addEventListener('click', e => {
    const cp = e.target.closest('.cp-all')
    if (cp) { e.stopPropagation(); copyAllByKey(cp.dataset.key); return }
    const row = e.target.closest('.row')
    if (!row) return
    // fuzz-row / fuzz 内联自己处理 (toggle panel, copyHits 等), 避免双触发
    if (row.classList.contains('fuzz-row')) return
    if ((e.ctrlKey || e.metaKey) && row.dataset.src?.startsWith('http')) {
      chrome.tabs.create({ url: row.dataset.src })
    } else {
      copyVal(row.dataset.val)
    }
  })
  c.addEventListener('contextmenu', e => {
    const row = e.target.closest('.row')
    if (!row || !row.dataset.val) return
    if (row.classList.contains('fuzz-row')) return  // fuzz-row 不接管右键
    e.preventDefault()
    copyVal(row.dataset.val)
  })
})()

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') }

// ====== Fuzz ======
document.getElementById('btnFuzz').onclick = () => {
  if (fuzzing) {
    fuzzing = false
    const btn = document.getElementById('btnFuzz')
    btn.textContent = 'FUZZ'; btn.classList.remove('running')
    removeProxy()
    const totalResults = fuzzRes.length
    chrome.storage.local.set({ lastFuzzRes: fuzzRes.slice(0, 200), lastFuzzTotal: total, fuzzTruncated: totalResults > 200, fuzzTruncatedCount: totalResults })
    refresh()
    if (!timer) timer = setInterval(refresh, 1500)
    return
  }
  fuzzing = true; fuzzRes = []; total = 0; _fuzzFilter = 'hit'; _expandedPanels.clear()
  _fuzzGen++; const myGen = _fuzzGen  // 新的 fuzz session, 旧 session 的 in-flight 回调将被丢弃
  let idx = 0, running = 0
  const btn = document.getElementById('btnFuzz')
  btn.textContent = '停止'; btn.classList.add('running')
  document.getElementById('fuzzPreview').textContent = ''
  applyProxy()
  document.querySelector('[data-tab="fuzz"]')?.click()
  if (timer) { clearInterval(timer); timer = null }

  const h = {}, hr = document.getElementById('hdrs').value.trim()
  if (hr) hr.split('\n').forEach(l => { const i = l.indexOf(':'); if (i > 0) h[l.slice(0,i).trim()] = l.slice(i+1).trim() })
  const base = data.url ? new URL(data.url).origin : ''
  // extract real param keys from runtime URLs
  const runtimeParams = new Set()
  for (const r of (data.runtimeReqs||[])) {
    try { new URL(r.url).searchParams.forEach((_, k) => runtimeParams.add(k)) } catch(e) {}
  }
  // filter static files from API list before generating dict
  const staticFileRe = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|rar|mp[34]|webm|wasm)(\?.*)?$/i
  const cleanPaths = (data.apis||[]).filter(a => !staticFileRe.test(a.path)).map(a => a.path)
  const useGeneric = document.getElementById('useGenericDict')?.checked || false
  // 采纳 ParamX: 把提取的 JS 参数并入 POST body 参数集 (高优先级优先), 用于 update/create 类接口的 body Fuzz
  const extractedParams = (data.params || []).filter(p => p.priority >= 3).map(p => p.value)
  const bodyParams = [...new Set([...(data.bodyParams || []), ...extractedParams])]
  const dict = DictGenerator.generate(data.fw||[], cleanPaths, base, [...runtimeParams], bodyParams, !useGeneric)
  // prioritize: discovered + inferred paths first, then frameworks, then generic
  const dedup = []
  const s = new Set()
  const isGeneric = (u) => u.startsWith('/login') || u.startsWith('/sign') || u.startsWith('/register') || u.startsWith('/actuator') || u.startsWith('/.git') || u.startsWith('/.env') || u.startsWith('/robots') || u.startsWith('/admin/') || u.startsWith('/api/v')
  const priority = (u) => {
    // 修复: u.startsWith(a.path) 太宽, /api/v1/users/list 会匹配到 /api → fuzzy 全被当 discovered
    // 改为要求 / 边界, 即 a.path 必须是 u 的完整前缀段
    if ((data.apis||[]).some(a => {
      if (a.path === u) return true
      const prefix = a.path.endsWith('/') ? a.path : a.path + '/'
      return u.startsWith(prefix)
    })) return 0 // discovered
    if (isGeneric(u)) return 2 // generic dict last
    return 1 // inferred / framework
  }
  dict.sort((a,b) => priority(a.url) - priority(b.url))
  dict.forEach(d => { const k = d.url+d.method; if (!s.has(k)&&dedup.length<500) { s.add(k); dedup.push(d) } })
  total = dedup.length

  // show dict breakdown
  const disc = dedup.filter(d => priority(d.url) === 0).length
  const infr = dedup.filter(d => priority(d.url) === 1).length
  const genr = dedup.filter(d => priority(d.url) === 2).length
  document.getElementById('fuzzPreview').textContent = `发现${disc} + 推断${infr} + 通用${genr}`

  const rate = document.getElementById('fuzzRate')?.value || 'normal'
  // 速率档位: 慢 1 并发+400ms, 常 3 并发+200ms, 快 5 并发+100ms
  const rateCfg = { slow: [1, 400], normal: [3, 200], fast: [5, 100] }
  const [MAX_CONC, REQ_DELAY] = rateCfg[rate] || rateCfg.normal
  function pump() {
    while (running < MAX_CONC && idx < dedup.length && fuzzing) {
      const req = dedup[idx++]; running++
      const sendReq = (retry) => {
        chrome.runtime.sendMessage({ action: 'fuzz', url: base+req.url, method: req.method, headers: {...h, _tabId: data.tabId} }).then(r => {
          // stale check: 用户在 in-flight 期间清空或重启 fuzz, gen 已变更 → 静默丢弃
          if (_fuzzGen !== myGen) { running--; return }
          // retry network errors once
          if (r.status === 0 && retry) { setTimeout(() => sendReq(false), 200); return }
          fuzzRes.push(r); running--
          renderFuzz()
          setTimeout(pump, REQ_DELAY)
        }).catch(() => {
          if (_fuzzGen !== myGen) { running--; return }
          running--; setTimeout(pump, REQ_DELAY)
        })
      }
      sendReq(true)
    }
    // 收尾: 仅在仍是当前 session 且仍在 fuzzing 时执行, 避免 stale 后空 finalize
    if (idx >= dedup.length && running === 0 && fuzzing && _fuzzGen === myGen) {
      fuzzing = false
      const b = document.getElementById('btnFuzz')
      b.textContent = 'FUZZ'; b.classList.remove('running')
      removeProxy(); renderFuzz()
      const totalResults = fuzzRes.length
      chrome.storage.local.set({ lastFuzzRes: fuzzRes.slice(0, 200), lastFuzzTotal: total, fuzzTruncated: totalResults > 200, fuzzTruncatedCount: totalResults })
      if (!timer) timer = setInterval(refresh, 1500)
    }
  }
  pump()
}

let _expandedPanels = new Set()
let _fuzzDebounce = null
function renderFuzz() {
  if (_fuzzDebounce) clearTimeout(_fuzzDebounce)
  _fuzzDebounce = setTimeout(_renderFuzzNow, 80)
}
let _fuzzFilter = 'hit'
function _renderFuzzNow() {
  const c = document.getElementById('tab-content')
  if (!c || activeTab !== 'fuzz') return

  const ok = fuzzRes.filter(r => r.status !== 404 && r.status !== 0 && r.status !== 501)
  let list = ok
  if (_fuzzFilter === '2xx') list = ok.filter(r => r.status >= 200 && r.status < 300)
  else if (_fuzzFilter === '3xx') list = ok.filter(r => r.status >= 300 && r.status < 400)
  else if (_fuzzFilter === '403') list = ok.filter(r => r.status === 403 || r.status === 401)
  else if (_fuzzFilter === '4xx') list = ok.filter(r => r.status >= 400 && r.status < 500)
  else if (_fuzzFilter === '5xx') list = ok.filter(r => r.status >= 500 && r.status < 600)
  else if (_fuzzFilter === 'hit') list = ok
  const cnt403 = ok.filter(r => r.status === 403 || r.status === 401).length

  // SPA detection: ≥3 different paths returning identical HTML → SPA catch-all
  const bodyHash = (r) => (r.body||'').slice(0, 300).replace(/\s/g, '').replace(/<title>[^<]+<\/title>/i, '')
  const hashCount = new Map()
  for (const r of ok) {
    if ((r.contentType||'').includes('html') && r.status === 200) {
      const h = bodyHash(r); hashCount.set(h, (hashCount.get(h)||0) + 1)
    }
  }
  const spaHashes = new Set()
  hashCount.forEach((n, h) => { if (n >= 3) spaHashes.add(h) })
  const spaHitCount = ok.filter(r => spaHashes.has(bodyHash(r))).length
  const isSPA = spaHashes.size > 0

  let html = `<div class="section"><div class="section-hdr" style="gap:6px">
    <span>${fuzzing ? '探测中 ' + fuzzRes.length + '/' + total : '完成'} | 命中 <b>${ok.length}</b> | 需鉴权 <b>${cnt403}</b>${isSPA ? ' <span style="color:var(--amber);font-size:9px">SPA路由'+spaHitCount+'个</span>' : ''}</span>
    ${['hit','all','2xx','3xx','403','4xx','5xx'].map(v => {
      const labels = {hit:'非404',all:'全部','2xx':'2xx','3xx':'3xx','403':'401/3','4xx':'4xx','5xx':'5xx'}
      const counts = {hit:ok.length,all:ok.length,'2xx':ok.filter(r=>r.status>=200&&r.status<300).length,'3xx':ok.filter(r=>r.status>=300&&r.status<400).length,'403':cnt403,'4xx':ok.filter(r=>r.status>=400&&r.status<500).length,'5xx':ok.filter(r=>r.status>=500&&r.status<600).length}
      const active = _fuzzFilter === v ? 'font-weight:600;color:#fff;background:var(--border-glow)' : ''
      return `<span class="fuzz-filter-btn" data-v="${v}" style="cursor:pointer;font-size:9px;padding:2px 5px;border-radius:3px;${active}">${labels[v]}(${counts[v]})</span>`
    }).join(' ')}
    <button id="copyHits" style="padding:2px 8px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--dim);cursor:pointer;font-size:9px">复制命中</button>
  </div><div class="list">`
  // merge same URL + same status → single row with combined methods
  const merged = []; const mergeSeen = new Set()
  for (const r of list) {
    const key = r.url + '|' + r.status
    if (mergeSeen.has(key)) {
      const existing = merged.find(x => x._key === key)
      if (existing && !existing._methods.includes(r.method)) existing._methods.push(r.method)
      continue
    }
    mergeSeen.add(key); r._key = key; r._methods = [r.method]
    merged.push(r)
  }
  merged.sort((a,b) => a.status - b.status).forEach((r, i) => {
    // 修复 method 标签: 原 method 突出, 错配 method 用小灰字 "+POST" 形式, 不再 "GET POST" 平铺误导
    const primaryMethod = r._methods[0]
    const extraMethods = r._methods.slice(1)
    const methodHtml = extraMethods.length
      ? `<b style="color:var(--bright)">${esc(primaryMethod)}</b><span style="color:var(--dim);font-size:8px;margin-left:2px">+${extraMethods.map(esc).join('/')}</span>`
      : esc(primaryMethod)
    const fp = r.fp?.type || '-'
    const rid = 'p' + i // stable ID based on position
    const wasOpen = _expandedPanels.has(rid)
    const needAuth = r.status === 401 || r.status === 403
    const ct = (r.contentType || '').toLowerCase()
    const ctLabel = ct.includes('json') ? 'JSON' : (ct.includes('html') ? 'HTML' : (r.size < 100 ? 'TINY' : ''))
    // highlight valuable responses
    const body = (r.body || '').toLowerCase()
    const isSpaHit = spaHashes.has(bodyHash(r))
    const hasSensitive = /"(?:user|pass|token|data|list|phone|email|name|id|role|perm|admin|secret|key|code|mobile)"/i.test(body) || /\b(?:成功|用户|密码|权限|数据)\b/.test(body)
    const sensitiveLabel = hasSensitive && !isSpaHit ? 'DATA' : ''
    // 修复 URL 截断: title 给完整 URL (hover 看), path 字号 9px 让 mono 多塞 5-8 字符
    html += `<div class="row fuzz-row${wasOpen?' sel':''}" data-rid="${rid}" title="${esc(r.url)}  ${primaryMethod}${extraMethods.length?' / '+extraMethods.join('/'):''}">
      <span class="s-${~~(r.status/100)}xx">${r.status||'E'}</span>
      <span class="method" style="min-width:32px">${methodHtml}</span>
      <span class="path mono" style="font-size:9px">${esc(r.url)}</span>
      ${isSpaHit ? '<span style="font-size:8px;color:var(--text-dim);background:rgba(94,109,140,.12);padding:1px 5px;border-radius:6px">SPA</span>' : ''}
      ${sensitiveLabel ? '<span style="font-size:8px;font-weight:600;color:#fff;background:var(--grn);padding:1px 5px;border-radius:6px">'+sensitiveLabel+'</span>' : ''}
      ${ctLabel ? `<span style="font-size:8px;color:${ctLabel==='JSON'?'var(--grn)':'var(--text-dim)'};background:rgba(255,255,255,.05);padding:1px 5px;border-radius:6px">${ctLabel}</span>` : ''}
      ${needAuth ? '<span style="color:var(--amber);font-size:8px;font-weight:600;background:rgba(240,160,32,.15);padding:1px 5px;border-radius:8px">需鉴权</span>' : ''}
      <span style="flex:1"></span>
      <span style="font-size:9px;color:var(--text-dim)">${esc(fp)} ${(r.size||0)>1024?(r.size/1024).toFixed(1)+'K':(r.size||0)+'B'}</span>
    </div>
    <div class="resp-panel${wasOpen?' show':''}" id="${rid}"><div class="resp-hdr"><span>HTTP ${r.status||'?'} | ${r.contentType||'?'} | ${(r.size||0)}B</span><span onclick="event.stopPropagation()" style="cursor:pointer;color:var(--crimson)">X</span></div><div class="resp-body${r.status>=400?' error':''}">${_preview(r)}</div></div>`
  })
  html += '</div></div>'
  if (!total) html = '<div class="empty">点击 FUZZ 开始探测</div>'
  else if (!list.length) html += '<div class="empty">当前筛选无结果</div>'
  c.innerHTML = html

  // filter button click
  c.querySelectorAll('.fuzz-filter-btn').forEach(btn => {
    btn.onclick = () => { _fuzzFilter = btn.dataset.v; _renderFuzzNow() }
  })
  // copy hits (filter out third-party domains)
  const cp = c.querySelector('#copyHits')
  if (cp) cp.onclick = (e) => {
    e.stopPropagation()
    const targetDomain = data.url ? new URL(data.url).hostname : ''
    const filtered = ok.filter(r => {
      if (!targetDomain) return !isThirdParty(r.url)
      try {
        const hostname = new URL(r.url).hostname
        return hostname === targetDomain || hostname.endsWith('.' + targetDomain)
      } catch(e) { return !isThirdParty(r.url) }
    })
    const text = filtered.map(r => r.url).join('\n')
    if (text) { navigator.clipboard.writeText(text).catch(()=>{}); showTip('已复制 ' + filtered.length + ' 条（过滤 ' + (ok.length - filtered.length) + ' 条第三方）') }
    else showTip('无目标域名路径')
  }
  // row click: simple toggle, tracked in Set
  c.querySelectorAll('.fuzz-row').forEach(tr => tr.onclick = () => {
    const rid = tr.dataset.rid
    if (_expandedPanels.has(rid)) { _expandedPanels.delete(rid) }
    else { _expandedPanels.add(rid) }
    _renderFuzzNow() // full re-render with new panel state
  })
  // X close button
  c.querySelectorAll('.resp-panel span[onclick]').forEach(sp => {
    sp.onclick = (e) => {
      e.stopPropagation()
      const rid = sp.closest('.resp-panel').id
      _expandedPanels.delete(rid)
      _renderFuzzNow()
    }
  })
}

function _preview(r) {
  if (r.error) return esc(r.body||'unknown')
  if (!r.body) return '(空)'
  let b = r.body; if (b.length > 500) b = b.substring(0,500)+'\n...'
  try { return JSON.stringify(JSON.parse(b),null,2).substring(0,600) } catch(e) {}
  return esc(b)
}

// ====== 代理 ======
async function applyProxy() {
  if (!proxyEnabled || !proxyUrl) return
  const m = proxyUrl.match(/^(https?|socks[45]):\/\/([^:]+):(\d+)/i)
  if (!m) return
  try { await chrome.proxy.settings.set({ value: { mode: 'fixed_servers', rules: { singleProxy: { scheme: m[1].toLowerCase(), host: m[2], port: parseInt(m[3]) } } }, scope: 'regular' }) } catch(e) {}
}
async function removeProxy() {
  if (!proxyEnabled) return
  try { await chrome.proxy.settings.clear({ scope: 'regular' }) } catch(e) {}
}
window.addEventListener('beforeunload', () => { if (fuzzing) removeProxy() })

// ====== 指纹 Tab ======
function renderFingerprint() {
  const c = document.getElementById('tab-content')

  // ---- 收集所有指纹 ----
  const items = []

  // Wappalyzer
  for (const w of (data.wap||[])) {
    items.push({ name: w.name, conf: w.confidence||80, ver: w.version||'', cat: (w.catNames||[])[0]||'', source: w.types?.[0]||'' })
  }
  // 内置框架/Header/Cookie
  for (const f of (data.fw||[])) {
    if (!f.name) continue
    // 去重
    const key = f.name.toLowerCase()
    const dup = items.find(x => x.name.toLowerCase() === key)
    if (dup) { dup.conf = Math.max(dup.conf, f.score||80); if (!dup.ver && f.prefix) dup.ver = f.prefix; continue }
    items.push({ name: f.name, conf: f.score||80, ver: f.prefix||'', cat: '', source: 'header' })
  }

  if (!items.length) { c.innerHTML = '<div class="empty">暂无数据 — 浏览目标时自动识别</div>'; return }

  // 排序 + 分类色
  items.sort((a,b) => b.conf - a.conf)
  const catColor = (item) => {
    const n = item.name.toLowerCase()
    if (/apache|nginx|iis|tomcat|jetty|cloudflare|cdn/i.test(n)) return '#38bdf8' // 蓝 - 基础设施
    if (/php|java|python|node|go\b|ruby/i.test(n)) return '#00c978' // 绿 - 运行时
    if (/spring|laravel|thinkphp|django|flask|fastapi|vue|react|angular|next|nuxt|shiro|asp/i.test(n)) return '#f0a020' // 金 - 框架
    if (/hsts|waf|cors|httponly/i.test(n)) return '#ff3355' // 红 - 安全
    if (/jquery|bootstrap|echarts|webpack|vite|tailwind/i.test(n)) return '#a855f7' // 紫 - 前端
    if (/google|analytics|sentry|hotjar|grafana/i.test(n)) return '#fbbf24' // 黄 - 分析
    return '#94a3b8' // 灰 - 其他
  }

  let html = '<div style="padding:8px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><span style="font-size:11px;font-weight:600;color:var(--bright)">技术栈指纹</span><span style="font-size:9px;color:var(--dim);font-family:var(--mono);background:rgba(255,255,255,.05);padding:1px 8px;border-radius:8px">' + items.length + ' 项</span></div>'

  for (const item of items) {
    const color = catColor(item)
    const confColor = item.conf >= 80 ? 'var(--grn)' : (item.conf >= 50 ? 'var(--amber)' : 'var(--dim)')
    html += `<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;margin-bottom:1px" onmouseover="this.style.background='var(--hover)'" onmouseout="this.style.background='transparent'">
      <span style="width:6px;height:6px;border-radius:50%;background:${color};flex-shrink:0"></span>
      <span style="font:10px var(--mono);color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(item.name)}</span>
      ${item.ver ? `<span style="font-size:8px;color:var(--blue);background:rgba(56,189,248,.1);padding:1px 5px;border-radius:6px;flex-shrink:0">v${esc(item.ver)}</span>` : ''}
      ${item.cat ? `<span style="font-size:8px;color:var(--dim);flex-shrink:0">${esc(item.cat)}</span>` : ''}
      ${item.source ? `<span style="font-size:7px;color:var(--dim);background:rgba(255,255,255,.05);padding:1px 5px;border-radius:4px;flex-shrink:0">${esc(item.source)}</span>` : ''}
      <span style="font:9px var(--mono);color:${confColor};font-weight:600;flex-shrink:0;text-align:right;width:32px">${item.conf}%</span>
    </div>`
  }

  // 配置信息
  const cfg = Object.entries(data.cfg||{}).filter(([,v])=>v)
  if (cfg.length) {
    html += '<div style="margin-top:12px;padding:8px;border-top:1px solid var(--border)"><div style="font-size:10px;color:var(--dim);margin-bottom:6px">配置信息</div>'
    for (const [k,v] of cfg) {
      html += `<div style="display:flex;gap:8px;padding:2px 0;font-size:9px"><code style="color:var(--grn);font-family:var(--mono);min-width:80px">${esc(k)}</code><span style="color:var(--dim)">${esc(String(v).substring(0,100))}</span></div>`
    }
    html += '</div>'
  }

  // 框架攻击路径提示
  if ((data.fw||[]).length && Object.keys(fwExploits).length) {
    html += '<div style="margin-top:12px;padding:8px;border-top:1px solid var(--border)"><div style="font-size:10px;color:var(--amber);margin-bottom:8px;font-weight:600;display:flex;align-items:center;gap:5px"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="width:11px;height:11px"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>攻击路径提示</div>'
    for (const f of data.fw) {
      const exploitKey = fwKeyMap[f.key] || f.key
      const exp = fwExploits[exploitKey]
      if (!exp) continue
      html += '<div style="margin-bottom:8px"><div style="font-size:9px;color:var(--bright);margin-bottom:4px">' + esc(exp.name) + '</div>'
      for (const h of exp.hints) {
        const riskColor = h.type === 'CRITICAL' ? '#ff3355' : h.type === 'HIGH' ? '#ff8c00' : h.type === 'MEDIUM' ? '#f0a020' : '#94a3b8'
        html += '<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:9px">'
        html += '<span style="font-size:7px;padding:1px 5px;border-radius:3px;background:' + riskColor + '22;color:' + riskColor + ';font-weight:600;flex-shrink:0">' + esc(h.type) + '</span>'
        html += '<code style="color:var(--blue);font-family:var(--mono);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(h.path) + '">' + esc(h.path) + '</code>'
        html += '</div><div style="font-size:8px;color:var(--dim);padding-left:0;margin-bottom:3px">' + esc(h.desc) + '</div>'
      }
      html += '</div>'
    }
    html += '</div>'
  }

  // GitHub 仓库
  const repos = data.githubRepos || []
  if (repos.length) {
    html += '<div style="margin-top:12px;padding:8px;border-top:1px solid var(--border)"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><span style="font-size:10px;color:var(--bright);font-weight:600;display:inline-flex;align-items:center;gap:5px"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="width:11px;height:11px"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>GitHub 仓库</span><span style="font-size:9px;color:var(--dim)">' + repos.length + '</span></div>'
    for (const repo of repos) {
      const repoName = repo.replace('https://github.com/', '')
      html += '<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:9px">'
      html += '<a href="' + esc(repo) + '" target="_blank" style="color:var(--blue);text-decoration:none;font-family:var(--mono);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(repo) + '">' + esc(repoName) + '</a>'
      html += '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>'
      html += '</div>'
    }
    html += '</div>'
  }

  // 电话号码
  const phones = data.phones || []
  if (phones.length) {
    html += '<div style="margin-top:12px;padding:8px;border-top:1px solid var(--border)"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><span style="font-size:10px;color:var(--bright);font-weight:600;display:inline-flex;align-items:center;gap:5px"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="width:11px;height:11px"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.37 1.9.72 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.35 1.85.59 2.81.72A2 2 0 0 1 22 16.92z"/></svg>提取的电话</span><span style="font-size:9px;color:var(--dim)">' + phones.length + '</span></div>'
    const uniquePhones = [...new Set(phones)]
    for (const p of uniquePhones) {
      html += '<div style="font-size:9px;font-family:var(--mono);color:var(--text);padding:2px 0">' + esc(p) + '</div>'
    }
    html += '</div>'
  }

  // 网站解析 (ICP / IP) — 修复: 原 handleSiteAnalysis 无消息入口属死代码, 补上 UI 入口
  html += '<div style="margin-top:12px;padding:8px;border-top:1px solid var(--border)"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><span style="font-size:10px;color:var(--bright);font-weight:600;display:inline-flex;align-items:center;gap:5px"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="width:11px;height:11px"><circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a14.5 14.5 0 0 1 0 18 14.5 14.5 0 0 1 0-18z"/></svg>网站解析</span><button id="btnSiteAnalysis" style="padding:2px 8px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--dim);cursor:pointer;font-size:9px">查询</button></div><div id="siteAnalysisResult" style="font-size:9px;color:var(--dim);line-height:1.6">在「设置」中配置 ICP/IP API 密钥后，可查询目标备案与归属信息</div></div>'

  html += '</div>'
  c.innerHTML = html

  const saBtn = c.querySelector('#btnSiteAnalysis')
  if (saBtn) saBtn.onclick = async () => {
    const out = c.querySelector('#siteAnalysisResult')
    if (!data.url) { out.textContent = '无目标 URL（先浏览目标站点）'; return }
    out.textContent = '查询中...'
    try {
      const domain = new URL(data.url).hostname
      const res = await chrome.runtime.sendMessage({ action: 'siteAnalysis', domain, tabId: data.tabId })
      if (!res) { out.textContent = '查询失败（网络错误或未配置密钥）'; return }
      out.innerHTML = `域名: <b>${esc(res.domain || domain)}</b><br>` +
        `ICP: ${esc(res.icp?.icp || '-')} ${esc(res.icp?.unit || '')} ${esc(res.icp?.time || '')}<br>` +
        `IP: ${esc(res.ip?.ip || '-')} ${esc(res.ip?.location || '')} ${esc(res.ip?.isp || '')}`
    } catch(e) { out.textContent = '查询失败: ' + e.message }
  }
}

// ====== 配置 Tab ======
async function renderConfig() {
  const c = document.getElementById('tab-content')
  let whitelist = [], apiCfg = {}
  try {
    const r = await chrome.storage.local.get(['customWhitelist','proxyUrl','proxyEnabled','icpApiId','icpApiKey','ipApiId','ipApiKey'])
    whitelist = r.customWhitelist||[]; proxyUrl = r.proxyUrl||''; proxyEnabled = r.proxyEnabled===true
    apiCfg = { icpId: r.icpApiId||'', icpKey: r.icpApiKey||'', ipId: r.ipApiId||'', ipKey: r.ipApiKey||'' }
  } catch(e) {}
  c.innerHTML = `<div class="section"><div class="section-hdr"><span>代理设置</span></div>
    <div class="list" style="padding:8px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:10px">
          <input type="checkbox" id="proxyToggle" ${proxyEnabled?'checked':''}> Fuzz时启用代理
        </label>
      </div>
      <input id="proxyInput" value="${esc(proxyUrl)}" placeholder="http://127.0.0.1:8080"
        style="width:100%;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:5px 8px;font:10px var(--mono);border-radius:3px">
      <div style="margin-top:8px"><button class="save-btn" id="saveProxy">保存</button></div>
    </div></div>
    <div class="section" style="margin-top:8px"><div class="section-hdr"><span>扫描白名单</span></div><div class="cfg-desc">以下域名跳过扫描，每行一个</div>
    <textarea id="wlInput" style="width:100%;min-height:60px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:8px;font:10px var(--mono);border-radius:3px;resize:vertical">${whitelist.join('\n')}</textarea>
    <div style="padding:6px 0"><button class="save-btn" id="saveWl">保存</button></div></div>
    <div class="section" style="margin-top:8px"><div class="section-hdr"><span>API 密钥 (网站解析)</span></div><div class="cfg-desc">用于ICP备案查询和IP地理位置查询 (cn.apihz.cn)，留空则跳过查询</div>
    <div class="list" style="padding:8px;display:flex;flex-direction:column;gap:6px">
      <div style="display:flex;gap:6px;align-items:center">
        <span style="font-size:9px;color:var(--dim);width:80px;flex-shrink:0">ICP API ID</span>
        <input id="icpApiId" value="${esc(apiCfg.icpId)}" placeholder="API ID" style="flex:1;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:4px 7px;font:10px var(--mono);border-radius:3px">
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <span style="font-size:9px;color:var(--dim);width:80px;flex-shrink:0">ICP API Key</span>
        <input id="icpApiKey" value="${esc(apiCfg.icpKey)}" placeholder="API Key" type="password" style="flex:1;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:4px 7px;font:10px var(--mono);border-radius:3px">
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <span style="font-size:9px;color:var(--dim);width:80px;flex-shrink:0">IP API ID</span>
        <input id="ipApiId" value="${esc(apiCfg.ipId)}" placeholder="API ID" style="flex:1;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:4px 7px;font:10px var(--mono);border-radius:3px">
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <span style="font-size:9px;color:var(--dim);width:80px;flex-shrink:0">IP API Key</span>
        <input id="ipApiKey" value="${esc(apiCfg.ipKey)}" placeholder="API Key" type="password" style="flex:1;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:4px 7px;font:10px var(--mono);border-radius:3px">
      </div>
      <div><button class="save-btn" id="saveApiKeys">保存密钥</button></div>
    </div></div>`
  document.getElementById('saveWl').onclick = async () => {
    const ds = document.getElementById('wlInput').value.split('\n').map(d=>d.trim()).filter(Boolean)
    await chrome.storage.local.set({ customWhitelist: ds })
    showTip('已保存')
  }
  document.getElementById('saveProxy').onclick = async () => {
    const pi = document.getElementById('proxyInput'); const pt = document.getElementById('proxyToggle')
    proxyUrl = pi.value.trim(); if (proxyUrl && !proxyUrl.includes('://')) proxyUrl = 'http://' + proxyUrl
    pi.value = proxyUrl; proxyEnabled = pt.checked
    await chrome.storage.local.set({ proxyUrl, proxyEnabled })
    showTip('已保存')
  }
  document.getElementById('saveApiKeys').onclick = async () => {
    await chrome.storage.local.set({
      icpApiId: document.getElementById('icpApiId').value.trim(),
      icpApiKey: document.getElementById('icpApiKey').value.trim(),
      ipApiId: document.getElementById('ipApiId').value.trim(),
      ipApiKey: document.getElementById('ipApiKey').value.trim(),
    })
    showTip('API 密钥已保存')
  }
}

// ====== 导出按钮 ======
document.getElementById('btnHit').onclick = async () => {
  const list = fuzzRes.filter(r => r.status!==404&&r.status!==0&&r.status!==501)
  const text = list.length ? list.map(r=>r.url).join('\n') : (data.apis||[]).map(a=>a.path).join('\n')
  if (!text) return
  await navigator.clipboard.writeText(text)
  showTip('已复制 '+(list.length||(data.apis||[]).length)+' 条')
}
document.getElementById('btnDict').onclick = async () => {
  const text = (data.apis||[]).map(a=>a.path).join('\n')
  if (!text) return
  await navigator.clipboard.writeText(text)
  showTip('已复制字典 '+(data.apis||[]).length+' 条')
}
document.getElementById('btnExport').onclick = () => {
  const useFullUrl = document.getElementById('exportFullUrl').checked
  // 导出完整JSON数据（供导入使用）
  const exportData = {
    version: '1.4',
    url: data.url || '',
    exportTime: new Date().toISOString(),
    apis: (data.apis||[]).map(a => ({ path: useFullUrl && data.url ? data.url.replace(/\/$/,'') + a.path : a.path, method: a.method, classify: a.classify })),
    fw: data.fw || [],
    params: data.params || [],
    domains: data.domains || [],
    ips: data.ips || [],
    jwts: data.jwts || [],
    creds: data.creds || [],
    phones: data.phones || [],
    githubRepos: data.githubRepos || [],
    runtimeReqs: data.runtimeReqs || [],
    fuzzResults: fuzzRes.slice(0, 5000),
  }
  const text = JSON.stringify(exportData, null, 2)
  const blob = new Blob([text], {type: 'application/json'})
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  const host = data.url ? new URL(data.url).hostname.replace(/\\./g, '_') : 'unknown'
  const date = new Date().toISOString().slice(0,10).replace(/-/g,'')
  a.href = url; a.download = 'DesJsFinder_' + host + '_' + date + '.json'
  a.click()
  URL.revokeObjectURL(url)
  const apiCount = (exportData.apis||[]).length
  showTip('已导出: ' + apiCount + ' API + ' + (exportData.fuzzResults||[]).length + ' Fuzz')
}
document.getElementById('btnImport').onclick = () => document.getElementById('fileImport').click()
document.getElementById('fileImport').addEventListener('change', async (e) => {
  const file = e.target.files[0]
  if (!file) return
  try {
    const text = await file.text()
    const imported = JSON.parse(text)
    if (!imported.version || !imported.apis) { showTip('文件格式无效'); return }
    const mergeSet = (field, keyFn) => {
      const existing = new Set((data[field]||[]).map(keyFn))
      const toAdd = (imported[field]||[]).filter(x => !existing.has(keyFn(x)))
      if (toAdd.length) data[field] = [...(data[field]||[]), ...toAdd]
    }
    mergeSet('apis', a => a.path + '|' + a.method)
    mergeSet('fw', f => f.key)
    mergeSet('params', p => p.value)
    mergeSet('domains', d => d)
    mergeSet('runtimeReqs', r => r.url + '|' + r.method)
    mergeSet('phones', p => p)
    mergeSet('githubRepos', g => g)
    if (imported.fuzzResults && imported.fuzzResults.length && !fuzzRes.length) fuzzRes = imported.fuzzResults
    chrome.storage.local.set({ lastData: data, lastFuzzRes: fuzzRes.slice(0, 5000), lastFuzzTotal: fuzzRes.length })
    updateBar(); render()
    showTip('已导入: ' + (imported.apis&&imported.apis.length||0) + ' API + ' + (imported.fuzzResults&&imported.fuzzResults.length||0) + ' Fuzz')
  } catch(err) { showTip('导入失败: ' + err.message) }
  e.target.value = ''
})
document.getElementById('btnClear').onclick = () => {
  data={};fuzzRes=[];fuzzing=false
  _fuzzGen++  // bump gen, 让所有 in-flight fuzz 请求的 stale callback 静默丢弃, 不再回填
  render(); updateBar()
  const btn = document.getElementById('btnFuzz'); btn.textContent = 'FUZZ'; btn.classList.remove('running')
  chrome.runtime.sendMessage({action:'clear'})
}

// ====== 键盘搜索 ======
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement === document.body) {
    e.preventDefault()
    const ex = document.getElementById('filterInput')
    if (ex) { ex.focus(); return }
    const inp = document.createElement('input')
    inp.id = 'filterInput'; inp.type = 'search'; inp.placeholder = '过滤...'
    inp.style.cssText = 'width:120px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);padding:3px 6px;font-size:10px;border-radius:3px;margin-left:4px'
    document.querySelector('.bar').appendChild(inp)
    inp.focus()
    inp.oninput = () => {
      const q = inp.value.toLowerCase()
      document.querySelectorAll('.row').forEach(el => { el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none' })
    }
    inp.onblur = () => inp.remove()
  }
})

// ====== 工具 ======
let _toastTimer = null
function showTip(text) {
  let t = document.getElementById('toast')
  if (!t) {
    t = document.createElement('div')
    t.id = 'toast'
    t.style.cssText = 'position:fixed;top:10px;left:50%;transform:translateX(-50%);background:linear-gradient(180deg,#101a30,#0a1120);color:var(--bright);padding:6px 14px;border-radius:999px;font:10px var(--mono);letter-spacing:.04em;font-weight:600;z-index:99999;pointer-events:none;opacity:0;transition:opacity .15s;border:1px solid var(--border-glow);box-shadow:0 4px 18px rgba(0,0,0,.55)'
    document.body.appendChild(t)
  }
  t.textContent = text
  t.style.opacity = '1'
  if (_toastTimer) clearTimeout(_toastTimer)
  _toastTimer = setTimeout(() => { t.style.opacity = '0' }, 1000)
}

// 一次性进入动画
document.body.classList.add('ready')