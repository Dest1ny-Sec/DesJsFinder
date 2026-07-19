// ============================================================
// Content — 注入页面,提取路径,发送background
// 支持: 被动采集 + MutationObserver动态扫描 + 多类型信息提取
// ============================================================
(function () {
  if (window.__apifuzzerRan) return
  window.__apifuzzerRan = true

  const host = location.host, protocol = location.protocol
  const tasks = [], apiFilter = new APIFilter(), fwDetect = new FrameworkDetect()
  let scanTimer = null
  const seenJsUrls = new Set() // 防止重复采集同一JS

  // ========== Wappalyzer 指纹识别 ==========
  let wapDetect = null
  let wapReady = false
  async function initWappalyzer() {
    if (wapReady) return
    try {
      const [dataResp, engineResp] = await Promise.all([
        fetch(chrome.runtime.getURL('filters/wappalyzer-data.json')),
        fetch(chrome.runtime.getURL('filters/wappalyzer-engine.js')),
      ])
      if (!dataResp.ok || !engineResp.ok) return
      const bundle = await dataResp.json()
      const engineCode = await engineResp.text()
      // Execute engine code in this context
      const mod = {}
      const fn = new Function('module', 'exports', engineCode.replace('module\.exports', 'module._e='))
      fn({ _e: mod }, {})
      const EngineClass = mod.WappalyzerEngine
      if (!EngineClass) return
      const engine = new EngineClass()
      engine.load(bundle.data)
      wapDetect = { engine, cats: bundle.cats || {} }
      wapReady = true
      console.log('[DesJsFinder] Wappalyzer ready: ' + (bundle.names || []).length + ' techs')
    } catch(e) { console.warn('[DesJsFinder] Wappalyzer init failed:', e.message) }
  }

  function runWappalyzer() {
    if (!wapReady || !wapDetect) return []
    try {
      const scripts = []
      document.querySelectorAll('script[src]').forEach(s => scripts.push(s.src))
      const cookies = {}
      try { document.cookie.split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) cookies[c.slice(0,i).trim()] = c.slice(i+1).trim() }) } catch(e) {}
      const globals = window.__desjsfinder_globals__ || {}
      const results = wapDetect.engine.detect({
        html: document.documentElement.outerHTML.slice(0, 500000),
        scripts, cookies, globals,
      })
      return results.map(r => ({
        name: r.name,
        cats: r.cats,
        catNames: (r.cats || []).map(id => (wapDetect.cats[id] || '')).filter(Boolean),
        confidence: r.confidence,
        version: r.version || '',
        types: r.types || [],
        match: (r.match || '').slice(0, 100),
      }))
    } catch(e) { return [] }
  }

  // ========== 工具函数 ==========
  let _cachedHTML = '', _cachedHTML_ts = 0
  function getHTML() {
    const now = Date.now()
    if (!_cachedHTML || now - _cachedHTML_ts > 2000) {
      _cachedHTML = document.documentElement.outerHTML
      _cachedHTML_ts = now
    }
    return _cachedHTML
  }
  function _normalize(u) {
    if (!u || u.startsWith('data:') || u.startsWith('blob:')) return u
    if (u.startsWith('//')) return location.origin + u
    if (u.startsWith('/')) return location.origin + u
    if (!u.startsWith('http')) { const b = location.href.split('#')[0]; return b.substring(0, b.lastIndexOf('/') + 1) + u }
    return u
  }

  function _dedup(arr) {
    const s = new Set(), r = []
    for (const x of arr) { if (!s.has(x)) { s.add(x); r.push(x) } }
    return r
  }

  // ========== 正则提取器 ==========
  const Extractor = {
    domain: (text) => {
      const re = /(?:\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+(?:[a-zA-Z]{2,63})(?:\:\d{1,5})?\b/gi
      const tldRe = /\.(?:com|cn|net|org|io|cc|top|vip|xyz|club|site|online|tech|store|wang|fun|space|info|pro|biz|co|me|tv|mobi|asia|studio|design|law|shop|art|press|icu|link|fan|cloud|games|cash|cafe|band|media|work|ren|yoga|red|luxe|fashion|technology|ski|pink|host|kim|pet|run|pub|chat|group|live|city|cool|fund|gold|guru|life|team|today|world|zone|social|bio|black|blue|green|lotto|organic|poker|promo|vote|archi|voto|fit|web|app|dev|ai|email|video|market|shopping|mba|sale|news|fyi|tax|gov|edu|mil)$/i
      const found = []; let m
      while ((m = re.exec(text)) !== null) {
        const d = m[0]
        if (/^(?:localhost|127\.|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/.test(d)) continue
        // strip port for TLD check
        const hostOnly = d.replace(/:\d+$/, '')
        if (!tldRe.test(hostOnly)) continue
        if (/\.(?:js|css|png|jpe?g|gif|svg|woff2?|ttf|eot|json|xml|html?|mp[34]|pdf|zip|tar|gz)$/i.test(hostOnly)) continue
        found.push(d)
      }
      return [...new Set(found)]
    },

    ip: (text) => {
      const re = /(?<!\.|\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?::\d{1,5})?/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) {
        const ip = m[0].split(':')[0]
        if (!/^(?:0\.0\.0\.0|255\.255\.255\.255|127\.0\.0\.1)$/.test(ip)) found.push(m[0])
      }
      return [...new Set(found)]
    },

    phone: (text) => {
      const re = /(?<!\d)(?:13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}(?!\d)/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) found.push(m[0])
      return [...new Set(found)]
    },

    email: (text) => {
      const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) found.push(m[0])
      return [...new Set(found)]
    },

    jwt: (text) => {
      const re = /["']?(?:ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}(?:\.[A-Za-z0-9._-]{10,})?)["']?/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) { const v = m[0].replace(/^["']|["']$/g, ''); if (v.length > 20) found.push(v) }
      return [...new Set(found)]
    },

    credentials: (text) => {
      const re = /(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|auth|authorization)\s*[:=]\s*(?:["']?)([^"',;\s\)\]\}]{4,})(?:["']?)/gi
      const found = []; let m
      while ((m = re.exec(text)) !== null) {
        const val = m[1]
        if (val && !/^(true|false|null|undefined|localhost|127\.0\.0\.1)$/i.test(val)) found.push(m[0].trim())
      }
      return [...new Set(found)]
    },

    cookie: (text) => {
      const re = /\b(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|session_id|token)\s*[:=]\s*(?:["']?)([a-zA-Z0-9_\-]{8,})(?:["']?)/gi
      const found = []; let m
      while ((m = re.exec(text)) !== null) found.push(m[0].trim())
      return [...new Set(found)]
    },

    company: (text) => {
      const re = /[一-龥]{2,15}(?:公司|中心|集团|科技|软件|网络|信息|系统|技术|电子|数码|智能|数据|云计算|互联网)/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) found.push(m[0])
      return [...new Set(found)]
    },

    github: (text) => {
      const re = /https?:\/\/(?:www\.)?github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+/g
      const found = []; let m
      while ((m = re.exec(text)) !== null) found.push(m[0])
      return [...new Set(found)]
    },
  }

  // ========== 收集JS URL ==========
  function collectJsUrls() {
    const urls = new Set()

    // 1. 常规 script/link 标签
    document.querySelectorAll('script[src]').forEach(s => {
      const u = _normalize(s.src)
      if (u && !seenJsUrls.has(u)) { seenJsUrls.add(u); urls.add(u) }
    })
    document.querySelectorAll('link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]').forEach(l => {
      const u = _normalize(l.href)
      if (u && !seenJsUrls.has(u)) { seenJsUrls.add(u); urls.add(u) }
    })

    // 2. Webpack chunk 检测
    try {
      const chunkNames = []
      try { for (const key in window.__webpack_require__?.c || {}) { chunkNames.push(key) } } catch(e) {}
      try { for (const key in window.webpackChunkLoad || {}) { chunkNames.push(key) } } catch(e) {}
      // 仅在有确定 base 路径时使用 chunk IDs (通过 detectWebpackChunkBase 推断)
      const chunkBase = detectWebpackChunkBase()
      if (chunkBase) {
        for (const name of chunkNames) {
          if (name && name.length > 3) {
            const url = chunkBase.base + name + '.js'
            if (!seenJsUrls.has(url)) { seenJsUrls.add(url); urls.add(url) }
          }
        }
      }
    } catch(e) {}

    // 3. import/require 动态提取 (use cached HTML)
    try {
      const importRe = /import\s*\(?["']([^"']+\.js(?:\?[^"']*)?)["']\)?/g
      let m
      while ((m = importRe.exec(getHTML())) !== null) {
        const u = _normalize(m[1])
        if (u && !seenJsUrls.has(u)) { seenJsUrls.add(u); urls.add(u) }
      }
    } catch(e) {}

    return [...urls]
  }

  // 检测Webpack chunk基础路径和id映射
  function detectWebpackChunkBase() {
    try {
      // 方法1: 从已有的script标签推断（兼容 CRA/Next.js/自定义路径）
      const scripts = document.querySelectorAll('script[src]')
      const chunks = []
      const chunkRe = /\/(?:static|assets|dist|js)\/.*\/(?:main|chunk-|vendors?|app|common|polyfills?|pages\/)[^\/]*?\.js$/
      const nextRe = /_next\/static\/(?:chunks|pages)/
      for (const s of scripts) {
        const src = s.src || ''
        if (chunkRe.test(src) || nextRe.test(src)) chunks.push(src)
      }
      if (chunks.length > 0) {
        // 提取目录路径: /xxx/yyy/zzz/main.abc.js → /xxx/yyy/zzz/
        const baseMatch = chunks[0].match(/(.*)\/[^\/]+\.js$/)
        if (baseMatch) {
          const base = baseMatch[1] + '/'
          const ids = {}
          chunks.forEach(url => {
            const m = url.match(/\/([^\/]+?)(?:[.\-][a-f0-9]{8,})?\.js$/)
            if (m) ids[m[1]] = ''
          })
          return { base, ids }
        }
      }
    } catch(e) {}
    return null
  }

  // ========== 收集内联脚本 ==========
  function collectInlineScripts() {
    const scripts = []
    document.querySelectorAll('script:not([src])').forEach(s => {
      const t = s.textContent
      if (t && t.length > 100) { seenJsUrls.add('inline:' + t.substring(0, 50)); scripts.push(t) }
    })
    return scripts
  }

  // ========== 发送数据到 background ==========
  function sendToBackground(data) {
    try {
      chrome.runtime.sendMessage({ action: 'passive', ...data })
    } catch (e) { /* extension context may be invalidated */ }
  }

  // ========== 监听 injector.js 的运行时 API 拦截数据 ==========
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.type !== '__desjsfinder_intercepted__') {
      // Also handle Wappalyzer globals from injector
      if (event.source !== window || !event.data || event.data.type !== '__desjsfinder_wap_globals__') return
      if (event.data.globals && Object.keys(event.data.globals).length > 0) {
        window.__desjsfinder_globals__ = event.data.globals
        // Re-run Wappalyzer detection with new globals
        if (wapReady) {
          const wap = runWappalyzer()
          if (wap.length) {
            sendToBackground({
              tasks: [], inlineScripts: [], apis: [],
              url: location.href, title: document.title,
              wap, isUpdate: true
            })
          }
        }
      }
      return
    }
    const d = event.data;
    // Forward captured auth tokens to background
    if (d.kind === 'token' && d.authHeader) {
      try { chrome.runtime.sendMessage({ action: 'storeToken', token: d.authHeader, tabId: null }) } catch(e) {}
      return
    }
    // Extract API path + params from runtime URL
    let path = '', query = '';
    try {
      const u = new URL(d.url)
      path = u.pathname
      query = u.search.replace(/[&?]?(?:fp|verifyFp|msToken|a_bogus|webid|uifid|timestamp|x-secsdk-web-signature)[^&]*/gi, '')
        .replace(/^&/, '?') // clean tracking params
    } catch (e) { return; }
    if (path.length < 2 || path === '/') return;
    const method = d.method || 'GET';
    const classify = apiFilter.classify(path);
    const apis = [{ path, method, classify }];
    // if runtime URL has real params, also add param-stripped path + path with params
    if (query.length > 1) {
      apis.push({ path: path + query, method: 'GET', classify: { label: '带参API', risk: 'MEDIUM' } })
    }
    // extract body param keys for Fuzz
    let bodyParams = []
    if (d.reqBody && d.reqBody.length > 2) {
      try {
        const obj = JSON.parse(d.reqBody)
        bodyParams = Object.keys(obj).filter(k => k.length >= 2 && k.length <= 30)
      } catch(e) {
        // try form-encoded
        bodyParams = d.reqBody.split('&').map(p => p.split('=')[0]).filter(k => k.length >= 2)
      }
    }
    try {
      chrome.runtime.sendMessage({
        action: 'passive',
        tasks: [], inlineScripts: [], apis,
        url: location.href, title: document.title,
        isRuntime: true,
        runtimeReq: { url: d.url, method, status: d.status, contentType: d.contentType, respBody: (d.respBody||'').slice(0, 4096) },
        bodyParams
      });
    } catch (e) {}
    // Also extract info from response body
    if (d.respBody && d.respBody.length > 50) {
      const domains = Extractor.domain(d.respBody);
      const ips = Extractor.ip(d.respBody);
      const emails = Extractor.email(d.respBody);
      const jwts = Extractor.jwt(d.respBody);
      const creds = Extractor.credentials(d.respBody);
      if (domains.length || ips.length || emails.length || jwts.length || creds.length) {
        try {
          chrome.runtime.sendMessage({
            action: 'passive',
            tasks: [], inlineScripts: [], apis: [],
            url: location.href, title: document.title,
            domains, ips, emails, jwts, creds, cookies: [], companies: [], githubs: [],
            isRuntime: true
          });
        } catch (e) {}
      }
    }
  });

  // ========== localStorage / sessionStorage 扫描 ==========
  function scanBrowserStorage() {
    const items = [];
    for (const [storageName, storage] of [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]]) {
      try {
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          const value = storage.getItem(key);
          if (!value || value.length < 20) continue;
          if (!/(token|key|secret|auth|credential|jwt|session|pass|user|perm|role|config)/i.test(key + value.substring(0, 200))) continue;
          items.push(`${storageName}:${key}=${value}`);
        }
      } catch (e) {}
    }
    return items;
  }

  // ========== 首次扫描 ==========
  // 从 HTML 属性提取所有路径 (href/src/action/content — 对标 FindSomething 的采集面)
  function extractAttrPaths() {
    const found = new Set()
    const attrs = ['href','src','action','content','data-url','data-src','data-href','data-base']
    for (const attr of attrs) {
      document.querySelectorAll(`[${attr}]`).forEach(el => {
        const v = el.getAttribute(attr) || ''
        if (v.length < 2 || v.startsWith('#') || v.startsWith('javascript:') || v.startsWith('data:')) return
        try {
          const u = new URL(v, location.href)
          if (u.host === location.host) {
            const p = u.pathname
            if (p.length >= 2 && p !== '/') found.add(p)
          }
        } catch(e) {
          // relative path
          if (v.startsWith('/') && v.length >= 2 && v.length <= 200) {
            const p = v.split('?')[0]
            if (p.length >= 2) found.add(p)
          }
        }
      })
    }
    return [...found].filter(p => !apiFilter.isStatic(p))
  }

  function initialScan() {
    const html = getHTML()
    const jsUrls = collectJsUrls()
    const inlineScripts = collectInlineScripts()

    // 从HTML、内联、属性提取API
    let inlineAPIs = []
    inlineScripts.forEach(t => inlineAPIs.push(...apiFilter.extract(t)))
    inlineAPIs.push(...apiFilter.extract(html))
    inlineAPIs.push(...extractAttrPaths())
    const apiList = _dedup(inlineAPIs).map(p => ({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }))

    // 框架 — 同时检测 HTML + 内联脚本，取并集
    const fwFromHtml = fwDetect.detect(html)
    const fwFromInline = fwDetect.detect(inlineScripts.join('\n')) || []
    const fw = [...fwFromHtml]
    for (const nf of fwFromInline) {
      if (!fw.some(f => f.key === nf.key)) fw.push(nf)
    }

    // 配置
    const cfg = {}
    inlineScripts.forEach(t => Object.assign(cfg, fwDetect.extractConfig(t) || {}))

    // 表单
    const forms = [...new Set([...document.querySelectorAll('input[name], select[name]')].map(e => e.name))]

    // 其他信息提取 (只提取有用的)
    const fullText = html + '\n' + inlineScripts.join('\n')
    // 第三方域名过滤 (用于JS下载去重)
    const THIRD_PARTY_DOMAINS = new Set([
      'google-analytics.com','googletagmanager.com','doubleclick.net','googleadservices.com',
      'baidu.com/hm','hm.baidu.com',
      'facebook.net','fbcdn.net',
      'hotjar.com','mouseflow.com','crazyegg.com','fullstory.com',
      'newrelic.com','datadoghq.com','sentry.io','bugsnag.com',
      'mixpanel.com','amplitude.com','segment.com',
      'hubspot.com','marketo.com','pardot.com','eloqua.com',
      'addthis.com','sharethis.com','addtoany.com',
      'livechatinc.com','zendesk.com','intercom.io','intercomcdn.com',
      'cloudflare.com','cdnjs.cloudflare.com','jsdelivr.net','unpkg.com',
      'polyfill.io','bootstrapcdn.com','stackpath.bootstrapcdn.com',
      'jquery.com','code.jquery.com','ajax.googleapis.com',
      'cnzz.com','51.la','tongji.linezing.com',
      'bytedance.com','bytecdn.cn','zijieapi.com','bytednsdoc.com','pstatp.com',
      'baidustatic.com','bdstatic.com','bdimg.com',
    ])
    function isThirdParty(url) {
      try {
        const hostname = new URL(url).hostname
        for (const d of THIRD_PARTY_DOMAINS) {
          if (hostname === d || hostname.endsWith('.' + d)) return true
        }
      } catch(e) {}
      return false
    }
    const domains = Extractor.domain(fullText)
    const ips = Extractor.ip(fullText)
    const jwts = Extractor.jwt(fullText)
    const creds = Extractor.credentials(fullText)
    const storageItems = scanBrowserStorage()

    const cleanJsUrls = jsUrls.filter(u => !isThirdParty(u))

    // Wappalyzer 指纹检测
    initWappalyzer().then(() => {
      const wap = runWappalyzer()
      if (wap.length) {
        sendToBackground({
          tasks: [], inlineScripts: [], apis: [],
          url: location.href, title: document.title,
          wap, isUpdate: true
        })
      }
    })

    sendToBackground({
      tasks: cleanJsUrls.slice(0, 30),
      inlineScripts: inlineScripts.slice(0, 20),
      apis: apiList.slice(0, 500),
      fw, cfg, forms,
      url: location.href, title: document.title,
      domains, ips, jwts, creds, storageItems
    })
  }

  // ========== MutationObserver 动态扫描 ==========
  let observer = null
  function initDynamicScan() {
    if (observer) return
    observer = new MutationObserver((mutations) => {
      const significant = mutations.filter(m => {
        if (m.type === 'attributes') {
          // 只关心 src/href 属性变化
          return ['src', 'href'].includes(m.attributeName)
        }
        if (m.type === 'childList') return m.addedNodes.length > 0
        return false
      })
      if (significant.length === 0) return

      // 防抖: 500ms内只扫一次
      if (scanTimer) clearTimeout(scanTimer)
      scanTimer = setTimeout(() => {
        const newJsUrls = collectJsUrls()
        const newInline = collectInlineScripts()

        // 只发新增的
        const newTasks = newJsUrls.filter(u => !tasks.includes(u)).slice(0, 20)
        const newApis = _dedup([...newInline.flatMap(t => apiFilter.extract(t)), ...apiFilter.extract(document.documentElement.outerHTML)])
          .map(p => ({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }))

        // 提取新内容中的其他信息
        const newContent = newInline.join('\n') + document.documentElement.outerHTML
        const domains = Extractor.domain(newContent)
        const ips = Extractor.ip(newContent)
        const phones = Extractor.phone(newContent)
        const emails = Extractor.email(newContent)
        const jwts = Extractor.jwt(newContent)
        const creds = Extractor.credentials(newContent)
        const cookies = Extractor.cookie(newContent)
        const companies = Extractor.company(newContent)
        const githubs = Extractor.github(newContent)

        // Wappalyzer 动态检测
        let wap = []
        if (wapReady) {
          wap = runWappalyzer()
        }

        if (newTasks.length || newApis.length || domains.length || wap.length) {
          sendToBackground({
            tasks: newTasks,
            inlineScripts: newInline.slice(0, 10),
            apis: newApis.slice(0, 200),
            url: location.href, title: document.title,
            domains, ips, phones, emails, jwts, creds, cookies, companies, githubs,
            wap, isUpdate: true
          })
        }
      }, 500)
    })

    observer.observe(document.documentElement, {
      childList: true, subtree: true,
      attributeFilter: ['src', 'href']
    })

    // also watch for dynamic iframe creation
    const iframeObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeName === 'IFRAME') {
            try {
              node.addEventListener('load', () => {
                const doc = node.contentDocument || node.contentWindow?.document
                if (!doc) return
                const html = doc.documentElement?.outerHTML
                if (!html) return
                const apis = apiFilter.extract(html).map(p => ({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }))
                if (apis.length) sendToBackground({ tasks: [], inlineScripts: [], apis, url: location.href, title: document.title + ' [iframe]', isUpdate: true })
              })
            } catch(e) {}
          }
        }
      }
    })
    iframeObserver.observe(document.documentElement, { childList: true, subtree: true })
  }

  // ========== SPA 路由变化重扫 ==========
  let _spaTimer = null, _lastHref = location.href
  function onRouteChange() {
    if (location.href === _lastHref) return
    _lastHref = location.href
    if (_spaTimer) clearTimeout(_spaTimer)
    _spaTimer = setTimeout(() => {
      const html = getHTML()
      const newJsUrls = collectJsUrls()
      const newInline = collectInlineScripts()
      const attrPaths = extractAttrPaths()
      const newApis = _dedup([...newInline.flatMap(t => apiFilter.extract(t)), ...apiFilter.extract(html), ...attrPaths])
        .map(p => ({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }))
      const storageItems = scanBrowserStorage()
      if (newJsUrls.length || newApis.length || storageItems.length) {
        // Wappalyzer 重扫
        let wap = []
        if (wapReady) wap = runWappalyzer()
        sendToBackground({
          tasks: newJsUrls.filter(u => !seenJsUrls.has(u)).slice(0, 20),
          inlineScripts: newInline.slice(0, 10), apis: newApis.slice(0, 200),
          url: location.href, title: document.title,
          storageItems, wap, isUpdate: true
        })
      }
    }, 800)
  }
  window.addEventListener('popstate', onRouteChange)
  window.addEventListener('hashchange', onRouteChange)
  // also catch pushState/replaceState via monkey-patch
  const _push = history.pushState, _replace = history.replaceState
  history.pushState = function() { _push.apply(this, arguments); onRouteChange() }
  history.replaceState = function() { _replace.apply(this, arguments); onRouteChange() }

  // ========== 启动 ==========
  const init = async () => {
    // 检查白名单
    try {
      const result = await chrome.storage.local.get(['customWhitelist'])
      const whitelist = result.customWhitelist || []
      if (whitelist.some(d => host === d || host.endsWith('.' + d))) return
    } catch (e) { /* storage may be unavailable */ }

    initialScan()
    initDynamicScan()
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init)
  } else {
    init()
  }

  // iframe scanning — 对标 FindSomething
  document.querySelectorAll('iframe').forEach(iframe => {
    try {
      iframe.addEventListener('load', () => {
        const doc = iframe.contentDocument || iframe.contentWindow?.document
        if (!doc) return
        const html = doc.documentElement?.outerHTML
        if (!html) return
        const apis = apiFilter.extract(html).map(p => ({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }))
        if (apis.length) {
          try { chrome.runtime.sendMessage({ action: 'passive', tasks: [], inlineScripts: [], apis, url: location.href, title: document.title + ' [iframe]', isUpdate: true }) } catch(e) {}
        }
      })
    } catch(e) {}
  })
})()