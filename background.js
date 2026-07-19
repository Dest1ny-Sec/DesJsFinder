// ============================================================
// Background — 被动收集+Fuzz+Badge
// ============================================================

// === 内联定义(Service Worker中importScripts有兼容问题) ===
class SvAPIFilter {
  extract(text) {
    // 与 filters/api-filter.js 完全一致的 6-pattern 提取逻辑
    if (!text||text.length<50) return []
    const found=new Set()
    const isStatic=p=>/\.(woff2?|ttf|eot|otf|jpe?g|png|gif|svg|webp|ico|bmp|jsx?|tsx?|vue|mjs|cjs|css|scss|sass|less|mp[34]|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg|pdf|docx?|xlsx?|pptx?|txt|md|csv)(\?.*)?$/i.test(p)
    let m
    // P1: LinkFinder/JSFinder absolute+relative paths
    const re1=/["'`]((?:\/|\.\.\/|\.\/)[^"'><,;|(){}\[\]\s]{1,200})["'`]/g
    while((m=re1.exec(text))!==null){const p=m[1];if(p.startsWith('/')&&p.length>=2&&!isStatic(p))found.add(p);else if(p.startsWith('.')&&p.length>=4&&!/\.(?:js|css|less|scss|png|jpg|gif|svg)$/i.test(p))found.add(p)}
    // P2: JSFinder Group4 relative resources with extensions
    const re2=/["'`]([a-zA-Z0-9_\-\.\/]{3,}\.(?:[a-zA-Z]{1,4}|action|do|jspa)(?:\?[^"'`]{0,})?)["'`]/g
    while((m=re2.exec(text))!==null)found.add(m[1])
    // P3: incomplete path (xx/yy → /xx/yy)
    const re3=/["'`]([a-zA-Z][\w\/\.\-]{3,150})["'`]/g
    while((m=re3.exec(text))!==null){const p=m[1];if(p.includes('/')&&!isStatic('/'+p)&&!/^https?:\/\//i.test(p))found.add('/'+p)}
    // P4: Vue/React route
    const re4=/(?:path|route|name)\s*:\s*["'`](\/[^"'`]{1,120})["'`]/gi
    while((m=re4.exec(text))!==null){const p=m[1];if(p.length>=2&&!isStatic(p))found.add(p)}
    // P5: dynamic import
    const re5=/(?:import|require)\s*\(\s*["'`](\.[^"'`]{1,120})["'`]\s*\)/g
    while((m=re5.exec(text))!==null){const p=m[1];if(p.length>=4&&!/\.(?:js|css|less|scss|sass|png|jpg|gif|svg)$/i.test(p))found.add(p)}
    // P6: url/base/prefix assignments
    const re6=/(?:url|base|prefix|api|href|action)\s*[:=]\s*["'`](\/[^"'`]{1,120})["'`]/gi
    while((m=re6.exec(text))!==null){const p=m[1];if(p.length>=2&&!isStatic(p))found.add(p)}
    return [...found]
  }
  method(p){const l=p.toLowerCase();if(/\/login|\/register|\/create|\/add|\/save|\/upload|\/submit|\/batch/.test(l))return'POST';if(/\/update|\/edit|\/modify/.test(l))return'PUT';if(/\/delete|\/remove/.test(l))return'DELETE';return'GET'}
  classify(p){const r=[{k:['/actuator','/heapdump','/env','/mappings','/shutdown','/restart','/threaddump','/configprops','/beans','/loggers','/metrics','/sessions'],l:'Actuator端点',r:'CRITICAL'},{k:['/login','/logout','/register','/auth','/token','/oauth','/sso','/signin','/forgot','/password','/captcha','/verify-code'],l:'认证鉴权',r:'HIGH'},{k:['/upload','/file/upload','/image/upload','/avatar/upload','/import'],l:'文件上传',r:'HIGH'},{k:['/admin/','/manage/','/console/','/system/','/monitor/','/dashboard'],l:'管理后台',r:'HIGH'},{k:['/order/','/trade/','/pay/','/payment/','/cart/','/checkout','/invoice','/refund'],l:'交易支付',r:'CRITICAL'},{k:['/user/','/member/','/account/','/profile','/role/','/permission','/org/','/dept/'],l:'用户管理',r:'HIGH'},{k:['/swagger','/api-docs','/doc.html','/openapi','/graphql','/graphiql'],l:'API文档',r:'HIGH'},{k:['/list','/page','/query','/search','/export','/import','/download','/report','/stat','/dict','/data'],l:'数据查询',r:'MEDIUM'},{k:['/create','/add','/save','/update','/edit','/modify','/delete','/remove','/batch','/submit'],l:'数据写入',r:'MEDIUM'},{k:['/health','/info','/ping','/status','/version','/metrics','/ready','/live'],l:'基础设施',r:'MEDIUM'},{k:['/callback','/webhook','/notify','/sync','/third/','/open/','/hook'],l:'第三方对接',r:'MEDIUM'},{k:['/.env','/.git/','/web.config','/elmah.axd','/trace.axd','/phpinfo','/info.php'],l:'敏感文件',r:'CRITICAL'},{k:['/sms','/send-sms','/send-code','/email/send','/mail/send'],l:'消息发送',r:'MEDIUM'},{k:['/bpm','/oa/','/workflow','/approval','/leave','/task'],l:'工作流',r:'MEDIUM'},{k:['/mall/','/product','/spu','/sku','/stock','/crm','/customer'],l:'业务模块',r:'MEDIUM'},{k:['/infra/','/file/','/codegen','/oss','/cos','/minio'],l:'基础设施',r:'MEDIUM'}];for(const x of r){if(x.k.some(k=>p.toLowerCase().includes(k.toLowerCase())))return{label:x.l,risk:x.r}}return{label:'API',risk:'INFO'}}
}

class SvFwDetect {
  detect(text){if(!text)return[];const sigs=[
    {n:'芋道Yudao',k:'yudao',p:'/admin-api',m:['/admin-api/','VITE_GLOB_API_URL_PREFIX','mall.yudao','iocoder','ruoyi']},
    {n:'若依Ruoyi',k:'ruoyi',p:'/',m:['ruoyi','RuoYi','/system/','/monitor/']},
    {n:'Spring Boot',k:'spring',p:'',m:['Whitelabel Error Page','actuator','spring-boot','api-docs','X-Application-Context']},
    {n:'Spring Cloud',k:'springcloud',p:'',m:['spring cloud','gateway','eureka','consul','nacos','sentinel']},
    {n:'ThinkPHP',k:'thinkphp',p:'',m:['thinkphp','ThinkPHP','runtime/log']},
    {n:'Laravel',k:'laravel',p:'/api',m:['csrf-token','laravel','XSRF-TOKEN','laravel_session']},
    {n:'FastAPI',k:'fastapi',p:'/api',m:['fastapi','OpenAPI','/docs','/redoc']},
    {n:'Django',k:'django',p:'/api',m:['csrfmiddlewaretoken','django','X-CSRFToken']},
    {n:'Flask',k:'flask',p:'/api',m:['flask','Werkzeug','jinja2']},
    {n:'ASP.NET',k:'aspnet',p:'',m:['__VIEWSTATE','__EVENTVALIDATION','ASP.NET','IIS','X-AspNet-Version']},
    {n:'Shiro',k:'shiro',p:'',m:['rememberMe=','shiro','org.apache.shiro']},
    {n:'Vue.js',k:'vue',p:'/api',m:['vue','__vue__','pinia','vuex','element-plus','ant-design-vue','nuxt']},
    {n:'React',k:'react',p:'/api',m:['react','react-dom','__INITIAL_STATE__','webpackJsonp','antd','next']},
    {n:'Angular',k:'angular',p:'/api',m:['angular','@angular','ng-version','zone.js']},
    {n:'Next.js',k:'nextjs',p:'/api',m:['_next/','__NEXT_DATA__','next/router']},
    {n:'Webpack',k:'webpack',p:'',m:['webpackJsonp','__webpack_require__','webpack-dev-server','webpackChunk']},
    {n:'Vite',k:'vite',p:'',m:['VITE_GLOB','@vitejs','vite-plugin','import.meta.hot']},
    {n:'ECharts',k:'echarts',p:'',m:['echarts','echarts.init','zrender']},
    {n:'jQuery',k:'jquery',p:'',m:['jQuery','$.ajax','$.get']},
    {n:'Node.js',k:'nodejs',p:'/api',m:['process.env','__dirname','require(','module.exports','Buffer.from']}
  ];const r=[];for(const s of sigs){let sc=0;for(const kw of s.m){if(text.includes(kw))sc+=30}if(sc>=60)r.push({name:s.n,key:s.k,prefix:s.p,score:sc})}return r.sort((a,b)=>b.score-a.score)}
  extractConfig(text){const cfg={};const ps=[[/VITE_GLOB_API_URL_PREFIX\s*[:=]\s*["']([^"']+)["']/,'apiPrefix'],[/VITE_GLOB_API_URL\s*[:=]\s*["']([^"']+)["']/,'apiUrl'],[/VITE_GLOB_UPLOAD_URL\s*[:=]\s*["']([^"']+)["']/,'uploadUrl'],[/VITE_GLOB_APP_TENANT_ENABLE\s*[:=]\s*["']([^"']+)["']/,'tenant'],[/VITE_GLOB_APP_CAPTCHA_ENABLE\s*[:=]\s*["']([^"']+)["']/,'captcha'],[/restfulUrl\s*[:=]\s*["']([^"']+)["']/,'restfulUrl'],[/api\s*[:=]\s*["']([^"']+)["']/,'apiHost'],[/baseURL\s*[:=]\s*["']([^"']+)["']/,'baseURL']];if(!text)return cfg;for(const[re,k]of ps){const m=text.match(re);if(m)cfg[k]=m[1]}return cfg}
}

class SvFingerprint {
  analyze(body,status){if(!body)return null;const fps=[{re:/"_links"[^}]{0,200}?(?:"actuator"|"heapdump"|"env"[^}]{0,100}?"href")/,t:'Actuator暴露!',r:'CRITICAL'},{re:/Whitelabel Error Page/,t:'Spring错误页',r:'HIGH'},{re:/thinkphp|ThinkPHP/,t:'ThinkPHP报错',r:'CRITICAL'},{re:/SQL syntax|mysql_fetch|SQLSTATE|ORA-/,t:'SQL错误',r:'CRITICAL'},{re:/Sensors Analytics is ready/,t:'神策Debug',r:'HIGH'},{re:/please provide valid app/,t:'API网关',r:'MEDIUM'},{re:/valid token is required/,t:'需认证',r:'INFO'},{re:/没有该操作权限|权限不足|access denied|forbidden/,t:'权限不足',r:'MEDIUM'},{re:/参数错误|参数不正确|missing parameter/,t:'参数校验',r:'INFO'},{re:/系统异常|系统内部错误|internal server error/,t:'服务端异常',r:'MEDIUM'},{re:/Index of \//,t:'目录遍历',r:'MEDIUM'},{re:/\.git\/HEAD|ref: refs\/heads/,t:'Git泄露',r:'CRITICAL'}];for(const fp of fps){if(fp.re.test(body))return{type:fp.t,risk:fp.r}}if(status===200&&body.startsWith('{')&&body.includes('"code":0'))return{type:'JSON成功',risk:'INFO'};if(status===500&&body.length>100)return{type:'500错误',risk:'MEDIUM'};return null}
}

const THIRD_PARTY_DOMAINS = [
  'google-analytics.com','googletagmanager.com','doubleclick.net','googleadservices.com',
  'baidu.com/hm','hm.baidu.com',
  'facebook.net','fbcdn.net','facebook.com/tr',
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
]
function isThirdParty(url) {
  try {
    const hostname = new URL(url).hostname
    for (const d of THIRD_PARTY_DOMAINS) {
      if (hostname === d || hostname.endsWith('.' + d)) return true
    }
  } catch(e) {}
  return false
}

const tabs = new Map()
const fetchingUrls = new Map()
function T(id) { if (!tabs.has(id)) tabs.set(id, { apis: [], fw: [], cfg: {}, jsN: 0, url: '', domains: [], ips: [], jwts: [], creds: [], storageItems: [], runtimeReqs: [], bodyParams: [], wap: [] }); return tabs.get(id) }
function getFetching(tabId) { if (!fetchingUrls.has(tabId)) fetchingUrls.set(tabId, new Set()); return fetchingUrls.get(tabId) }

// === SW persistence: restore on startup, save periodically ===
(async function restoreState() {
  try {
    const stored = await chrome.storage.session.get('tabSnapshots')
    if (stored.tabSnapshots) {
      for (const [id, data] of Object.entries(stored.tabSnapshots)) {
        const numId = parseInt(id)
        if (!tabs.has(numId)) {
          // restore with fresh maps/arrays
          tabs.set(numId, { ...data, processing: false })
        }
      }
    }
  } catch (e) { /* ignore */ }
})()
function persistState() {
  try {
    const snap = {}
    tabs.forEach((v, k) => {
      if (v.apis?.length || v.domains?.length) snap[k] = { ...v, processing: false }
    })
    if (Object.keys(snap).length) chrome.storage.session.set({ tabSnapshots: snap })
  } catch (e) { /* ignore */ }
}
setInterval(persistState, 5000) // every 5s

// === content发来的被动数据 ===
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'passive') {
    const t = T(sender.tab?.id); if (!sender.tab?.id) return
    t.url = msg.url; t.title = msg.title
    // 合并框架 (不覆盖)
    if (msg.fw?.length) {
      const existKeys = new Set(t.fw.map(f => f.key))
      for (const f of msg.fw) { if (!existKeys.has(f.key)) { t.fw.push(f); existKeys.add(f.key) } }
    }
    t.cfg = msg.cfg || t.cfg || {}; t.forms = msg.forms || t.forms || []
    mergeAPIs(t, msg.apis || [])
    // 合并其他信息类型
    const mergeList = (field, list) => {
      if (!list || !list.length) return
      // Items can be plain strings or arrays [value, source]
      const existing = new Set((t[field] || []).map(x => Array.isArray(x) ? x[0] : (typeof x === 'string' ? x : (x.value ?? x))))
      for (const item of list) {
        const key = Array.isArray(item) ? item[0] : (typeof item === 'string' ? item : (item.value ?? item))
        if (key && !existing.has(key)) { t[field].push(item); existing.add(key) }
      }
    }
    mergeList('domains', msg.domains)
    mergeList('ips', msg.ips)
    mergeList('jwts', msg.jwts)
    mergeList('creds', msg.creds)
    // storage scan results
    if (msg.storageItems?.length) {
      const exist = new Set(t.storageItems)
      for (const s of msg.storageItems) { if (!exist.has(s)) { t.storageItems.push(s); exist.add(s) } }
    }
    // runtime intercepted requests
    if (msg.runtimeReq) {
      const r = msg.runtimeReq
      r.respBody = (r.respBody || '').slice(0, 1024) // cap for storage
      // dedup by pathname+method (ignore varying query params)
      let rPath = r.url; try { rPath = new URL(r.url).pathname } catch(e) {}
      const dup = t.runtimeReqs.some(x => {
        let xPath = x.url; try { xPath = new URL(x.url).pathname } catch(e) {}
        return xPath === rPath && x.method === r.method
      })
      if (!dup && t.runtimeReqs.length < 400) t.runtimeReqs.push(r)
    }
    // accumulate POST body param keys
    if (msg.bodyParams?.length) {
      const exist = new Set(t.bodyParams)
      for (const k of msg.bodyParams) { if (!exist.has(k)) { t.bodyParams.push(k); exist.add(k) } }
    }
    // Wappalyzer 指纹结果 (按 name 去重合并)
    if (msg.wap?.length) {
      const existNames = new Set(t.wap.map(w => w.name))
      for (const w of msg.wap) {
        if (!existNames.has(w.name)) { t.wap.push(w); existNames.add(w.name) }
        else {
          // Update confidence if new result is higher
          const existing = t.wap.find(ew => ew.name === w.name)
          if (existing && w.confidence > existing.confidence) {
            existing.confidence = w.confidence
            if (w.version && !existing.version) existing.version = w.version
          }
        }
      }
    }
    badge(sender.tab.id)
    // 异步处理
    processInline(t, msg.inlineScripts || [])
    downloadJS(sender.tab.id, msg.tasks || [])
    sendResponse({ ok: true })
  }
  if (msg.action === 'getData') { chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => { const d = t ? T(t.id) : {}; sendResponse({ ...d, tabId: t?.id, capturedToken: d._token || '' }) }); return true }
  if (msg.action === 'storeToken') { if (sender.tab?.id) T(sender.tab.id)._token = msg.token; return true }
  if (msg.action === 'fuzz') { fuzzURL(msg.url, msg.method, { ...msg.headers, _tabId: sender.tab?.id }).then(sendResponse); return true }
  if (msg.action === 'clear') { chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => { if (t) { const fresh = { apis: [], fw: [], cfg: {}, jsN: 0, url: '', domains: [], ips: [], jwts: [], creds: [], storageItems: [], runtimeReqs: [], bodyParams: [], wap: [] }; tabs.set(t.id, fresh) }; badge(t?.id) }); sendResponse({ ok: true }) }
})

// === 网站解析 (ICP / IP / 权重) ===
async function handleSiteAnalysis(msg, sender, sendResponse) {
  const { domain, tabId } = msg
  // 先检查缓存
  try {
    const cacheKey = `analysis_${domain}`
    const cached = await chrome.storage.session.get(cacheKey)
    if (cached[cacheKey] && cached[cacheKey].ts && Date.now() - cached[cacheKey].ts < 3600000) {
      sendResponse(cached[cacheKey].data)
      return true
    }
  } catch (e) { /* ignore */ }

  const result = { domain, icp: null, ip: null, weight: null }

  // 并行查询
  const [icpData, ipData] = await Promise.all([
    fetchIcpInfo(domain),
    fetchIpInfo(domain)
  ]).catch(() => [null, null])

  result.icp = icpData
  result.ip = ipData

  // 缓存1小时
  try {
    await chrome.storage.session.set({ [`analysis_${domain}`]: { data: result, ts: Date.now() } })
  } catch (e) { /* ignore */ }

  sendResponse(result)
  return true
}

async function fetchIcpInfo(domain) {
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/
  if (ipv4.test(domain)) return { icp: 'IP地址不适用', unit: '-', time: '-' }
  try {
    const cfg = await chrome.storage.local.get(['icpApiId', 'icpApiKey']).catch(() => ({}))
    const id = cfg.icpApiId || '', key = cfg.icpApiKey || ''
    if (!id || !key) return { icp: '请在设置中配置ICP API密钥', unit: '-', time: '-' }
    const r = await fetch(`https://cn.apihz.cn/api/wangzhan/icp.php?id=${encodeURIComponent(id)}&key=${encodeURIComponent(key)}&domain=${encodeURIComponent(domain)}`)
    if (!r.ok) return null
    const data = await r.json()
    if (data.code === 404) return { icp: '未查询到备案信息', unit: '未知', time: '未知' }
    return { icp: data.data?.icp || data.data?.icp_no || '-', unit: data.data?.unit || '-', time: data.data?.time || '-' }
  } catch (e) { return null }
}

async function fetchIpInfo(domain) {
  try {
    const cfg = await chrome.storage.local.get(['ipApiId', 'ipApiKey']).catch(() => ({}))
    const id = cfg.ipApiId || '', key = cfg.ipApiKey || ''
    if (!id || !key) return { ip: domain, location: '请在设置中配置IP API密钥', isp: '-' }
    const r = await fetch(`https://cn.apihz.cn/api/ip/ip_json.php?id=${encodeURIComponent(id)}&key=${encodeURIComponent(key)}&ip=${encodeURIComponent(domain)}`)
    if (!r.ok) return null
    const data = await r.json()
    if (data.data) return { ip: data.data?.ip || domain, location: [data.data?.country, data.data?.region, data.data?.city].filter(Boolean).join(' ') || '-', isp: data.data?.isp || '-' }
    return null
  } catch (e) { return null }
}

function mergeAPIs(t, newAPIs) {
  const seen = new Set(t.apis.map(a => a.path + a.method))
  for (const a of newAPIs) { if (!seen.has(a.path + a.method) && t.apis.length < 600) { t.apis.push(a); seen.add(a.path + a.method) } }
}

// === 内联脚本直接提取(不走网络) ===
function processInline(t, scripts) {
  const apiFilter = new SvAPIFilter(), fwDetect = new SvFwDetect()
  const seen = new Set(t.apis.map(a => a.path + a.method))
  for (const text of scripts) {
    for (const p of (apiFilter.extract(text) || [])) {
      const m = apiFilter.method(p)
      if (!seen.has(p + m) && t.apis.length < 600) { seen.add(p + m); t.apis.push({ path: p, method: m, classify: apiFilter.classify(p) }) }
    }
  }
  // 框架+配置 — append newly detected frameworks
  if (scripts.length) {
    const newFw = fwDetect.detect(scripts.join('\n')) || []
    for (const nf of newFw) {
      if (!t.fw.some(f => f.key === nf.key)) t.fw.push(nf)
    }
  }
  scripts.forEach(s => Object.assign(t.cfg, fwDetect.extractConfig(s) || {}))
}

// === 下载外部JS (CORS降级: fetch→chrome.scripting注入) ===
async function downloadJS(tabId, tasks) {
  const t = T(tabId)
  const fetching = getFetching(tabId)
  // filter out already-fetching URLs
  const fresh = (tasks || []).filter(u => u.startsWith('http') && !fetching.has(u) && !isThirdParty(u))
  if (!fresh.length) return
  fresh.forEach(u => fetching.add(u))
  const apiFilter = new SvAPIFilter(), fwDetect = new SvFwDetect()
  const seenApis = new Set(t.apis.map(a => a.path))
  const seenDomains = new Set((t.domains||[]).map(d => typeof d === 'string' ? d : d[0]))
  const seenIps = new Set((t.ips||[]).map(d => typeof d === 'string' ? d : d[0]))

  for (const url of fresh) {
    try {
      const text = await fetchWithFallback(tabId, url)
      if (!text || text.length < 100) continue

      for (const p of (apiFilter.extract(text) || [])) { if (!seenApis.has(p) && t.apis.length < 600) { seenApis.add(p); t.apis.push({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }) } }

      const newFw = fwDetect.detect(text) || []
      for (const nf of newFw) { if (!t.fw.some(f => f.key === nf.key)) t.fw.push(nf) }
      Object.assign(t.cfg, fwDetect.extractConfig(text) || {})

      const domains = extractDomains(text)
      const ips = extractIps(text)
      for (const d of domains) { if (!seenDomains.has(d)) { seenDomains.add(d); t.domains.push(d) } }
      for (const ip of ips) { if (!seenIps.has(ip)) { seenIps.add(ip); t.ips.push(ip) } }

      t.jsN = (t.jsN || 0) + 1; badge(tabId)
    } catch (e) { /* skip */ }
  }
  badge(tabId)
}

// 简单域名提取（background环境，无需依赖Extractor）
function extractDomains(text) {
  const re = /(?:\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+(?:[a-zA-Z]{2,63})(?:\:\d{1,5})?\b/gi
  const tlds = /\.(?:com|cn|net|org|io|cc|top|vip|xyz|club|site|online|tech|store|wang|fun|space|info|pro|biz|co|me|tv|mobi|asia|studio|design|law|shop|art|press|icu|link|fan|cloud|games|cash|cafe|band|media|work|ren|yoga|red|luxe|fashion|technology|ski|pink|host|kim|pet|run|pub|chat|group|live|city|cool|fund|gold|guru|life|team|today|world|zone|social|bio|black|blue|green|lotto|organic|poker|promo|vote|archi|voto|fit|web|app|dev|ai|email|video|market|shopping|mba|sale|news|fyi|tax|gov|edu|mil)$/i
  const found = []; let m
  while ((m = re.exec(text)) !== null) {
    const d = m[0]
    if (/^(?:localhost|127\.|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/.test(d)) continue
    const hostOnly = d.replace(/:\d+$/, '')
    if (!tlds.test(hostOnly)) continue
    if (/\.(?:js|css|png|jpe?g|gif|svg|woff2?|ttf|eot|json|xml|html?|mp[34]|pdf|zip|tar|gz)$/i.test(hostOnly)) continue
    found.push(d)
  }
  return [...new Set(found)]
}
function extractIps(text) {
  const re = /(?<!\.|\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?::\d{1,5})?/g
  const found = []; let m
  while ((m = re.exec(text)) !== null) { const ip = m[0].split(':')[0]; if (!/^(?:0\.0\.0\.0|255\.255\.255\.255|127\.0\.0\.1)$/.test(ip)) found.push(m[0]) }
  return [...new Set(found)]
}

// fetch 降级: 先直接fetch, CORS失败则注入页面上下文
async function fetchWithFallback(tabId, url, fetchHeaders) {
  try {
    const r = await fetch(url, { mode: 'cors', headers: { 'Accept': '*/*' } })
    if (!r.ok) return null
    return await r.text()
  } catch (e) {
    // CORS blocked — fallback to page-context fetch via scripting
    if (tabId && tabId > 0) {
      try {
        const { _tabId: _ti, ...fetchHdrs } = fetchHeaders || {}
        const results = await chrome.scripting.executeScript({
          target: { tabId },
          func: (u, hdrs) => fetch(u, { credentials: 'omit', headers: hdrs || {} }).then(r => r.text()).catch(() => null),
          args: [url, fetchHdrs]
        })
        return results?.[0]?.result || null
      } catch (e2) { return null }
    }
    return null
  }
}

function badge(tabId) {
  if (!tabId || tabId < 0) return
  const t = tabs.get(tabId)
  if (!t) return
  let total = 0
  const fields = ['apis', 'domains', 'ips', 'jwts', 'creds', 'storageItems', 'runtimeReqs', 'wap']
  for (const f of fields) { if (t[f]) total += t[f].length }
  const text = total > 0 ? (total > 999 ? '1k+' : String(total)) : ''
  chrome.action.setBadgeText({ text, tabId })
  chrome.action.setBadgeBackgroundColor({ color: total > 10 ? '#e94560' : '#f39c12', tabId })
}

// ============================================================
// Offscreen Document 管理 (借鉴 Phantom)
// ============================================================
let _offscreenCreating = false, _offscreenReady = false, _offscreenChecking = false

async function ensureOffscreen() {
  // Return cached if known ready
  if (_offscreenReady) return true
  if (_offscreenCreating) {
    // Wait up to 1s for creation to finish
    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 100))
      if (_offscreenReady) return true
    }
    return false
  }
  _offscreenCreating = true
  try {
    // Check if already exists
    const existing = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] })
    if (existing.length > 0) {
      _offscreenReady = true
      // Verify responsive
      try {
        const resp = await chrome.runtime.sendMessage({ action: 'ping' })
        if (resp?.pong) { _offscreenCreating = false; return true }
      } catch(e) {
        // Need to recreate
        _offscreenReady = false
      }
    }
    // Close stale offscreen
    try { await chrome.offscreen.closeDocument() } catch(e) {}

    await chrome.offscreen.createDocument({
      url: 'offscreen.html',
      reasons: ['DOM_SCRAPING'],
      justification: '发送带Cookie和自定义Headers的Fuzz请求'
    })
    // Wait for it to be ready
    await new Promise(r => setTimeout(r, 200))
    _offscreenReady = true
    return true
  } catch(e) {
    if (e.message?.includes('single offscreen')) {
      _offscreenReady = true
      return true
    }
    console.warn('[DesJsFinder] Offscreen create failed:', e.message)
    return false
  } finally {
    _offscreenCreating = false
  }
}

// ============================================================
// declarativeNetRequest 动态 Header 注入
// ============================================================
let _headerRuleId = 100
async function injectHeadersForDomain(hostname, headers) {
  if (!hostname || !headers || !Object.keys(headers).length) return
  try {
    const requestHeaders = []
    for (const [key, value] of Object.entries(headers)) {
      if (!key || !value) continue
      const lk = key.toLowerCase()
      // Skip content-type (auto-set by fetch), skip forbidden headers
      if (['content-type','content-length','host','origin','referer'].includes(lk)) continue
      requestHeaders.push({ header: key, operation: 'set', value: value })
    }
    if (!requestHeaders.length) return

    const ruleId = _headerRuleId++
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id: ruleId,
        priority: 1,
        action: { type: 'modifyHeaders', requestHeaders },
        condition: { urlFilter: `*://${hostname}/*`, resourceTypes: ['xmlhttprequest','other'] }
      }],
      removeRuleIds: [ruleId - 1] // remove previous rule
    })
    // Store for cleanup
    self.__dnrRuleId = ruleId
  } catch(e) {
    console.warn('[DesJsFinder] declarativeNetRequest rule failed:', e.message)
  }
}

async function removeHeaderInjection() {
  try {
    const ids = []
    if (self.__dnrRuleId) ids.push(self.__dnrRuleId)
    if (ids.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ids })
    self.__dnrRuleId = 0
  } catch(e) {}
}

// ============================================================
// Fuzz URL — 优先使用 offscreen document (带 Cookie)
// ============================================================
async function fuzzURL(url, method, headers) {
  const fetchHeaders = { ...headers }
  let body = undefined
  if (method === 'POST') {
    fetchHeaders['Content-Type'] = 'application/json'
    body = '{}'
  }
  const _tabId = fetchHeaders._tabId
  delete fetchHeaders._tabId

  // Clean up internal/forbidden headers
  for (const k of Object.keys(fetchHeaders)) {
    const lk = k.toLowerCase()
    if (['host','origin','referer','content-length'].includes(lk)) delete fetchHeaders[k]
  }

  const _doDirectFetch = async (methodOverride, bodyOverride) => {
    try {
      const r = await fetch(url, { method: methodOverride, headers: { ...fetchHeaders }, body: bodyOverride, mode: 'cors' })
      const text = await r.text()
      return { url, method: methodOverride, status: r.status, size: text.length, body: text.substring(0, 2000), contentType: r.headers.get('content-type')||'' }
    } catch(e) { return null }
  }

  // First try: direct fetch (fast path, works for most non-auth APIs)
  let res = await _doDirectFetch(method, body)

  // POST retry logic for direct fetch
  if (method === 'POST' && res && res.status === 400 && !(res.contentType||'').includes('json')) {
    fetchHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
    res = await _doDirectFetch(method, 'id=1') || res
  }
  if (method === 'POST' && res && res.status === 400) {
    delete fetchHeaders['Content-Type']
    const gr = await _doDirectFetch('GET', undefined)
    if (gr && gr.status < 400) res = { ...gr, method: 'POST→GET' }
  }

  // If direct fetch got a non-error response, return it
  if (res && res.status > 0 && res.status !== 0) {
    const fp = (RESP_FP_LOADED ? new ResponseFingerprint() : new SvFingerprint()).analyze(res.body, res.status)
    return { ...res, fp }
  }

  // Direct fetch failed (CORS / network error) — try offscreen document
  const hasAuth = fetchHeaders['authorization'] || fetchHeaders['cookie'] ||
    Object.keys(fetchHeaders).some(k => k.toLowerCase() === 'authorization' || k.toLowerCase() === 'cookie')

  if (res && res.status === 0 && hasAuth) {
    try {
      const offscreenReady = await ensureOffscreen()
      if (offscreenReady) {
        const resp = await chrome.runtime.sendMessage({
          action: 'offscreenFetch',
          id: Date.now(),
          url, method: method, headers: fetchHeaders, body: body,
          timeout: 8000
        })
        if (resp?.success && resp.data && resp.data.status > 0) {
          const r = resp.data
          const fp = (RESP_FP_LOADED ? new ResponseFingerprint() : new SvFingerprint()).analyze(r.body || '', r.status)
          return { url, method: r.status === 0 ? method : method, status: r.status, size: r.size || 0, body: r.body?.substring(0, 2000) || '', contentType: r.contentType || '', fp }
        }
      }
    } catch(e) {
      // Offscreen failed, continue to CORS fallback
    }
  }

  // Second chance: if we got a direct result, return with fingerprint
  if (res) {
    const fp = (RESP_FP_LOADED ? new ResponseFingerprint() : new SvFingerprint()).analyze(res.body, res.status)
    return { ...res, fp }
  }

  // Ultimate fallback: CORS fallback via page context scripting
  if (_tabId && _tabId > 0) {
    for (const tryMethod of [method, 'GET']) {
      try {
        const text = await fetchWithFallback(_tabId, url, fetchHeaders)
        if (text) {
          const fp = (RESP_FP_LOADED ? new ResponseFingerprint() : new SvFingerprint()).analyze(text, 200)
          return { url, method: tryMethod, status: 200, size: text.length, body: text.substring(0, 2000), contentType: 'text/html', fp }
        }
      } catch(e2) {}
    }
  }
  return { url, method, status: 0, size: 0, body: 'network error', error: true }
}

chrome.tabs.onRemoved.addListener(id => { tabs.delete(id); fetchingUrls.delete(id) })

// ============================================================
// TideFinger 指纹加载 (5334条header关键词, 207KB)
// ============================================================
let TIDE_FP_LOADED = false, RESP_FP_LOADED = false
try {
  importScripts('filters/tide-fingerprint.js')
  TIDE_FP_LOADED = true
  console.log('[DesJsFinder] TideFinger loaded: ' + Object.keys(self.TIDE_H||{}).length + ' fingerprints')
} catch(e) { console.warn('TideFinger load failed:', e) }
try {
  importScripts('filters/response-fingerprint.js')
  RESP_FP_LOADED = true
  console.log('[DesJsFinder] ResponseFingerprint loaded')
} catch(e) { console.warn('ResponseFingerprint load failed:', e) }

// 头指纹配置 (TideFinger升级版)
const HEADER_FPS = [
  { type: 'server', name: 'Apache', pattern: /apache\/?([\d\.]+)?/i, header: 'server', value: 'version' },
  { type: 'server', name: 'Apache Tomcat', pattern: /apache-(coyote)\/?([\d\.]+)?/i, header: 'server', value: 'component,version', extType: 'technology', extName: 'Java' },
  { type: 'server', name: 'Nginx', pattern: /nginx\/?([\d\.]+)?/i, header: 'server', value: 'version' },
  { type: 'server', name: 'IIS', pattern: /microsoft-iis\/?([\d\.]+)?/i, header: 'server', value: 'version', extType: 'os', extName: 'Windows' },
  { type: 'server', name: 'Jetty', pattern: /jetty\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version', extType: 'technology', extName: 'Java' },
  { type: 'server', name: 'OpenResty', pattern: /openresty\/?([\d\.]+)?/i, header: 'server', value: 'version', extType: 'server', extName: 'Nginx' },
  { type: 'server', name: 'Tengine', pattern: /tengine\/?([\d\.]+)?/i, header: 'server', value: 'version' },
  { type: 'server', name: 'Cloudflare', pattern: /cloudflare\/?([\d\.]+)?/i, header: 'server', value: 'version' },
  { type: 'framework', name: 'Spring Boot', pattern: /([a-zA-Z0-9\.\-]+):([a-zA-Z0-9\-]+):(\d+)/i, header: 'x-application-context', value: 'app,env,port', extType: 'technology', extName: 'Java' },
  { type: 'framework', name: 'ASP.NET', pattern: /[0-9.]+/i, header: 'x-aspnet-version', value: 'version' },
  { type: 'framework', name: 'Express', pattern: /express/i, header: 'x-powered-by', extType: 'technology', extName: 'Node.js' },
  { type: 'technology', name: 'PHP', pattern: /php\/?([\d\.]+)?/i, header: 'x-powered-by', value: 'version' },
  { type: 'technology', name: 'Java', pattern: /java/i, header: 'x-powered-by' },
  { type: 'technology', name: 'Python', pattern: /python\/?([\d\.]+)?/i, header: 'server', value: 'version' },
  { type: 'security', name: 'HSTS', pattern: /max-age=(\d+)/i, header: 'strict-transport-security', value: 'time' },
  { type: 'cdn', name: 'CDN', pattern: /cdn/i, header: 'server' },
]

const COOKIE_FPS = [
  { type: 'technology', name: 'PHP', match: /PHPSESSID/i, desc: 'Cookie包含PHPSESSID，网站使用PHP' },
  { type: 'framework', name: 'ASP.NET', match: /ASP\.NET_SessionId|ASPSESSIONID/i, desc: 'Cookie包含ASP.NET Session，网站使用ASP.NET框架' },
  { type: 'technology', name: 'Java', match: /JSESSIONID|jeesite/i, desc: 'Cookie包含JSESSIONID，网站使用Java技术栈' },
  { type: 'framework', name: 'Shiro', match: /rememberMe/i, desc: 'Cookie包含rememberMe，网站可能使用Apache Shiro框架' },
  { type: 'framework', name: 'Laravel', match: /laravel_session/i, desc: 'Cookie包含laravel_session，网站使用Laravel框架' },
]

// 从响应头提取指纹
function processHeaders(headers, tabId) {
  const t = T(tabId)
  const headerMap = new Map(headers.map(h => [h.name.toLowerCase(), h.value]))
  const fps = []
  // 1. Built-in regex patterns (16 entries)
  for (const fp of HEADER_FPS) {
    const val = headerMap.get(fp.header.toLowerCase())
    if (val && !t.fw.some(f => f.key === fp.name.toLowerCase())) {
      const m = val.match(fp.pattern)
      if (m) {
        let desc = `通过${fp.header}头识别到${fp.name}`
        if (fp.value) { const parts = fp.value.split(','); desc += ' (' + parts.map((p, i) => p+'='+(m[i+1]||'?')).join(', ') + ')' }
        fps.push({ type: fp.type, name: fp.name, key: fp.name.toLowerCase(), description: desc, version: fp.name, prefix: '', score: 80 })
      }
    }
  }
  // 2. TideFinger header keywords
  if (TIDE_FP_LOADED && typeof self.TIDE_H !== 'undefined') {
    const hdrs = ['server','x-powered-by','set-cookie']
    const keywords = Object.keys(self.TIDE_H)
    const matched = new Set()
    for (const h of hdrs) {
      const val = headerMap.get(h)
      if (!val) continue
      const lv = val.toLowerCase()
      for (const kw of keywords) {
        if (lv.includes(kw)) {
          const product = self.TIDE_H[kw].split(',')[0]
          if (product && !matched.has(product)) {
            matched.add(product)
            fps.push({ type: 'technology', name: product, key: product.toLowerCase(), description: product, version: product, prefix: '', score: 70 })
          }
        }
      }
    }
  }
  return fps
}

function processCookies(cookieStr) {
  const fps = []
  for (const fp of COOKIE_FPS) {
    if (fp.match.test(cookieStr)) {
      fps.push({ type: fp.type, name: fp.name, description: fp.desc })
    }
  }
  return fps
}

// 监听响应头
if (chrome.webRequest) {
  chrome.webRequest.onHeadersReceived.addListener(
    details => {
      if (details.type !== 'main_frame') return { responseHeaders: details.responseHeaders }
      const tabId = details.tabId
      if (tabId && tabId > 0) {
        const t = T(tabId)
        const fps = processHeaders(details.responseHeaders || [], tabId)
        for (const fp of fps) {
          if (!t.fw.some(f => f.key === fp.name.toLowerCase())) {
            t.fw.push({ name: fp.name, key: fp.name.toLowerCase(), prefix: '', score: 80 })
          }
        }
        // Cookie识别
        const cookieHeader = (details.responseHeaders || []).find(h => h.name.toLowerCase() === 'set-cookie')
        if (cookieHeader) {
          const cookieFps = processCookies(cookieHeader.value)
          for (const cfp of cookieFps) {
            if (!t.fw.some(f => f.key === cfp.name.toLowerCase())) {
              t.fw.push({ name: cfp.name, key: cfp.name.toLowerCase(), prefix: '', score: 70 })
            }
          }
        }
        badge(tabId)
      }
      return { responseHeaders: details.responseHeaders }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
  )

  // 拦截JS请求,自动下载分析
  chrome.webRequest.onBeforeRequest.addListener(
    details => {
      const { tabId, url, type } = details
      if (type !== 'script' || tabId < 0 || !url.startsWith('http') || isThirdParty(url)) return
      const fetching = getFetching(tabId)
      if (fetching.has(url)) return
      fetching.add(url)
      const t = T(tabId)
      t.jsN = (t.jsN || 0) + 1
      badge(tabId)
      // async download — don't block the listener
      downloadJS(tabId, [url]).catch(() => {})
    },
    { urls: ['<all_urls>'] },
    []
  )
}
