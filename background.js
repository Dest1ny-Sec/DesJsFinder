// ============================================================
// Background — 被动收集+Fuzz+Badge
// ============================================================

// === 内联定义(Service Worker中importScripts有兼容问题) ===
class SvAPIFilter {
  extract(text) { if (!text||text.length<50) return []; const found=new Set(); const re=/["'`](\/(?:[a-zA-Z0-9][a-zA-Z0-9\/_\-\.]{2,120}))["'`]/g; let m; while((m=re.exec(text))!==null){const p=m[1];if(!/\.(woff2?|ttf|eot|otf|jpe?g|png|gif|svg|webp|ico|bmp|jsx?|tsx?|vue|mjs|cjs|css|scss|sass|less|mp[34]|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg|pdf|docx?|xlsx?|pptx?|txt|md|csv)(\?.*)?$/i.test(p)) found.add(p)} return [...found] }
  method(p){const l=p.toLowerCase();if(/\/login|\/register|\/create|\/add|\/save|\/upload|\/submit|\/batch/.test(l))return'POST';if(/\/update|\/edit|\/modify/.test(l))return'PUT';if(/\/delete|\/remove/.test(l))return'DELETE';return'GET'}
  classify(p){const r=[{k:['/actuator','/heapdump','/env','/mappings'],l:'Actuator端点',r:'CRITICAL'},{k:['/login','/logout','/auth','/token','/oauth','/sso','/register','/reset','/password'],l:'认证鉴权',r:'HIGH'},{k:['/upload','/file/upload'],l:'文件上传',r:'HIGH'},{k:['/admin/','/manage/','/console/','/system/','/monitor/'],l:'管理后台',r:'HIGH'},{k:['/order/','/trade/','/pay/','/cart/','/checkout/'],l:'交易支付',r:'CRITICAL'},{k:['/user/','/member/','/account/','/profile','/role/'],l:'用户管理',r:'HIGH'},{k:['/swagger','/api-docs','/doc.html'],l:'API文档',r:'HIGH'},{k:['/list','/page','/query','/search','/export','/import','/dict'],l:'数据查询',r:'MEDIUM'},{k:['/create','/add','/save','/update','/edit','/delete','/remove'],l:'数据写入',r:'MEDIUM'},{k:['/.env','/.git/','/web.config','/elmah.axd'],l:'敏感文件',r:'CRITICAL'}];for(const x of r){if(x.k.some(k=>p.toLowerCase().includes(k.toLowerCase())))return{label:x.l,risk:x.r}}return{label:'API',risk:'INFO'}}
}

class SvFwDetect {
  detect(text){if(!text)return[];const sigs=[{n:'芋道Yudao',k:'yudao',p:'/admin-api',m:['/admin-api/','VITE_GLOB_API_URL_PREFIX','mall.yudao']},{n:'SpringBoot',k:'spring',p:'',m:['Whitelabel Error Page','actuator','spring-boot','api-docs']},{n:'ThinkPHP',k:'thinkphp',p:'',m:['thinkphp','ThinkPHP','runtime/log']},{n:'ASP.NET',k:'aspnet',p:'',m:['__VIEWSTATE','ASP.NET','IIS']},{n:'Laravel',k:'laravel',p:'/api',m:['csrf-token','laravel','XSRF-TOKEN']},{n:'Shiro',k:'shiro',p:'',m:['rememberMe=','shiro','apache.shiro']},{n:'Vue',k:'vue',p:'/api',m:['vue','__vue__','pinia','vuex','element-plus']},{n:'React',k:'react',p:'/api',m:['react','react-dom','__INITIAL_STATE__','webpackJsonp']}];const r=[];for(const s of sigs){let sc=0;for(const kw of s.m){if(text.includes(kw))sc+=30}if(sc>=60)r.push({name:s.n,key:s.k,prefix:s.p,score:sc})}return r.sort((a,b)=>b.score-a.score)}
  extractConfig(text){const cfg={};const ps=[[/VITE_GLOB_API_URL_PREFIX\s*[:=]\s*["']([^"']+)["']/,'apiPrefix'],[/VITE_GLOB_API_URL\s*[:=]\s*["']([^"']+)["']/,'apiUrl'],[/VITE_GLOB_UPLOAD_URL\s*[:=]\s*["']([^"']+)["']/,'uploadUrl'],[/VITE_GLOB_APP_TENANT_ENABLE\s*[:=]\s*["']([^"']+)["']/,'tenant'],[/VITE_GLOB_APP_CAPTCHA_ENABLE\s*[:=]\s*["']([^"']+)["']/,'captcha']];if(!text)return cfg;for(const[re,k]of ps){const m=text.match(re);if(m)cfg[k]=m[1]}return cfg}
}

class SvFingerprint {
  analyze(body,status){if(!body)return null;const fps=[{re:/"_links".*"actuator"|"heapdump"|"env".*"href"/,t:'Actuator暴露!',r:'CRITICAL'},{re:/Whitelabel Error Page/,t:'Spring错误页',r:'HIGH'},{re:/thinkphp|ThinkPHP/,t:'ThinkPHP报错',r:'CRITICAL'},{re:/SQL syntax|mysql_fetch|SQLSTATE|ORA-/,t:'SQL错误',r:'CRITICAL'},{re:/Sensors Analytics is ready/,t:'神策Debug',r:'HIGH'},{re:/please provide valid app/,t:'API网关',r:'MEDIUM'},{re:/valid token is required/,t:'需认证',r:'INFO'},{re:/没有该操作权限/,t:'权限不足',r:'MEDIUM'},{re:/参数错误|参数不正确/,t:'参数校验',r:'INFO'},{re:/系统异常/,t:'服务端异常',r:'MEDIUM'},{re:/Index of \//,t:'目录遍历',r:'MEDIUM'},{re:/\.git\/HEAD|ref: refs/,t:'Git泄露',r:'CRITICAL'}];for(const fp of fps){if(fp.re.test(body))return{type:fp.t,risk:fp.r}}if(status===200&&body.startsWith('{')&&body.includes('"code":0'))return{type:'JSON成功',risk:'INFO'};if(status===500&&body.length>100)return{type:'500错误',risk:'MEDIUM'};return null}
}

// === 字典生成(MV3 service worker中用importScripts加载dict) ===
try { importScripts('src/core/dict-generator.js') } catch(e) { console.warn('DictGenerator load failed:', e) }

const tabs = new Map()
function T(id) { if (!tabs.has(id)) tabs.set(id, { apis: [], fw: [], cfg: {}, jsN: 0, forms: [], url: '', title: '', processing: false }); return tabs.get(id) }

// === content发来的被动数据 ===
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'passive') {
    const t = T(sender.tab?.id); if (!sender.tab?.id) return
    t.url = msg.url; t.title = msg.title; t.fw = msg.fw || []; t.cfg = msg.cfg || {}; t.forms = msg.forms || []
    mergeAPIs(t, msg.apis || [])
    badge(sender.tab.id)
    // 异步处理
    processInline(t, msg.inlineScripts || [])
    t.processing = true
    downloadJS(sender.tab.id, msg.tasks || [])
    sendResponse({ ok: true })
  }
  if (msg.action === 'getData') { chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => sendResponse(T(t?.id) || {})); return true }
  if (msg.action === 'fuzz') { fuzzURL(msg.url, msg.method, msg.headers).then(sendResponse); return true }
  if (msg.action === 'clear') { chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => { if (t) tabs.delete(t.id); badge(t?.id) }); sendResponse({ ok: true }) }
})

function mergeAPIs(t, newAPIs) {
  const seen = new Set(t.apis.map(a => a.path + a.method))
  for (const a of newAPIs) { if (!seen.has(a.path + a.method) && t.apis.length < 600) { t.apis.push(a); seen.add(a.path + a.method) } }
}

// === 内联脚本直接提取(不走网络) ===
function processInline(t, scripts) {
  const apiFilter = new SvAPIFilter(), fwDetect = new SvFwDetect()
  const seen = new Set(t.apis.map(a => a.path))
  for (const text of scripts) {
    for (const p of (apiFilter.extract(text) || [])) {
      if (!seen.has(p) && t.apis.length < 600) { seen.add(p); t.apis.push({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }) }
    }
  }
  // 框架+配置
  if (!t.fw.length && scripts.length) t.fw = fwDetect.detect(scripts.join('\n')) || []
  scripts.forEach(s => Object.assign(t.cfg, fwDetect.extractConfig(s) || {}))
}

// === 下载外部JS ===
async function downloadJS(tabId, tasks) {
  const t = T(tabId)
  const apiFilter = new SvAPIFilter(), fwDetect = new SvFwDetect()
  const seen = new Set(t.apis.map(a => a.path))
  for (const url of tasks) {
    if (!url.startsWith('http')) continue
    try {
      const r = await fetch(url, { mode: 'cors' }); if (!r.ok) continue
      const text = await r.text(); if (text.length < 100) continue
      for (const p of (apiFilter.extract(text) || [])) { if (!seen.has(p) && t.apis.length < 600) { seen.add(p); t.apis.push({ path: p, method: apiFilter.method(p), classify: apiFilter.classify(p) }) } }
      if (!t.fw.length) t.fw = fwDetect.detect(text) || []
      Object.assign(t.cfg, fwDetect.extractConfig(text) || {})
      t.jsN++; badge(tabId)
    } catch (e) { /* skip */ }
  }
  t.processing = false; badge(tabId)
}

function badge(tabId) {
  if (!tabId || tabId < 0) return
  const n = tabs.get(tabId)?.apis?.length || 0
  const text = n > 0 ? (n > 999 ? '1k' : String(n)) : ''
  chrome.action.setBadgeText({ text, tabId })
  chrome.action.setBadgeBackgroundColor({ color: n > 10 ? '#e94560' : '#f39c12', tabId })
}

async function fuzzURL(url, method, headers) {
  try {
    const r = await fetch(url, { method, headers, mode: 'cors' }); const text = await r.text()
    const fp = (new SvFingerprint()).analyze(text, r.status)
    return { url, method, status: r.status, size: text.length, body: text.substring(0, 2000), contentType: r.headers.get('content-type')||'', fp }
  } catch (e) { return { url, method, status: 0, size: 0, body: e.message, error: true } }
}

chrome.tabs.onRemoved.addListener(id => tabs.delete(id))
