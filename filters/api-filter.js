// ============================================================
// API Filter — 路径提取 + 分类 (借鉴Phantom架构)
// 注入到content script中,直接访问页面DOM
// ============================================================
// 公共静态扩展名清单 (各模块需保持同步: api-filter.js / background.js / popup.js / dict-generator.js)
const STATIC_EXTS = 'woff2?|ttf|eot|otf|jpe?g|png|gif|svg|webp|avif|apng|ico|bmp|jsx?|tsx?|vue|mjs|cjs|css|scss|sass|less|styl|mp[34]|m4a|3gp|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg|oga|pdf|docx?|xlsx?|pptx?|txt|md|csv|wasm|webmanifest|manifest|map|br|gz|zip|rar|7z|tar|iso'
// 路径归一化: 去除 JS 转义残留的末尾标点 (如 "feishu\" 实际就是 "feishu"), 多余尾斜杠
function normalizePath(p) {
  if (!p) return p
  return String(p).replace(/[\\\/]+$/, '').replace(/\\+$/, '').replace(/\/{2,}/g, '/')
}

class APIFilter {
  constructor() {
    this.patterns = {
      font: /\.(woff2?|ttf|eot|otf)(\?.*)?$/i,
      img: /\.(jpe?g|png|gif|svg|webp|avif|apng|ico|bmp)(\?.*)?$/i,
      js: /\.(jsx?|tsx?|vue|mjs|cjs)(\?.*)?$/i,
      css: /\.(css|scss|sass|less|styl)(\?.*)?$/i,
      media: /\.(mp[34]|m4a|3gp|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg|oga)(\?.*)?$/i,
      doc: /\.(pdf|docx?|xlsx?|pptx?|txt|md|csv)(\?.*)?$/i,
      app: /\.(wasm|webmanifest|manifest)(\?.*)?$/i,
      archive: /\.(map|br|gz|zip|rar|7z|tar|iso)(\?.*)?$/i,
      apiPrefix: /^\/(api|admin-api|v[0-9]+|gateway|rest|service|rpc|graphql|auth|system|console)\//,
      dynamic: /\.(aspx?|ashx)(\?.*)?$/i,
      hasQuery: /\?[^#\s]+/,
    }
    // 路径关键词+风险分类
    this.keywords = [
      { k: ['/actuator','/heapdump','/env','/mappings','/shutdown','/restart','/threaddump','/configprops','/beans','/loggers','/metrics','/sessions'], label: 'Actuator端点', risk: 'CRITICAL' },
      { k: ['/login','/logout','/register','/auth','/token','/oauth','/sso','/signin','/forgot','/password','/captcha','/verify-code'], label: '认证鉴权', risk: 'HIGH' },
      { k: ['/upload','/file/upload','/image/upload','/avatar/upload','/import'], label: '文件上传', risk: 'HIGH' },
      { k: ['/admin/','/manage/','/console/','/system/','/monitor/','/dashboard'], label: '管理后台', risk: 'HIGH' },
      { k: ['/order/','/trade/','/pay/','/payment/','/cart/','/checkout','/invoice','/refund'], label: '交易支付', risk: 'CRITICAL' },
      { k: ['/user/','/member/','/account/','/profile','/role/','/permission','/org/','/dept/'], label: '用户管理', risk: 'HIGH' },
      { k: ['/swagger','/api-docs','/doc.html','/openapi','/graphql','/graphiql'], label: 'API文档', risk: 'HIGH' },
      { k: ['/list','/page','/query','/search','/export','/import','/download','/report','/stat','/dict','/data'], label: '数据查询', risk: 'MEDIUM' },
      { k: ['/create','/add','/save','/update','/edit','/modify','/delete','/remove','/batch','/submit'], label: '数据写入', risk: 'MEDIUM' },
      { k: ['/health','/info','/ping','/status','/version','/metrics','/ready','/live'], label: '基础设施', risk: 'MEDIUM' },
      { k: ['/callback','/webhook','/notify','/sync','/third/','/open/','/hook'], label: '第三方对接', risk: 'MEDIUM' },
      { k: ['/.env','/.git/','/web.config','/elmah.axd','/trace.axd','/phpinfo','/info.php'], label: '敏感文件', risk: 'CRITICAL' },
      { k: ['/sms','/send-sms','/send-code','/email/send','/mail/send'], label: '消息发送', risk: 'MEDIUM' },
      { k: ['/bpm','/oa/','/workflow','/approval','/leave','/task'], label: '工作流', risk: 'MEDIUM' },
      { k: ['/mall/','/product','/spu','/sku','/stock','/crm','/customer'], label: '业务模块', risk: 'MEDIUM' },
      { k: ['/infra/','/file/','/codegen','/oss','/cos','/minio'], label: '基础设施', risk: 'MEDIUM' },
    ]
  }

  // 从JS文本提取API路径
  extract(text) {
    if (!text || text.length < 50) return []
    const found = new Set()
    // Pattern 1: LinkFinder/JSFinder 同款路径正则 (最宽松字符集)
    // 对标: (?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,}
    const re1 = /["'`]((?:\/|\.\.\/|\.\/)[^"'><,;|(){}\[\]\s]{1,200})["'`]/g
    let m
    while ((m = re1.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (!p) continue
      if (p.startsWith('/') && p.length >= 2 && !this.isStatic(p)) found.add(p)
      else if (p.startsWith('.') && p.length >= 4 && !/\.(?:js|css|less|scss|png|jpg|gif|svg|avif|webmanifest)$/i.test(p)) found.add(p)
    }
    // Pattern 2: JSFinder Group 4 — relative resources with extensions
    // [a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)
    const re2 = /["'`]([a-zA-Z0-9_\-\.\/]{3,}\.(?:[a-zA-Z]{1,4}|action|do|jspa)(?:\?[^"'`]{0,})?)["'`]/g
    while ((m = re2.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (p) found.add(p)
    }
    // Pattern 3: FindSomething incomplete path (xx/yy → /xx/yy)
    const re3 = /["'`]([a-zA-Z][\w\/\.\-]{3,150})["'`]/g
    while ((m = re3.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (!p) continue
      if (/[?#=]/.test(p)) continue  // skip noise: query/hash/equals
      if (/^(true|false|undefined|null|none|yes|no|auto|default)$/i.test(p)) continue  // skip boolean
      if (/^[a-f0-9]{32,}$/i.test(p)) continue  // skip hex hash
      if (/%[0-9a-f]{2}/i.test(p)) continue  // skip url-encoded garbage (e.g. %3C%3E)
      if (/u[0-9a-f]{4}/i.test(p)) continue  // skip HTML unicode entities (e.g. u003e u003c)
      if (new RegExp('\\.(?:' + STATIC_EXTS + ')', 'i').test(p)) continue  // skip media/files (统一清单)
      if (/^[\w\/\.-]+\.[a-z]{2,4}$/i.test(p) && !/\/(api|admin|rest|gateway|service|rpc)/i.test(p)) continue  // skip filename.ext unless API-related
      if (p.length > 120) continue  // skip unreasonably long
      if (/^[\w-]+\/[\w-]+$/.test(p) && !/(zh|en|ko|ja|fr|de|es|pt|ru|ar|hi)/.test(p.split('/')[0])) continue  // skip short two-segment non-locale paths
      if (p.includes('/') && !this.isStatic('/'+p) && !/^(?:http|https):\/\//i.test(p)) found.add('/'+p)
    }
    // Pattern 4: Vue/React route definitions
    const re4 = /(?:path|route|name)\s*:\s*["'`](\/[^"'`]{1,120})["'`]/gi
    while ((m = re4.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (p && p.length >= 2 && !this.isStatic(p)) found.add(p)
    }
    // Pattern 5: dynamic imports  import('./xxx'),  require('./xxx')
    const re5 = /(?:import|require)\s*\(\s*["'`](\.[^"'`]{1,120})["'`]\s*\)/g
    while ((m = re5.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (p && p.length >= 4 && !/\.(?:js|css|less|scss|sass|png|jpg|gif|svg|avif|webmanifest)$/i.test(p)) found.add(p)
    }
    // Pattern 6: url/base/prefix assignments
    const re6 = /(?:url|base|prefix|api|href|action)\s*[:=]\s*["'`](\/[^"'`]{1,120})["'`]/gi
    while ((m = re6.exec(text)) !== null) {
      const p = normalizePath(m[1])
      if (p && p.length >= 2 && !this.isStatic(p)) found.add(p)
    }
    return [...found]
  }

  // 分类一条路径
  classify(path) {
    for (const rule of this.keywords) {
      if (rule.k.some(k => path.toLowerCase().includes(k.toLowerCase()))) {
        return { label: rule.label, risk: rule.risk }
      }
    }
    if (this.patterns.apiPrefix.test(path) || this.patterns.dynamic.test(path)) {
      return { label: 'API接口', risk: 'INFO' }
    }
    return { label: '其他路径', risk: 'INFO' }
  }

  // 推测HTTP方法
  method(path) {
    const l = path.toLowerCase()
    if (/\/login|\/register|\/create|\/add|\/save|\/upload|\/submit|\/batch|\/search|\/query/.test(l)) return 'POST'
    if (/\/update|\/edit|\/modify/.test(l)) return 'PUT'
    if (/\/delete|\/remove/.test(l)) return 'DELETE'
    return 'GET'
  }

  isStatic(path) {
    // 归一化: 末尾 \\ 或 / 不应影响扩展名识别 (JS 字符串里 "feishu\\" 实际是 "feishu")
    const p = path ? path.replace(/[\\\/]+$/, '') : path
    return this.patterns.font.test(p) || this.patterns.img.test(p) ||
      this.patterns.js.test(p) || this.patterns.css.test(p) ||
      this.patterns.media.test(p) || this.patterns.doc.test(p) ||
      this.patterns.app.test(p) || this.patterns.archive.test(p)
  }
}

globalThis.APIFilter = APIFilter
