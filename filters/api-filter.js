// ============================================================
// API Filter — 路径提取 + 分类 (借鉴Phantom架构)
// 注入到content script中,直接访问页面DOM
// ============================================================
class APIFilter {
  constructor() {
    this.patterns = {
      font: /\.(woff2?|ttf|eot|otf)(\?.*)?$/i,
      img: /\.(jpe?g|png|gif|svg|webp|ico|bmp)(\?.*)?$/i,
      js: /\.(jsx?|tsx?|vue|mjs|cjs)(\?.*)?$/i,
      css: /\.(css|scss|sass|less|styl)(\?.*)?$/i,
      media: /\.(mp[34]|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg)(\?.*)?$/i,
      doc: /\.(pdf|docx?|xlsx?|pptx?|txt|md|csv)(\?.*)?$/i,
      apiPrefix: /^\/(api|admin-api|v[0-9]+|gateway|rest|service|rpc|graphql|auth|system|console)\//,
      dynamic: /\.(php|aspx?|ashx|jsp|do|action)(\?.*)?$/i,
      hasQuery: /\?[^#\s]+/,
    }
    // 路径关键词+风险分类
    this.keywords = [
      { k: ['/actuator','/heapdump','/env','/mappings','/shutdown','/restart'], label: 'Actuator端点', risk: 'CRITICAL' },
      { k: ['/login','/logout','/register','/auth','/token','/oauth','/sso','/signin','/forgot','/password'], label: '认证鉴权', risk: 'HIGH' },
      { k: ['/upload','/file/upload','/image/upload','/avatar/upload'], label: '文件上传', risk: 'HIGH' },
      { k: ['/admin/','/manage/','/console/','/system/','/monitor/'], label: '管理后台', risk: 'HIGH' },
      { k: ['/order/','/trade/','/pay/','/payment/','/cart/','/checkout/'], label: '交易支付', risk: 'CRITICAL' },
      { k: ['/user/','/member/','/account/','/profile','/role/','/permission'], label: '用户管理', risk: 'HIGH' },
      { k: ['/swagger','/api-docs','/doc.html','/openapi'], label: 'API文档', risk: 'HIGH' },
      { k: ['/list','/page','/query','/search','/export','/import','/download','/report','/stat','/dict'], label: '数据查询', risk: 'MEDIUM' },
      { k: ['/create','/add','/save','/update','/edit','/modify','/delete','/remove','/batch','/submit'], label: '数据写入', risk: 'MEDIUM' },
      { k: ['/health','/info','/ping','/status','/version','/metrics'], label: '基础设施', risk: 'MEDIUM' },
      { k: ['/callback','/webhook','/notify','/sync','/third/','/open/'], label: '第三方对接', risk: 'MEDIUM' },
      { k: ['/.env','/.git/','/web.config','/elmah.axd','/trace.axd'], label: '敏感文件', risk: 'CRITICAL' },
    ]
  }

  // 从JS文本提取API路径
  extract(text) {
    if (!text || text.length < 50) return []
    const found = new Set()
    // 所有带引号的绝对路径
    const re = /["'`](\/(?:[a-zA-Z0-9][a-zA-Z0-9\/_\-\.]{2,120}))["'`]/g
    let m
    while ((m = re.exec(text)) !== null) {
      const p = m[1]
      if (!this.isStatic(p)) found.add(p)
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
    return this.patterns.font.test(path) || this.patterns.img.test(path) ||
      this.patterns.js.test(path) || this.patterns.css.test(path) ||
      this.patterns.media.test(path) || this.patterns.doc.test(path)
  }
}

globalThis.APIFilter = APIFilter
