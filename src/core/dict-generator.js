// ============================================================
// Dict Generator — 框架字典 + 路径变形
// ============================================================
const DictGenerator = {
  templates: {
    yudao: [
      '/admin-api/system/auth/login','/admin-api/system/auth/register','/admin-api/system/auth/send-sms-code',
      '/admin-api/system/auth/sms-login','/admin-api/system/auth/social-login','/admin-api/system/auth/logout',
      '/admin-api/system/auth/get-permission-info','/admin-api/system/user/page','/admin-api/system/user/simple-list',
      '/admin-api/system/user/profile/get','/admin-api/system/user/profile/update-password',
      '/admin-api/system/dept/simple-list','/admin-api/system/role/simple-list',
      '/admin-api/system/dict-data/list-all-simple','/admin-api/system/menu/list-all-simple',
      '/admin-api/system/notice/page','/admin-api/system/oauth2/client/page',
      '/admin-api/system/sms-channel/page','/admin-api/system/mail-account/page',
      '/admin-api/system/login-log/page','/admin-api/system/operate-log/page',
      '/admin-api/system/tenant/page','/admin-api/system/social-user/page',
      '/admin-api/infra/file/upload','/admin-api/infra/file/page','/admin-api/infra/config/page',
      '/admin-api/infra/job/page','/admin-api/infra/api-error-log/page','/admin-api/infra/codegen/table/page',
      '/admin-api/bpm/task/my','/admin-api/bpm/oa/leave/create',
      '/admin-api/crm/customer/page','/admin-api/crm/receivable/submit',
      '/admin-api/mall/product/spu/page','/admin-api/mall/trade/order/page',
      '/admin-api/pay/channel/page','/admin-api/ai/platform/page','/admin-api/erp/stock/page',
    ],
    spring: [
      '/actuator','/actuator/health','/actuator/env','/actuator/heapdump','/actuator/threaddump',
      '/actuator/mappings','/actuator/info','/actuator/configprops','/actuator/beans','/actuator/loggers',
      '/actuator/metrics','/actuator/sessions','/swagger-ui.html','/swagger-ui/index.html',
      '/v2/api-docs','/v3/api-docs','/doc.html','/druid/index.html','/h2-console',
    ],
    thinkphp: ['/index.php','/admin.php','/runtime/','/.env','/.env.bak','/config.php','/database.php'],
    aspnet: ['/web.config','/elmah.axd','/trace.axd','/Login.aspx','/Default.aspx','/.git/config'],
    vue: [
      '/api/v1/','/api/v2/','/api/auth/login','/api/auth/register','/api/user/info','/api/user/list',
      '/api/config','/api/upload','/api/search','/api/data','/api/export','/api/import',
      '/admin/','/manage/','/dashboard/','/system/','/monitor/',
    ],
    react: [
      '/api/v1/','/api/v2/','/api/auth/login','/api/auth/register','/api/user/me','/api/user/list',
      '/api/settings','/api/upload','/api/search','/api/export',
      '/admin/','/dashboard/','/api/graphql',
    ],
    generic: ['/.env','/.git/config','/.git/HEAD','/robots.txt','/sitemap.xml','/swagger-ui.html','/v3/api-docs','/doc.html','/graphql','/phpinfo.php','/test.php','/admin/','/login','/register','/actuator','/actuator/health','/actuator/env','/actuator/heapdump'],
  },

  generate(frameworks, discoveredPaths, baseUrl) {
    const result = []; const seen = new Set()
    const add = (url, method) => { if (!seen.has(url+'|'+method)) { seen.add(url+'|'+method); result.push({ url, method }) } }

    // 框架模板 + 参数
    const _addWithParams = (p, m) => {
      add(p, m)
      if (/\/page|\/list/.test(p)) { add(p+'?pageNo=1&pageSize=10', 'GET'); add(p+'?pageNo=1&pageSize=100', 'GET') }
      if (/\/get|\/user|\/detail/.test(p)) add(p+'?id=1', 'GET')
      if (!/\/page|\/login|\/register/.test(p) && /\/api/.test(p)) { add(p+'?status=1', 'GET'); add(p+'?type=1', 'GET') }
    }
    for (const fw of (frameworks || [])) {
      for (const t of (this.templates[fw.key] || [])) _addWithParams(t, this._method(t))
    }
    for (const t of this.templates.generic) add(t, this._method(t))

    // 已发现的路径 + 变形 + 参数组合
    for (const p of (discoveredPaths || [])) {
      add(p, this._method(p))
      // 变形
      if (p.includes('list-all-simple')) add(p.replace('list-all-simple','page'), 'GET')
      if (p.endsWith('/page')) { add(p.replace('/page','/list-all-simple'), 'GET'); add(p.replace('/page','/list'), 'GET') }
      if (p.endsWith('/create')) { add(p.replace('/create','/update'), 'PUT'); add(p.replace('/create','/delete'), 'DELETE') }
      if (p.endsWith('/get')) { add(p.replace('/get','/detail'), 'GET'); add(p.replace('/get','/info'), 'GET') }
      // 前缀变换
      if (p.includes('/admin-api/')) add(p.replace('/admin-api/','/api/'), 'GET')
      if (p.includes('/api/') && !p.includes('/admin-api/')) add(p.replace('/api/','/admin-api/'), 'GET')

      // === 参数组合 ===
      const lp = p.toLowerCase()
      // 列表类 → 分页参数
      if (/\/page|\/list|\/query|\/search/.test(lp)) {
        add(p+'?pageNo=1&pageSize=10', 'GET')
        add(p+'?pageNo=1&pageSize=100', 'GET')
      }
      // 详情类 → id参数
      if (/\/get|\/detail|\/info|\/user|\/member|\/product|\/order/.test(lp) && !p.includes('?')) {
        add(p+'?id=1', 'GET')
      }
      // channel参数
      if (/\/api\//.test(p) && !p.includes('?')) {
        add(p+'?channel=MOBILE', 'GET')
        add(p+'?channel=APP', 'GET')
      }
      // 通用状态/类型参数
      if (/\/api\/|\/admin-api\//.test(p) && !p.includes('?') && !/\/page|\/login|\/register/.test(lp)) {
        add(p+'?status=1', 'GET')
        add(p+'?type=1', 'GET')
      }
      // POST补全
      if (/\/login|\/register|\/create|\/submit|\/upload|\/save/.test(lp)) { add(p, 'POST') }
    }

    // 前缀补全
    for (const fw of (frameworks || [])) {
      if (fw.prefix) {
        for (const t of this.templates.generic) { if (!t.startsWith(fw.prefix)) add(fw.prefix+t, 'GET') }
      }
    }
    return result
  },

  _method(p) {
    const l = p.toLowerCase()
    if (/\/login|\/register|\/create|\/add|\/save|\/upload|\/submit|\/batch/.test(l)) return 'POST'
    if (/\/update|\/edit|\/modify/.test(l)) return 'PUT'
    if (/\/delete|\/remove/.test(l)) return 'DELETE'
    return 'GET'
  }
}
