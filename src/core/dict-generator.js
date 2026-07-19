// ============================================================
// Dict Generator — 框架字典 + fuzzdicts通用字典 + 路径拼接
// 字典来源: thekingofduck/fuzzdicts (api.txt + top7000精选)
// ============================================================
const DictGenerator = {
  // ====== 框架专用模板 ======
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
    ruoyi: [
      '/system/user/list','/system/user/profile','/system/user/changeRole',
      '/system/dept/list','/system/role/list','/system/menu/list','/system/notice/list',
      '/system/dict/data/list','/system/config/list','/system/loginlog/list',
      '/system/operlog/list','/system/role/export','/system/user/export',
      '/system/user/resetPwd','/system/user/authRole','/system/role/select',
      '/system/menu/add','/system/menu/edit','/system/role/add','/system/role/edit',
      '/system/notice/add','/system/notice/edit','/system/notice/remove',
      '/monitor/job/list','/monitor/cache/list','/monitor/online/list',
      '/monitor/log/list','/monitor/server/list','/monitor/cache/get',
      '/system/area/list','/system/area/export',
    ],
    spring: [
      '/actuator','/actuator/health','/actuator/env','/actuator/heapdump','/actuator/threaddump',
      '/actuator/mappings','/actuator/info','/actuator/configprops','/actuator/beans','/actuator/loggers',
      '/actuator/metrics','/actuator/sessions','/actuator/conditions','/actuator/shutdown',
      '/swagger-ui.html','/swagger-ui/index.html','/swagger-resources','/v2/api-docs','/v3/api-docs',
      '/doc.html','/druid/index.html','/druid/login.html','/h2-console',
      '/actuator/jolokia',
    ],
    thinkphp: ['/index.php','/admin.php','/runtime/','/.env','/.env.bak','/config.php','/database.php','/application/','/thinkphp/','/extend/'],
    fastapi: ['/docs','/redoc','/openapi.json','/api/v1/','/api/v2/','/health','/items/','/users/','/auth/login','/auth/register'],
    django: ['/admin/','/api-auth/','/api/v1/','/api/v2/','/accounts/login/','/api-token-auth/','/api/v1/token/','/api/v1/users/','/api/v1/items/'],
    flask: ['/api/v1/','/api/v2/','/login','/logout','/register','/users','/api/token','/api/items'],
    aspnet: ['/web.config','/elmah.axd','/trace.axd','/Login.aspx','/Default.aspx','/.git/config','/api/values','/api/weather'],
    laravel: ['/.env','/storage/logs/','/telescope','/api/v1/','/api/v2/','/sanctum/token','/api/login','/api/register','/api/user'],
    vue: [
      '/api/v1/','/api/v2/','/api/auth/login','/api/auth/register','/api/user/info','/api/user/list',
      '/api/config','/api/upload','/api/search','/api/data','/api/export','/api/import',
      '/admin/','/manage/','/dashboard/','/system/','/monitor/',
      '/api/captcha','/api/sms/send','/api/file/upload',
    ],
    react: [
      '/api/v1/','/api/v2/','/api/auth/login','/api/auth/register','/api/user/me','/api/user/list',
      '/api/settings','/api/upload','/api/search','/api/export','/api/dashboard',
      '/admin/','/dashboard/','/api/graphql',
    ],
    // Chinese CMS editors — only injected when no modern framework detected
    legacy_cms: [
      '/dede','/Fckeditor','/fckeditor','/FCKeditor','/fckeditor/editor','/FCKeditor/editor',
      '/ewebeditor','/eWebEditor','/eWebEditor/admin',
      '/CuteEditor','/admin/CuteEditor','/kindeditor','/ckfinder','/ueditor',
      '/admin/editor/upload.asp','/admin/UpFile.asp',
      '/admin/EDITOR/Dialog','/Admin/Editor/ewebeditor.htm',
      '/phpmyadmin/','/phpMyAdmin/',
    ],
  },

  // ====== 通用字典 (来自 fuzzdicts: api.txt + top7000精选) ======
  generic: [
    // --- API 端点 (来自 fuzzdicts api.txt) ---
    '/api/v1/','/api/v2/','/api/v3/','/api/','/apis/',
    '/api/v1/status','/api/v1/scan','/api/v1/coupon','/api/v1/forapp/loginBeforeRoleForProject',
    '/api/v1/forapp/resetLoginRoleMsg','/api/v1/cloudron/avatar',
    '/apis/apps','/apis/apps/v1','/apis/apps/v1beta1','/apis/apps/v1beta2',
    '/apis/autoscaling','/apis/autoscaling/v1','/apis/autoscaling/v2beta1',
    '/apis/batch','/apis/batch/v1','/apis/batch/v1beta1','/apis/batch/v2alpha1',
    '/apis/extensions','/apis/extensions/v1beta1',
    '/apis/policy','/apis/policy/v1beta1',
    '/api/v1/proxy/namespaces/kube-system/services/kibana-logging/app/kibana',
    '/api/v1/namespaces','/api/v1/nodes','/api/v1/pods','/api/v1/services',
    // --- 敏感文件/配置泄露 ---
    '/.git/config','/.git/HEAD','/.svn/entries','/.hg/','/.bzr/',
    '/.ds_store','/.DS_Store','/robots.txt','/sitemap.xml',
    '/WEB-INF/','/WEB-INF/web.xml',
    '/.env','/.env.bak','/.env.backup','/.env.production','/.env.local',
    '/web.config','/package.json','/composer.json','/Gemfile','/Dockerfile',
    '/phpinfo.php','/info.php','/test.php','/phpmyadmin/','/phpMyAdmin/',
    '/server-status','/server-info',
    // --- 管理后台 ---
    '/admin/','/admin/login','/admin/index','/admin888/','/admin123/',
    '/manage/','/manager/','/management/','/webadmin/',
    '/system/','/console/','/dashboard/','/backend/','/backstage/',
    '/login/','/signin','/signup','/register','/auth/login',
    '/user/login','/admin/login.html','/admin/login.jsp','/admin/login.aspx',
    // --- 数据库/备份 ---
    '/database/','/db/','/sql/','/backup/','/bak/','/data/',
    '/tmp/','/temp/','/cache/','/logs/','/log/',
    '/dump.sql','/db.sql','/backup.sql','/database.sql',
    '/wwwroot.rar','/web.rar','/root.rar','/www.rar','/wwwroot.zip','/web.zip',
    '/备份.rar','/备份.zip',
    // --- 上传/文件 ---
    '/upload/','/uploads/','/uploadfile/','/uploadfiles/','/file/','/files/',
    '/UPLOAD/','/UploadFile/','/uploadify/','/UploadFiles/',
    '/download/','/down/','/downloads/',
    '/images/','/img/','/image/','/static/','/assets/','/public/',
    // --- 安装/配置 ---
    '/install/','/setup/','/Install/','/Setup/',
    '/install/index.html','/install/index.php','/install/index.jsp',
    '/config/','/configuration/','/settings/',
    '/readme.html','/readme.txt','/README.md','/CHANGELOG.md','/LICENSE',
    // --- 接口文档 ---
    '/swagger-ui.html','/swagger-ui/index.html','/swagger-resources',
    '/v2/api-docs','/v3/api-docs','/api-docs','/doc.html',
    '/graphql','/graphiql','/playground',
    '/openapi.json','/openapi.yaml','/swagger.json','/swagger.yaml',
    // --- 健康检查 ---
    '/health','/healthz','/ready','/live','/ping','/status','/metrics','/info','/version',
    // --- 通用业务 ---
    '/user/','/users/','/account/','/profile','/member/',
    '/order/','/orders/','/pay/','/payment/','/trade/',
    '/goods/','/product/','/products/','/item/','/items/',
    '/list','/detail','/search','/query','/page',
    '/add','/create','/edit','/update','/delete','/remove',
    '/export','/import','/download',
    '/message/','/notice/','/notify/','/mail/','/sms/',
    '/captcha','/verify','/code','/check',
    '/token','/refresh','/oauth','/authorize',
    // --- 监控/运维 ---
    '/actuator','/actuator/health','/actuator/env','/actuator/heapdump',
    '/actuator/mappings','/actuator/beans','/actuator/loggers',
    '/druid/index.html','/druid/login.html',
    '/h2-console','/h2-console/login.jsp',
    '/jmx-console','/web-console','/jolokia',
    '/nacos','/sentinel','/eureka','/consul',
    '/prometheus','/grafana','/kibana','/elasticsearch',
    // --- 测试/调试 ---
    '/test','/test/','/debug','/dev','/demo',
    '/example','/examples','/sample','/samples',
    '/echo','/mock','/stub','/sandbox',
  ],

  generate(frameworks, discoveredPaths, baseUrl, runtimeParams, bodyParams, skipGeneric) {
    const result = []; const seen = new Set()
    const add = (url, method) => { if (!seen.has(url+'|'+method)) { seen.add(url+'|'+method); result.push({ url, method }) } }
    const addDual = (url) => {
      const isStatic = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|rar|mp[34]|webm|wasm|html?|htm)(\?.*)?$/i.test(url)
      if (isStatic) { add(url, 'GET'); return }
      const m = this._method(url)
      add(url, m)
      if (m !== 'GET') add(url, 'GET')
      if (m !== 'POST') add(url, 'POST')
    }
    // runtime URL params + POST body params
    const rp = (runtimeParams || []).slice(0, 15).filter(k => k.length >= 2 && k.length <= 20 && !/^(fp|msToken|a_bogus|timestamp|webid|verify)/i.test(k))
    const bp = (bodyParams || []).slice(0, 15).filter(k => k.length >= 2 && k.length <= 30)

    // 1. 框架模板
    const fwKeys = (frameworks || []).map(f => f.key)
    for (const fw of (frameworks || [])) {
      for (const t of (this.templates[fw.key] || [])) { addDual(t); this._addParams(add, t) }
    }
    // legacy CMS dict ONLY if explicitly detected (ASP.NET/PHP/ThinkPHP)
    const isLegacy = fwKeys.some(k => ['aspnet','thinkphp','php','iis'].includes(k))
    if (isLegacy) {
      for (const t of (this.templates.legacy_cms || [])) { addDual(t) }
    }

    // 2. 通用字典 (可跳过)
    if (!skipGeneric) {
      for (const t of this.generic) { addDual(t); this._addParams(add, t) }
    }

    // 3. 已发现路径 → 变形 + 参数 + P2递归 + runtime params
    for (const p of (discoveredPaths || [])) {
      addDual(p)
      this._addParams(add, p)
      // inject runtime URL params into API paths
      if (rp.length && /\/api\/|\/aweme\/|\/v[0-9]\//.test(p) && !p.includes('?')) {
        const kv = rp.slice(0, 3).map(k => k + '=1').join('&')
        if (kv) add(p + '?' + kv, 'GET')
      }
      // inject POST body params from runtime into update/create paths
      if (bp.length && /\/(?:update|create|add|save|edit|modify|submit)/i.test(p) && !p.includes('?')) {
        const bodyObj = {}
        bp.slice(0, 4).forEach(k => { bodyObj[k] = k.toLowerCase().includes('id') ? 1 : 'test' })
        add(p + '?' + new URLSearchParams(bodyObj).toString(), 'POST')
      }
      // 前缀变换
      if (p.includes('/admin-api/')) addDual(p.replace('/admin-api/', '/api/'))
      if (p.includes('/api/') && !p.includes('/admin-api/')) addDual(p.replace('/api/', '/admin-api/'))

      // P2: 一级递归 — 集合接口追 ID
      this._recurse(add, p)
    }

    // 3.5 CRUD 推理: 从已发现的命名规律推断同类接口
    this._inferCRUD(add, discoveredPaths || [])

    // 4. 框架前缀补全 (可跳过)
    if (!skipGeneric) {
      for (const fw of (frameworks || [])) {
        if (fw.prefix) {
          for (const t of this.generic.slice(0, 30)) { if (!t.startsWith(fw.prefix)) addDual(fw.prefix + t) }
        }
      }
    }
    return result
  },

  // P2: 对集合类路径生成子资源探测
  // CRUD 推理: 从已知接口的命名规律推断同类接口
  _inferCRUD(add, paths) {
    const verbs = ['get','query','list','add','save','create','update','edit','modify','delete','remove','del','export','import','download','reset','change','send','check','verify']
    const fields = ['Id','ById','ByUserId','ByUsername','ByName','ByPhone','ByEmail','ByStatus','ByType','ByRole','ByDept','ByOrg']
    const seen = new Set()
    for (const p of paths) {
      // skip file extensions — can't infer CRUD from files
      if (/\.(html?|htm|php|jsp|asp|aspx|do|action|json|xml|css|js|png|jpg)$/i.test(p)) continue
      const clean = p.replace(/\/$/, '')
      const parts = clean.split('/').filter(Boolean)
      if (parts.length < 2) continue
      const last = parts[parts.length - 1]
      const prefix = '/' + parts.slice(0, -1).join('/') + '/'

      // Pattern: getXxxByYyy → extract entity and field
      const m = last.match(/^(get|query|find)([A-Z][a-zA-Z0-9]+?)(?:By([A-Z][a-zA-Z0-9]+))?$/)
      if (m) {
        const entity = m[2] // ConfigUser
        const baseVerbs = ['get','add','update','delete','list']
        for (const v of baseVerbs) {
          const suffix = v === 'list' ? entity + 'List' : v + entity
          const url = prefix + v + entity
          if (!seen.has(url)) { seen.add(url); add(url, v === 'add' || v === 'save' ? 'POST' : 'GET') }
          // also try with List/s suffix
          if (v === 'get') {
            for (const sfx of [entity + 'List', entity + 's']) {
              const url2 = prefix + 'get' + sfx
              if (!seen.has(url2)) { seen.add(url2); add(url2, 'GET') }
            }
          }
        }
        // Replace field: getConfigUserByUsername → getConfigUserById
        for (const f of fields) {
          if (f === 'By' + (m[3] || '')) continue
          const url = prefix + m[1] + entity + f
          if (!seen.has(url)) { seen.add(url); add(url, 'GET') }
        }
        // Entity swap: getRolesByUserId → getUserByUserId (article technique)
        if (m[3]) {
          const fieldEntity = m[3] // UserId → User
          const singular = fieldEntity.replace(/s$/i, '') // Users → User
          const swapUrl = prefix + m[1] + singular
          if (!seen.has(swapUrl)) { seen.add(swapUrl); add(swapUrl, 'GET') }
          // also try By + original entity: getUserByRoles
          const reverseUrl = prefix + m[1] + singular + 'By' + entity
          if (!seen.has(reverseUrl)) { seen.add(reverseUrl); add(reverseUrl, 'GET') }
        }
      }

      // Pattern: /xxx/yyy/zzz → module prefix, generate CRUD under it
      if (parts.length >= 3 && /^(get|query|find|update|delete|create|add|save)/i.test(last)) {
        const modulePrefix = '/' + parts.slice(0, -1).join('/') + '/'
        // try common verbs on this prefix
        for (const v of ['get','list','add','update','delete','query','search','export','import']) {
          const url = modulePrefix + v
          if (!seen.has(url)) { seen.add(url); add(url, v === 'add' ? 'POST' : 'GET') }
        }
      }
    }
  },

  _recurse(add, p) {
    // skip paths with file extensions — can't recurse into files
    if (/\.(html?|htm|php|jsp|asp|aspx|do|action|json|xml)$/i.test(p)) return
    const ids = ['1', '0', 'admin', 'self', 'me', 'profile', 'info', 'detail', 'all', 'tree', 'root']
    const lp = p.toLowerCase()
    // /api/users → /api/users/1, /api/users/admin
    if (/\/(user|member|account|role|dept|org|product|order|goods|item|customer|tenant|notice|article|news|cate|tag|menu|dict|config|file|task|job|log)s?\/?$/.test(lp)) {
      // 去掉末尾 / 如果有
      const base = p.replace(/\/$/, '')
      for (const id of ids) { add(base + '/' + id, 'GET') }
    }
    // /admin-api/system/user/page → 也要探测 /admin-api/system/user/get?id=1
    if (/\/(?:page|list|query|search)/.test(lp)) {
      const base = p.replace(/\/(?:page|list|query|search).*$/, '/get')
      if (base !== p) { add(base + '?id=1', 'GET'); add(base + '?id=admin', 'GET') }
    }
  },

  _addParams(add, p) {
    const lp = p.toLowerCase()
    if (/\/page|\/list|\/query|\/search/.test(lp)) {
      add(p+'?pageNo=1&pageSize=10', 'GET'); add(p+'?pageNo=1&pageSize=100', 'GET')
    }
    if (/\/get|\/detail|\/info|\/user|\/member|\/product|\/order/.test(lp) && !p.includes('?')) {
      add(p+'?id=1', 'GET')
    }
    if (/\/api\//.test(p) && !p.includes('?')) {
      add(p+'?channel=MOBILE', 'GET'); add(p+'?channel=APP', 'GET')
    }
    if (/\/api\/|\/admin-api\//.test(p) && !p.includes('?') && !/\/page|\/login|\/register/.test(lp)) {
      add(p+'?status=1', 'GET'); add(p+'?type=1', 'GET')
    }
    // hidden parameter fuzz — only for API-like paths, not HTML/CSS/JS/files
    if (/\.(css|js|png|jpe?g|gif|svg|ico|woff|ttf|eot|map|pdf|html?|htm)$/i.test(p)) return
    if (/(?:login|auth|token|oauth|register|user|admin|api)/i.test(p) && !p.includes('?')) {
      const hiddenParams = ['callback=jsonp','format=json','debug=1','admin=1','token=1','userid=1','role=admin','__user=admin','__role=admin']
      for (const hp of hiddenParams) { add(p + '?' + hp, 'GET') }
    }
  },

  _method(p) {
    const l = p.toLowerCase()
    if (/\/login|\/register|\/create|\/add|\/save|\/upload|\/submit|\/batch/.test(l)) return 'POST'
    if (/\/update|\/edit|\/modify/.test(l)) return 'PUT'
    if (/\/delete|\/remove/.test(l)) return 'DELETE'
    return 'GET'
  }
}