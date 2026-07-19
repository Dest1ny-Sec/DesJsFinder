// ============================================================
// Framework Detect — 框架识别 + 配置提取
// ============================================================
class FrameworkDetect {
  constructor() {
    this.signatures = [
      { name: '芋道Yudao', key: 'yudao', prefix: '/admin-api',
        match: ['/admin-api/','VITE_GLOB_API_URL_PREFIX','mall.yudao','iocoder','ruoyi'], weight: 100 },
      { name: '若依Ruoyi', key: 'ruoyi', prefix: '/',
        match: ['ruoyi','若依','RuoYi','/system/','/monitor/'], weight: 95 },
      { name: 'Spring Boot', key: 'spring', prefix: '',
        match: ['Whitelabel Error Page','actuator','spring-boot','api-docs','X-Application-Context'], weight: 90 },
      { name: 'Spring Cloud', key: 'springcloud', prefix: '',
        match: ['spring cloud','gateway','eureka','consul','nacos','sentinel'], weight: 85 },
      { name: 'ThinkPHP', key: 'thinkphp', prefix: '',
        match: ['thinkphp','ThinkPHP','think\\\\','runtime/log'], weight: 80 },
      { name: 'Laravel', key: 'laravel', prefix: '/api',
        match: ['csrf-token','laravel','XSRF-TOKEN','laravel_session'], weight: 80 },
      { name: 'FastAPI', key: 'fastapi', prefix: '/api',
        match: ['fastapi','OpenAPI','/docs','/redoc'], weight: 75 },
      { name: 'Django', key: 'django', prefix: '/api',
        match: ['csrfmiddlewaretoken','django','X-CSRFToken'], weight: 75 },
      { name: 'Flask', key: 'flask', prefix: '/api',
        match: ['flask','Werkzeug','jinja2'], weight: 70 },
      { name: 'ASP.NET', key: 'aspnet', prefix: '',
        match: ['__VIEWSTATE','__EVENTVALIDATION','ASP.NET','IIS','X-AspNet-Version'], weight: 75 },
      { name: 'Shiro', key: 'shiro', prefix: '',
        match: ['rememberMe=','shiro','org.apache.shiro'], weight: 70 },
      { name: 'Vue.js', key: 'vue', prefix: '/api',
        match: ['vue','__vue__','pinia','vuex','element-plus','ant-design-vue','nuxt'], weight: 40 },
      { name: 'React', key: 'react', prefix: '/api',
        match: ['react','react-dom','__INITIAL_STATE__','webpackJsonp','antd','next'], weight: 40 },
      { name: 'Angular', key: 'angular', prefix: '/api',
        match: ['angular','@angular','ng-version','zone.js'], weight: 40 },
      { name: 'Next.js', key: 'nextjs', prefix: '/api',
        match: ['_next/','__NEXT_DATA__','next/router','X-Powered-By: Next.js'], weight: 45 },
      { name: 'Webpack', key: 'webpack', prefix: '',
        match: ['webpackJsonp','__webpack_require__','webpack-dev-server','webpackChunk'], weight: 35 },
      { name: 'Vite', key: 'vite', prefix: '',
        match: ['VITE_GLOB','@vitejs','vite-plugin','import.meta.hot'], weight: 35 },
      { name: 'ECharts', key: 'echarts', prefix: '',
        match: ['echarts','echarts.init','zrender'], weight: 20 },
      { name: 'jQuery', key: 'jquery', prefix: '',
        match: ['jQuery','\\$\\.ajax','\\$\\.get','\\$\$.post'], weight: 25 },
      { name: 'Node.js', key: 'nodejs', prefix: '/api',
        match: ['process.env','__dirname','require(','module.exports','Buffer.from'], weight: 30 },
    ]
    this.configPatterns = [
      [/VITE_GLOB_API_URL_PREFIX\s*[:=]\s*["']([^"']+)["']/, 'apiPrefix'],
      [/VITE_GLOB_API_URL\s*[:=]\s*["']([^"']+)["']/, 'apiUrl'],
      [/VITE_GLOB_UPLOAD_URL\s*[:=]\s*["']([^"']+)["']/, 'uploadUrl'],
      [/VITE_GLOB_APP_TENANT_ENABLE\s*[:=]\s*["']([^"']+)["']/, 'tenant'],
      [/VITE_GLOB_APP_CAPTCHA_ENABLE\s*[:=]\s*["']([^"']+)["']/, 'captcha'],
      [/restfulUrl\s*[:=]\s*["']([^"']+)["']/, 'restfulUrl'],
      [/api\s*[:=]\s*["']([^"']+)["']/, 'apiHost'],
      [/baseURL\s*[:=]\s*["']([^"']+)["']/, 'baseURL'],
      [/axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["']([^"']+)["']/, 'axiosBaseURL'],
    ]
  }

  detect(text) {
    if (!text) return []
    const results = []
    for (const sig of this.signatures) {
      let score = 0
      for (const kw of sig.match) { if (text.includes(kw)) score += 30 }
      if (score >= 60) results.push({ name: sig.name, key: sig.key, prefix: sig.prefix, score })
    }
    return results.sort((a, b) => b.score - a.score)
  }

  extractConfig(text) {
    const cfg = {}
    if (!text) return cfg
    for (const [re, key] of this.configPatterns) {
      const m = text.match(re)
      if (m) cfg[key] = m[1]
    }
    return cfg
  }
}

globalThis.FrameworkDetect = FrameworkDetect