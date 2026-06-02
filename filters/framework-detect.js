// ============================================================
// Framework Detect — 框架识别 + 配置提取
// ============================================================
class FrameworkDetect {
  constructor() {
    this.signatures = [
      { name: '芋道Yudao', key: 'yudao', prefix: '/admin-api',
        match: ['/admin-api/','VITE_GLOB_API_URL_PREFIX','mall.yudao','iocoder'], weight: 100 },
      { name: 'Spring Boot', key: 'spring', prefix: '',
        match: ['Whitelabel Error Page','actuator','spring-boot','api-docs','X-Application-Context'], weight: 90 },
      { name: 'Spring Cloud', key: 'springcloud', prefix: '',
        match: ['spring cloud','gateway','eureka','consul','nacos','sentinel'], weight: 85 },
      { name: 'ThinkPHP', key: 'thinkphp', prefix: '',
        match: ['thinkphp','ThinkPHP','think\\\\','runtime/log'], weight: 80 },
      { name: 'Laravel', key: 'laravel', prefix: '/api',
        match: ['csrf-token','laravel','XSRF-TOKEN'], weight: 80 },
      { name: 'ASP.NET', key: 'aspnet', prefix: '',
        match: ['__VIEWSTATE','__EVENTVALIDATION','ASP.NET','IIS','X-AspNet-Version'], weight: 75 },
      { name: 'Shiro', key: 'shiro', prefix: '',
        match: ['rememberMe=','shiro','org.apache.shiro'], weight: 70 },
      { name: 'Vue.js', key: 'vue', prefix: '/api',
        match: ['vue','__vue__','pinia','vuex','element-plus','ant-design-vue'], weight: 40 },
      { name: 'React', key: 'react', prefix: '/api',
        match: ['react','react-dom','__INITIAL_STATE__','webpackJsonp','antd'], weight: 40 },
      { name: 'Next.js', key: 'nextjs', prefix: '/api',
        match: ['_next/','__NEXT_DATA__','X-Powered-By: Next.js'], weight: 35 },
    ]
    this.configPatterns = [
      [/VITE_GLOB_API_URL_PREFIX\s*[:=]\s*["']([^"']+)["']/, 'apiPrefix'],
      [/VITE_GLOB_API_URL\s*[:=]\s*["']([^"']+)["']/, 'apiUrl'],
      [/VITE_GLOB_UPLOAD_URL\s*[:=]\s*["']([^"']+)["']/, 'uploadUrl'],
      [/VITE_GLOB_APP_TENANT_ENABLE\s*[:=]\s*["']([^"']+)["']/, 'tenant'],
      [/VITE_GLOB_APP_CAPTCHA_ENABLE\s*[:=]\s*["']([^"']+)["']/, 'captcha'],
      [/restfulUrl\s*[:=]\s*["']([^"']+)["']/, 'restfulUrl'],
      [/api\s*[:=]\s*["']([^"']+)["']/, 'apiHost'],
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
