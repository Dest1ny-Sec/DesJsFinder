// ============================================================
// Response Fingerprint — 响应指纹识别漏洞
// ============================================================
class ResponseFingerprint {
  constructor() {
    this.fingerprints = [
      { re: /"_links".*"actuator"|"heapdump"|"env".*"href"/, type: 'Actuator暴露!', risk: 'CRITICAL', detail: 'Spring Boot Actuator端点完全暴露' },
      { re: /Whitelabel Error Page/, type: 'Spring错误页', risk: 'HIGH', detail: 'Spring Boot默认错误页' },
      { re: /thinkphp|ThinkPHP|think\\\\/, type: 'ThinkPHP报错', risk: 'CRITICAL', detail: 'ThinkPHP框架调试信息泄露' },
      { re: /SQL syntax|mysql_fetch|SQLSTATE|ORA-|PostgreSQL.*ERROR/, type: 'SQL错误', risk: 'CRITICAL', detail: 'SQL错误 — 疑似注入点!' },
      { re: /Sensors Analytics is ready/, type: '神策Debug', risk: 'HIGH', detail: '神策数据Debug模式开启' },
      { re: /please provide valid app/, type: 'API网关', risk: 'MEDIUM', detail: 'ESB网关,需app参数' },
      { re: /账号未登录|valid token is required/, type: '需认证', risk: 'INFO', detail: '接口存在但需要登录' },
      { re: /没有该操作权限/, type: '权限不足', risk: 'MEDIUM', detail: '接口存在 —> 可尝试提权' },
      { re: /参数错误|参数不正确|缺少参数/, type: '参数校验', risk: 'INFO', detail: '参数可Fuzz' },
      { re: /系统异常|系统内部错误/, type: '服务端异常', risk: 'MEDIUM', detail: '500,参数可能可控' },
      { re: /Welcome to nginx|Apache2.*Default/, type: '默认页', risk: 'LOW', detail: 'Web服务器默认页' },
      { re: /swagger|api-docs|openapi/, type: 'API文档', risk: 'HIGH', detail: 'Swagger/API文档可访问' },
      { re: /Index of \//, type: '目录遍历', risk: 'MEDIUM', detail: 'Web服务器目录列表' },
      { re: /\.git\/HEAD|ref: refs/, type: 'Git泄露', risk: 'CRITICAL', detail: '.git目录可访问!' },
      { re: /DB_NAME|jdbc:|mongodb:\/\/|password.*=/, type: '凭据泄露', risk: 'CRITICAL', detail: '代码中泄露数据库凭据!' },
    ]
  }

  analyze(body, status) {
    if (!body) return null
    for (const fp of this.fingerprints) {
      if (fp.re.test(body)) return fp
    }
    if (status === 200 && body.startsWith('{') && body.includes('"code":0')) return { type: 'JSON成功', risk: 'INFO', detail: '返回code:0,接口可用' }
    if (status === 500 && body.length > 100) return { type: '500错误', risk: 'MEDIUM', detail: 'HTTP500+有响应体,可能有调试信息' }
    if (status === 429) return { type: '限速', risk: 'LOW', detail: 'WAF限速,需降速' }
    return null
  }
}

globalThis.ResponseFingerprint = ResponseFingerprint
