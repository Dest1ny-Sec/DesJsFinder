// ============================================================
// ParamExtractor — JS 参数全量提取 + 分类评分
// 采纳自 ParamX (https://github.com/daydust/ParamX) 的提取引擎,
// 清理了调试噪音, 允许下划线参数名(真实 API 参数常含 _), 增加数量上限。
// 9 种提取策略: 对象属性名 / 解构 / 嵌套解构 / 函数参数 / 变量赋值 /
//              API请求参数 / URL参数 / 配置对象 / 路由参数
// ============================================================
class ParamExtractor {
  constructor() {
    this.MAX_PARAMS = 800 // 单文件上限
  }

  extract(jsCode) {
    if (!jsCode || jsCode.length < 50) return []
    const params = []
    this._extractObjectPropertyNames(jsCode, params)
    this._extractDestructuringVariables(jsCode, params)
    this._extractNestedDestructuring(jsCode, params)
    this._extractFunctionParameters(jsCode, params)
    this._extractVariableAssignments(jsCode, params)
    this._extractAPIRequestParams(jsCode, params)
    this._extractURLParams(jsCode, params)
    this._extractConfigObjects(jsCode, params)
    this._extractRouteParams(jsCode, params)
    return this._finalize(params)
  }

  // ---- 提取策略 ----

  // 对象字面量属性名
  _extractObjectPropertyNames(jsCode, params) {
    const patterns = [
      /(?:^|,|\n|\r\n)\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g,
      /{[\s]*['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"][\s]*:/g,
      /{[\s]*'([a-zA-Z_$][a-zA-Z0-9_$]*)'[\s]*:/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        if (this._valid(m[1])) this._push(params, m[1], 'object_property')
      }
    }
  }

  // 解构赋值变量名(含重命名 key: alias → alias)
  _extractDestructuringVariables(jsCode, params) {
    const re = /(?:const|let|var)\s*\{([^}]+)\}\s*=/g
    let m
    while ((m = re.exec(jsCode)) !== null) {
      const inner = m[1]
      const vre = /([a-zA-Z_$][a-zA-Z0-9_$]*)(?:\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$]*))?/g
      let vm
      while ((vm = vre.exec(inner)) !== null) {
        const name = vm[2] || vm[1]
        if (this._valid(name)) this._push(params, name, 'destructuring')
      }
    }
  }

  // 嵌套解构 const { a: { b, c } } = obj
  _extractNestedDestructuring(jsCode, params) {
    const patterns = [
      /(?:const|let|var)\s*\{[^}]*:\s*\{([^}]+)\}[^}]*\}/g,
      /(?:const|let|var)\s*\{[^}]*:\s*\{([^}]+)\}[^}]*,[^}]*:\s*\{([^}]+)\}[^}]*\}/g,
      /const\s*\{\s*settings:\s*\{([^}]+)\}\s*,\s*preferences:\s*\{([^}]+)\}\s*\}\s*=\s*userConfig/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        for (let i = 1; i < m.length; i++) {
          if (!m[i]) continue
          m[i].split(',').map(v => v.trim()).forEach(v => {
            // 处理内层重命名 a: b → b
            const parts = v.split(':').map(x => x.trim())
            const name = parts.length > 1 ? parts[parts.length - 1] : parts[0]
            if (this._valid(name)) this._push(params, name, 'nested_destructuring')
          })
        }
      }
    }
  }

  // 函数参数 (普通 / 箭头 / 解构)
  _extractFunctionParameters(jsCode, params) {
    const patterns = [
      /function\s+[^(]*\(\s*([^)]+)\s*\)/g,
      /\(\s*([^)]+)\s*\)\s*=>/g,
      /function\s+[^(]*\(\s*{([^}]+)}\s*\)/g,
      /\(\s*{([^}]+)}\s*\)\s*=>/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        const paramsStr = m[1] || ''
        paramsStr.split(',').map(p => p.trim()).filter(p => p && p !== '{' && p !== '}').forEach(p => {
          let name = p
          // 解构 { key: alias } → alias; { key } → key
          if (name.includes('{')) {
            name = name.replace(/{|}/g, '').trim()
            if (name.includes(':')) name = name.split(':').pop().trim()
            if (name.includes(',')) { // 多个解构名
              name.split(',').map(x => x.trim()).forEach(x => { if (this._valid(x)) this._push(params, x, 'function_param') })
              return
            }
          } else if (name.includes('=')) {
            name = name.split('=')[0].trim() // 默认值
          } else if (name.includes(':')) {
            name = name.split(':').pop().trim() // TS 类型标注 / 重命名
          }
          if (this._valid(name)) this._push(params, name, 'function_param')
        })
      }
    }
  }

  // 变量赋值
  _extractVariableAssignments(jsCode, params) {
    const patterns = [
      /(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/g,
      /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[^{]/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        if (this._valid(m[1]) && !this._isCommonVar(m[1])) this._push(params, m[1], 'variable_assignment')
      }
    }
  }

  // API 请求参数 (fetch/axios/$.get 等调用中的对象键)
  _extractAPIRequestParams(jsCode, params) {
    const patterns = [
      /(?:fetch|axios|\.(?:get|post|put|delete|patch))\([^,]+,\s*{([^}]*)}/g,
      /\.(?:then|catch)\([^,]*{([^}]*)}/g,
      /\([^)]*{([^}]*)}[^)]*\)/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        this._propsFrom(m[1] || '', params, 'api_request')
      }
    }
  }

  // URL 查询参数
  _extractURLParams(jsCode, params) {
    const patterns = [
      /[?&]([a-zA-Z_$][a-zA-Z0-9_$]*)=/g,
      /\.(?:set|append)\(['"]([^'"]+)['"]/g,
      /[?&]\$\{([^}]+)\}/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        if (this._valid(m[1])) this._push(params, m[1], 'url_param')
      }
    }
  }

  // 配置对象
  _extractConfigObjects(jsCode, params) {
    const patterns = [
      /(?:config|options|params|settings)\s*=\s*{([^}]*)}/g,
      /(?:headers|data|body|query)\s*:\s*{([^}]*)}/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        this._propsFrom(m[1] || '', params, 'config_object')
      }
    }
  }

  // 路由参数 /:id {id} [id]
  _extractRouteParams(jsCode, params) {
    const patterns = [
      /\/:([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /path:.*?\/:([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /path.*?\/:([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /\/\{([a-zA-Z_$][a-zA-Z0-9_$]*)\}/g,
      /\/\[([a-zA-Z_$][a-zA-Z0-9_$]*)\]/g,
      /['"`]\/:[^/'"]*?\/([a-zA-Z_$][a-zA-Z0-9_$]*)['"`]/g,
      /['"`](\/api\/[^'"`]*?\/(?::|\{|\[])([a-zA-Z_$][a-zA-Z0-9_$]*)(?::|\}|\]))[^'"`]*?['"`]/g,
      /['"`](\/v\d+\/[\w\/]*?\/(?::|\{|\[])([a-zA-Z_$][a-zA-Z0-9_$]*)(?::|\}|\]))[^'"`]*?['"`]/g,
    ]
    for (const re of patterns) {
      let m
      while ((m = re.exec(jsCode)) !== null) {
        const name = m[2] || m[1]
        if (this._valid(name)) this._push(params, name, 'route_param')
      }
    }
  }

  // 对象内容 → 属性名
  _propsFrom(content, params, source) {
    const re = /(['"]?)([a-zA-Z_$][a-zA-Z0-9_$]*)\1\s*:/g
    let m
    while ((m = re.exec(content)) !== null) {
      if (this._valid(m[2])) this._push(params, m[2], source)
    }
  }

  // ---- 过滤 / 分类 ----

  _push(params, name, source) {
    if (params.length >= this.MAX_PARAMS) return
    params.push({ value: name, source })
  }

  _valid(name) {
    if (!name || typeof name !== 'string') return false
    const n = name.trim()
    if (n.length < 2 || n.length > 50) return false
    if (!/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(n)) return false
    // 允许下划线(真实参数如 user_id), 但过滤全下划线 / 双下划线噪音
    if (/^_+$/.test(n) || n.includes('__')) return false
    // JS 关键字
    const keywords = ['var','let','const','function','if','else','for','while','return','class','import','export','default','extends','super','this','new','typeof','instanceof','void','delete','in','of','try','catch','finally','throw','debugger','with','yield','await','async','static','set','true','false','null','undefined','arguments','prototype','constructor','length','name','window','document','globalThis']
    if (keywords.includes(n)) return false
    // 常见噪音变量 (只过滤单字符 / 单字母 + 通用 Promise / 容器抽象, 保留 data/value/key/state/items/result 等真实业务字段)
    const noise = ['headers','response','request','error','success','then','catch','finally','resolve','reject','promise','fn','func','obj','arr','str','bool','reg','regex','style','res','req','config','options','params','settings','e','t','i','j','k','x','y','z','n','m','a','b','c','d','f','g','h','u','v','w','el','ev','event','cb','callback','index']
    if (noise.includes(n)) return false
    if (n.length === 1) return false
    return true
  }

  _isCommonVar(name) {
    return name.length === 1 || /^_[a-zA-Z0-9]*$/.test(name)
  }

  _finalize(params) {
    // 去重 + 分类评分 + 按优先级排序
    const seen = new Set()
    const out = []
    for (const p of params) {
      if (seen.has(p.value)) continue
      seen.add(p.value)
      out.push(this._classify(p))
    }
    return out.sort((a, b) => b.priority - a.priority || a.value.localeCompare(b.value))
  }

  _classify(param) {
    const name = param.value.toLowerCase()
    let category = 'general', priority = 1
    const tags = []
    if (param.source === 'route_param') { priority = 4; tags.push('route') }
    if (name.includes('id') || name.endsWith('id')) { category = 'identifier'; priority = 4; tags.push('id') }
    if (name.includes('token') || name.includes('auth') || name.includes('key') || name.includes('secret') || name.includes('password') || name.includes('session')) { category = 'authentication'; priority = 5; tags.push('auth') }
    if (name.includes('page') || name.includes('size') || name.includes('limit') || name.includes('offset')) { category = 'pagination'; priority = 2; tags.push('pagination') }
    if (name.includes('time') || name.includes('date') || name.includes('timestamp')) { category = 'timestamp'; priority = 3; tags.push('time') }
    if (name.includes('status') || name.includes('state')) { category = 'status'; priority = 3; tags.push('status') }
    if (param.source.includes('url') || param.source.includes('api')) { priority = Math.min(5, priority + 1); tags.push('api') }
    return { ...param, category, priority, tags }
  }
}

globalThis.ParamExtractor = ParamExtractor
