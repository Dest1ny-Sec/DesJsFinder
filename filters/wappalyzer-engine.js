// ============================================================
// Wappalyzer Detection Engine for DesJsFinder
// Lightweight reimplementation of Wappalyzer's pattern matching
// ============================================================
class WappalyzerEngine {
  constructor() {
    this.techs = []
    this.cats = {}
    this.techMap = {}
    this._hIdx = {}     // html patterns → tech[]
    this._ssIdx = {}    // scriptSrc domain fragments → tech[]
    this._jsIdx = {}    // js global name prefix → tech[]
    this._hdrIdx = {}   // header name lower → tech[]
    this._ckIdx = {}    // cookie name lower → tech[]
    this._ready = false
  }

  load(bundle) {
    if (!bundle || typeof bundle !== 'object') return false
    this.cats = bundle.cats || {}
    this.techs = []
    this.techMap = {}
    this._hIdx = {}
    this._ssIdx = {}
    this._jsIdx = {}
    this._hdrIdx = {}
    this._ckIdx = {}

    // Helper: compile a pattern string to RegExp
    const compileRe = (raw) => {
      if (raw && raw.regex) return raw.regex // already compiled
      const str = typeof raw === 'string' ? raw : (raw?.value || '')
      if (typeof str !== 'string') return null
      try {
        // Empty string means "match anything" (presence check)
        let pattern = str.replace(/\//g, '\\/')
          .replace(/\\\+/g, '__escapedPlus__')
          .replace(/\+/g, '{1,250}')
          .replace(/\*/g, '{0,250}')
          .replace(/__escapedPlus__/g, '\\+')
        // Empty pattern matches anything
        if (!pattern) pattern = '.*'
        return new RegExp(pattern, 'i')
      } catch(e) { return null }
    }

    for (const [name, t] of Object.entries(bundle)) {
      if (name === 'cats') continue
      const tech = { name, cats: t.c || [], implies: [], excludes: [] }
      if (t.implies) tech.implies = Array.isArray(t.implies) ? t.implies : [t.implies]
      this.techs.push(tech)
      this.techMap[name] = tech

      // Index HTML patterns
      if (t.h) {
        tech._hp = []
        for (const raw of t.h) {
          const re = compileRe(raw)
          if (re) tech._hp.push({ value: raw.value || raw, regex: re, confidence: raw.confidence || 100, version: raw.version || '' })
        }
        if (tech._hp.length) this._hIdx[name] = tech._hp
      }
      // Index scriptSrc patterns
      if (t.ss) {
        tech._ssp = []
        for (const raw of t.ss) {
          const re = compileRe(raw)
          if (!re) continue
          const p = { value: raw.value || raw, regex: re, confidence: raw.confidence || 100, version: raw.version || '' }
          tech._ssp.push(p)
          // Extract meaningful fragments: domain parts + path keywords
          const val = raw.value || raw
          // Domain-like parts: xxx.xxx, xxx.xxx.xxx
          const domainParts = val.match(/[a-z0-9]+\.[a-z]{2,}/gi) || []
          for (const dp of domainParts) {
            const clean = dp.replace(/[^a-z0-9]/gi, '').toLowerCase()
            if (clean.length >= 3) {
              if (!this._ssIdx[clean]) this._ssIdx[clean] = []
              this._ssIdx[clean].push({ tech, pattern: p })
            }
          }
          // Keyword fragments: sequences of 4+ alphanumeric chars from path patterns
          const keywords = val.replace(/[^a-zA-Z0-9]/g, ' ').split(/\s+/).filter(w => w.length >= 4 && !/^\d+$/.test(w))
          for (const kw of keywords.slice(0, 5)) {
            const lower = kw.toLowerCase()
            if (!this._ssIdx[lower]) this._ssIdx[lower] = []
            // Avoid duplicate entries for same tech+pattern
            const exists = this._ssIdx[lower].some(e => e.tech.name === tech.name && e.pattern.value === p.value)
            if (!exists) this._ssIdx[lower].push({ tech, pattern: p })
          }
        }
      }
      // Index JS global patterns
      if (t.js) {
        tech._jp = {}
        for (const [key, raw] of Object.entries(t.js)) {
          const re = compileRe(raw)
          if (!re) continue
          tech._jp[key] = { value: raw.value || raw, regex: re, confidence: raw.confidence || 100, version: raw.version || '' }
          const prefix = key.split('.')[0].toLowerCase()
          if (prefix.length >= 2) {
            if (!this._jsIdx[prefix]) this._jsIdx[prefix] = []
            this._jsIdx[prefix].push({ tech, key, pattern: tech._jp[key] })
          }
        }
      }
      // Index header patterns
      if (t.hdrs) {
        tech._hdrp = {}
        for (const [hName, raw] of Object.entries(t.hdrs)) {
          const re = compileRe(raw)
          if (!re) continue
          tech._hdrp[hName] = { value: raw.value || raw, regex: re, confidence: raw.confidence || 100, version: raw.version || '' }
          const hLower = hName.toLowerCase()
          if (!this._hdrIdx[hLower]) this._hdrIdx[hLower] = []
          this._hdrIdx[hLower].push({ tech, hName, pattern: tech._hdrp[hName] })
        }
      }
      // Index cookie patterns
      if (t.ck) {
        tech._ckp = {}
        for (const [cName, raw] of Object.entries(t.ck)) {
          const re = compileRe(raw)
          if (!re) continue
          tech._ckp[cName] = { value: raw.value || raw, regex: re, confidence: raw.confidence || 100, version: raw.version || '' }
          const cLower = cName.toLowerCase()
          if (!this._ckIdx[cLower]) this._ckIdx[cLower] = []
          this._ckIdx[cLower].push({ tech, cName, pattern: tech._ckp[cName] })
        }
      }
    }
    this._ready = true
    return true
  }

  loaded() { return this._ready }

  // Run full detection on collected page data
  detect(data) {
    if (!this._ready) return []
    const detections = []
    const html = (data.html || '').slice(0, 500000)
    const scripts = data.scripts || []
    const headers = data.headers || {}
    const cookies = data.cookies || {}
    const globals = data.globals || {}

    // HTML patterns
    if (html.length > 20) {
      for (const [name, patterns] of Object.entries(this._hIdx)) {
        for (const p of patterns) {
          if (!p.pattern || !p.pattern.regex) continue
          const m = p.pattern.regex.exec(html)
          if (m) {
            const ver = this._resolveVersion(p.pattern, m)
            detections.push({ tech: p.tech, pattern: p.pattern, type: 'html', match: m[0], version: ver })
            break // one match per tech is enough
          }
        }
      }
    }

    // scriptSrc patterns - test all techs with scriptSrc patterns
    // Use inverted index for pre-filtering, but also test remaining techs
    const testedScriptSrc = new Set()
    for (const src of scripts) {
      const srcLower = src.toLowerCase()
      // Collect candidates from inverted index
      const candidates = new Set()
      for (const [frag, entries] of Object.entries(this._ssIdx)) {
        if (srcLower.includes(frag)) {
          for (const e of entries) candidates.add(e.tech.name)
        }
      }
      // Also test ALL remaining techs with scriptSrc patterns (catches path-only patterns like React)
      for (const [tName, tech] of Object.entries(this.techMap)) {
        if (!tech._ssp || testedScriptSrc.has(tName)) continue
        testedScriptSrc.add(tName)
        candidates.add(tName)
      }
      // Test candidates
      for (const tName of candidates) {
        const tech = this.techMap[tName]
        if (!tech || !tech._ssp) continue
        for (const p of tech._ssp) {
          if (!p || !p.regex) continue
          const m = p.regex.exec(src)
          if (m) {
            const ver = this._resolveVersion(p, m)
            detections.push({ tech, pattern: p, type: 'scriptSrc', match: m[0], version: ver })
            break // one match per tech per script is enough
          }
        }
      }
    }

    // JS global patterns
    const globalKeys = Object.keys(globals)
    const checkedJs = new Set()
    for (const key of globalKeys) {
      const parts = key.split('.')
      for (let i = parts.length; i > 0; i--) {
        const prefix = parts.slice(0, i).join('.').toLowerCase()
        if (checkedJs.has(prefix)) break
        checkedJs.add(prefix)
        const entries = this._jsIdx[prefix]
        if (!entries) continue
        for (const e of entries) {
          if (e.key.toLowerCase() !== prefix) continue
          if (!e.pattern || !e.pattern.regex) continue
          const val = String(globals[key] || '').slice(0, 5000)
          const m = e.pattern.regex.exec(val)
          if (m) {
            const ver = this._resolveVersion(e.pattern, m)
            detections.push({ tech: e.tech, pattern: e.pattern, type: 'js', match: m[0], version: ver })
            break
          }
        }
      }
    }

    // Header patterns
    for (const [hName, hVal] of Object.entries(headers)) {
      const hLower = hName.toLowerCase()
      const entries = this._hdrIdx[hLower]
      if (!entries) continue
      const val = String(hVal)
      for (const e of entries) {
        if (!e.pattern || !e.pattern.regex) continue
        const m = e.pattern.regex.exec(val)
        if (m) {
          const ver = this._resolveVersion(e.pattern, m)
          detections.push({ tech: e.tech, pattern: e.pattern, type: 'header', match: m[0], version: ver })
        }
      }
    }

    // Cookie patterns
    for (const [cName, cVal] of Object.entries(cookies)) {
      const cLower = cName.toLowerCase()
      const entries = this._ckIdx[cLower]
      if (!entries) continue
      for (const e of entries) {
        if (!e.pattern || !e.pattern.regex) continue
        const m = e.pattern.regex.exec(cVal)
        if (m) {
          const ver = this._resolveVersion(e.pattern, m)
          detections.push({ tech: e.tech, pattern: e.pattern, type: 'cookie', match: m[0], version: ver })
        }
      }
    }

    // Resolve results
    return this._resolve(detections)
  }

  _resolveVersion(pattern, match) {
    let ver = pattern.version || ''
    if (!ver) return ''
    let resolved = ver
    for (let i = 1; i < match.length; i++) {
      resolved = resolved.replace(new RegExp('\\\\' + i, 'g'), match[i] || '')
    }
    // Remove ternary leftovers
    resolved = resolved.replace(/\\\d/g, '').trim()
    // Validate: ignore long numbers (timestamps etc)
    if (resolved && /^\d{4,}$/.test(resolved)) return ''
    return resolved.slice(0, 20)
  }

  _resolve(detections) {
    // Deduplicate by tech name, sum confidence
    const map = new Map()
    for (const d of detections) {
      const existing = map.get(d.tech.name)
      if (!existing) {
        map.set(d.tech.name, {
          tech: d.tech,
          confidence: Math.min(100, d.pattern.confidence),
          version: d.version,
          types: new Set([d.type]),
          match: d.match,
        })
      } else {
        existing.confidence = Math.min(100, existing.confidence + d.pattern.confidence)
        existing.types.add(d.type)
        if (d.version && (!existing.version || d.version.length > existing.version.length)) {
          existing.version = d.version
        }
      }
    }

    // Resolve implies
    let changed = true
    while (changed) {
      changed = false
      for (const [name, result] of map) {
        const tech = result.tech
        if (!tech.implies) continue
        for (const imp of tech.implies) {
          const impName = typeof imp === 'string' ? imp : imp.name
          if (!map.has(impName) && this.techMap[impName]) {
            const impTech = this.techMap[impName]
            map.set(impName, {
              tech: impTech,
              confidence: Math.min(result.confidence, typeof imp === 'object' ? (imp.confidence || 80) : 80),
              version: '',
              types: new Set(['implied']),
              match: 'implied by ' + name,
            })
            changed = true
          }
        }
      }
    }

    // Convert to output format and sort by confidence
    return Array.from(map.values())
      .filter(r => r.confidence >= 30)
      .sort((a, b) => b.confidence - a.confidence)
      .map(r => ({
        name: r.tech.name,
        cats: r.tech.cats,
        confidence: r.confidence,
        version: r.version || '',
        types: [...r.types],
        match: r.match,
        description: r.tech.d || '',
        website: r.tech.w || '',
      }))
  }
}

// Singleton
const engine = new WappalyzerEngine()

// ============================================================
// DOM detection (runs in MAIN world via injector.js)
// ============================================================
function detectDOM() {
  const results = {}
  // Only check DOM for technologies that have dom patterns
  // This is called from injector.js which has access to document
  return results
}

// Collect JS globals from window (MAIN world)
function collectGlobals() {
  const globals = {}
  // Scan window for common Wappalyzer-detectable globals
  const checkKeys = []
  for (const key of Object.keys(window)) {
    if (key.length < 2 || key.length > 50) continue
    // Only collect objects and functions (potential library globals)
    const val = window[key]
    if (val && typeof val === 'object' && !Array.isArray(val) && val !== window && val !== document) {
      checkKeys.push(key)
    } else if (typeof val === 'function') {
      checkKeys.push(key)
    }
  }
  // Also check nested objects for version strings
  for (const key of checkKeys.slice(0, 200)) {
    try {
      const val = window[key]
      if (val && typeof val === 'object') {
        const strVal = JSON.stringify(val).slice(0, 1000)
        if (strVal.length > 5) globals[key] = strVal
        // Also check common sub-paths
        for (const sub of ['version', 'VERSION', 'SDK_VERSION', 'config', 'props']) {
          if (val[sub] !== undefined) {
            globals[key + '.' + sub] = String(val[sub]).slice(0, 200)
          }
        }
      } else if (typeof val === 'function') {
        globals[key] = '[Function]'
      }
    } catch(e) {}
  }
  return globals
}

if (typeof module !== 'undefined') {
  module.exports = { WappalyzerEngine, engine, collectGlobals }
}
