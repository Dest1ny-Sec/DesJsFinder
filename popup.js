let data={},fuzzing=false,fuzzRes=[],total=0,timer=0

// === 1. 秒开: 先从storage加载 ===
chrome.storage.local.get(['lastData'], r => {
  if (r.lastData && r.lastData.apis?.length) {
    data = r.lastData
    const s = (data.apis||[]).sort((a,b) => { const r={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1}; return (r[b.classify?.risk]||0)-(r[a.classify?.risk]||0) })
    render(s)
    document.getElementById('apiC').textContent = data.apis.length
    document.getElementById('jsC').textContent = data.jsN||0
    document.getElementById('fwT').innerHTML = (data.fw||[]).map(f => `<span class="fw">${f.name}</span>`).join('')
    document.getElementById('apiE').style.display = 'none'
  }
})

// === 2. 后台更新: 每1.5秒拉最新 ===
function refresh() {
  chrome.runtime.sendMessage({action:'getData'}, d => {
    if (!d) { return }
    if (!(d.apis||[]).length) { return } // 没数据不覆盖缓存
    const prevLen = (data.apis||[]).length
    data = d
    // 保存到storage
    chrome.storage.local.set({ lastData: data })
    document.getElementById('apiC').textContent = (data.apis||[]).length
    document.getElementById('jsC').textContent = data.jsN||0
    document.getElementById('fwT').innerHTML = (data.fw||[]).map(f => `<span class="fw">${f.name}</span>`).join('')
    if (Object.keys(data.cfg||{}).length) document.getElementById('cfgT').innerHTML = Object.entries(data.cfg).slice(0,5).map(([k,v]) => `<span class="fw" title="${v}">${k}</span>`).join(' ')
    const sorted = (data.apis||[]).sort((a,b) => { const r={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1}; return (r[b.classify?.risk]||0)-(r[a.classify?.risk]||0) })
    render(sorted)
    // 状态提示
    const el = document.getElementById('apiE'); const badge = document.getElementById('badge')
    if (d.processing && sorted.length === 0) {
      el.innerHTML = `⏳ 正在下载分析JS (已处理${d.jsN||0}个)...<br><small>Badge数字实时更新</small>`
      el.style.display = 'block'
    } else if (sorted.length === 0) {
      el.innerHTML = '🔍 等待页面加载JS...<br><small>打开新页面后自动收集,无需操作</small>'
      el.style.display = 'block'
    } else if (d.processing) {
      el.innerHTML = `⏳ 持续分析中...已发现${sorted.length}个API,处理了${d.jsN||0}个JS文件`
      el.style.display = 'block'
    } else if (sorted.length > prevLen) {
      el.innerHTML = `✅ 已发现 ${sorted.length} 个API (新增${sorted.length-prevLen})`
      el.style.display = 'block'
      setTimeout(() => { el.style.display = 'none' }, 2000)
    } else {
      el.style.display = 'none'
    }
  })
}
refresh(); timer = setInterval(refresh, 1500)

// === Tab ===
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'))
  t.classList.add('active')
  document.getElementById('tab-apis').style.display = t.dataset.tab === 'apis' ? 'block' : 'none'
  document.getElementById('tab-fuzz').style.display = t.dataset.tab === 'fuzz' ? 'block' : 'none'
})

function render(list) {
  document.getElementById('apiB').innerHTML = list.map(a => `<tr><td class="mono" title="${a.path}">${a.path}</td><td>${a.method}</td><td>${a.classify?.label||'-'}</td><td>${a.classify?.risk?`<span class="badge b-${a.classify.risk}">${a.classify.risk}</span>`:''}</td></tr>`).join('')
}

// === Fuzz ===
document.getElementById('btnFuzz').onclick = () => {
  if (fuzzing) { fuzzing = false; document.getElementById('btnFuzz').textContent = '⚡ Fuzz'; clearInterval(timer); timer = setInterval(refresh, 1500); return }
  fuzzing = true; fuzzRes = []; total = 0; let idx = 0, running = 0
  document.getElementById('btnFuzz').textContent = '⏹ 停止'; document.querySelector('[data-tab="fuzz"]').click()
  document.getElementById('fE').style.display = 'none'
  clearInterval(timer) // 停止被动刷新,专注Fuzz

  const h = {}, hr = document.getElementById('hdrs').value.trim()
  if (hr) hr.split('\n').forEach(l => { const i = l.indexOf(':'); if (i > 0) h[l.slice(0,i).trim()] = l.slice(i+1).trim() })
  const base = data.url ? new URL(data.url).origin : ''
  const dict = DictGenerator.generate(data.fw||[], (data.apis||[]).map(a => a.path), base)
  const dedup = []; const s = new Set(); dict.forEach(d => { const k = d.url+d.method; if (!s.has(k)&&dedup.length<500) { s.add(k); dedup.push(d) } })
  total = dedup.length

  const run = () => {
    while (running < 5 && idx < dedup.length && fuzzing) {
      const req = dedup[idx++]; running++
      chrome.runtime.sendMessage({ action: 'fuzz', url: base+req.url, method: req.method, headers: h }).then(r => { fuzzRes.push(r); running--; renderFuzz(); run() })
    }
    if (idx >= dedup.length && running === 0) { fuzzing = false; document.getElementById('btnFuzz').textContent = '⚡ Fuzz'; renderFuzz(); timer = setInterval(refresh, 1500) }
  }
  for (let i = 0; i < 5; i++) run()
}

function renderFuzz() {
  const ok = fuzzRes.filter(r => r.status !== 404 && r.status !== 0)
  document.getElementById('fC').textContent = ok.length
  document.getElementById('fB').innerHTML = ok.sort((a,b) => a.status-b.status).map((r,i) => `<tr class="fuzz-row" data-idx="${i}" title="点击查看响应内容"><td class="mono">${r.url}</td><td>${r.method}</td><td><span class="s-${~~(r.status/100)}xx">${r.status||'E'}</span></td><td>${r.size>1024?(r.size/1024).toFixed(1)+'K':r.size+'B'}</td><td>${r.fp?.type||'-'}</td><td>${r.fp?.risk?`<span class="badge b-${r.fp.risk}">${r.fp.risk}</span>`:''}</td></tr>
    <tr class="resp-panel" id="resp-${i}"><td colspan="6"><div class="resp-hdr"><span>HTTP ${r.status||'?'} | ${(r.size||0)}B | ${r.contentType||'?'}</span><span onclick="this.closest('.resp-panel').classList.remove('show')" style="cursor:pointer;color:#e94560">✕</span></div><div class="resp-body${r.status>=400?' error':(r.contentType||'').includes('html')?' html':''}">${_preview(r)}</div></td></tr>`).join('')
  document.getElementById('fS').textContent = `测${fuzzRes.length}/${total} 命中${ok.length} — 点行看响应`

  document.querySelectorAll('.fuzz-row').forEach(tr => tr.onclick = () => {
    const panel = document.getElementById('resp-' + tr.dataset.idx)
    const wasOpen = panel.classList.contains('show')
    document.querySelectorAll('.resp-panel.show').forEach(p => p.classList.remove('show'))
    document.querySelectorAll('.fuzz-row.selected').forEach(r => r.classList.remove('selected'))
    if (!wasOpen) { panel.classList.add('show'); tr.classList.add('selected') }
  })
}

function _preview(r) {
  if (r.error) return `❌ ${r.body||'未知错误'}`
  if (!r.body) return '(空响应)'
  let b = r.body; if (b.length > 500) b = b.substring(0,500)+'\n... 截断,共'+r.body.length+'字符'
  try { return JSON.stringify(JSON.parse(b),null,2).substring(0,600) } catch(e) {}
  return b.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

// === 导出 ===
document.getElementById('btnHit').onclick = () => download((fuzzRes.filter(r => r.status!==404).map(r => r.url).join('\n')||(data.apis||[]).map(a => a.path).join('\n')),'api-hit.txt')
document.getElementById('btnDict').onclick = () => download((data.apis||[]).map(a => a.path).join('\n'),'api-dict.txt')
document.getElementById('btnClear').onclick = () => { data={};fuzzRes=[];render([]);renderFuzz();document.getElementById('apiC').textContent='0';document.getElementById('jsC').textContent='0';document.getElementById('fwT').innerHTML='';document.getElementById('cfgT').innerHTML='';chrome.runtime.sendMessage({action:'clear'})}
function download(t,n) { const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([t])); a.download=n; a.click() }
