// ============================================================
// DesJsFinder Offscreen Document
// 在完整 DOM 上下文中发请求，可携带 Cookie 和自定义 Headers
// 借鉴 Phantom 的 offscreen document 架构
// ============================================================

let _requestId = 0
const _pending = new Map()

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'offscreenFetch') {
    _doFetch(msg.id, msg.url, msg.method, msg.headers, msg.body, msg.timeout)
      .then(r => sendResponse({ success: true, data: r }))
      .catch(e => sendResponse({ success: false, error: e.message }))
    return true
  }
  if (msg.action === 'offscreenFetchMany') {
    Promise.allSettled(msg.requests.map(r =>
      _doFetch(r.id, r.url, r.method, r.headers, r.body, r.timeout)
    )).then(results => {
      sendResponse({ success: true, data: results.map((r, i) => ({
        id: msg.requests[i].id,
        ok: r.status === 'fulfilled',
        data: r.status === 'fulfilled' ? r.value : null,
        error: r.status === 'rejected' ? r.reason?.message : null,
      })) })
    })
    return true
  }
  if (msg.action === 'ping') {
    sendResponse({ pong: true })
  }
})

async function _doFetch(id, url, method, headers, body, timeout) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout || 10000)

  const fetchOpts = {
    method: method || 'GET',
    headers: { ...headers } || {},
    signal: controller.signal,
    credentials: 'include',
  }

  // Remove headers that fetch API auto-sets
  delete fetchOpts.headers['content-length']
  delete fetchOpts.headers['host']
  delete fetchOpts.headers['origin']
  delete fetchOpts.headers['referer']

  // Set body for non-GET/HEAD
  if (body && method !== 'GET' && method !== 'HEAD') {
    fetchOpts.body = body
  }

  try {
    const resp = await fetch(url, fetchOpts)
    clearTimeout(timer)
    const text = await resp.text()
    // Collect response headers
    const respHeaders = {}
    resp.headers.forEach((v, k) => { respHeaders[k] = v })
    // Trim body for response
    const maxBody = 8192 // 8KB cap for offscreen responses
    return {
      id,
      status: resp.status,
      statusText: resp.statusText,
      headers: respHeaders,
      contentType: resp.headers.get('content-type') || '',
      body: text.substring(0, maxBody),
      size: text.length,
      url: resp.url,
    }
  } catch (e) {
    clearTimeout(timer)
    if (e.name === 'AbortError') {
      return { id, status: 0, error: 'timeout', body: '' }
    }
    return { id, status: 0, error: e.message, body: '' }
  }
}
