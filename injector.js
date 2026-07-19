// ============================================================
// DesJsFinder — MAIN world runtime interceptor
// Monkey-patch fetch/XHR to capture all API traffic at runtime.
// Sends intercepted data to content.js via window.postMessage.
// ============================================================
(function () {
  'use strict';

  const TAG = '__desjsfinder_intercepted__';
  const MAX_BODY = 512 * 1024; // 512KB

  function post(data) {
    try { window.postMessage({ type: TAG, ...data }, '*'); } catch (e) {}
  }

  // ====== fetch() monkey-patch ======
  const _fetch = window.fetch;
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input?.url || '');
    const method = (init?.method || 'GET').toUpperCase();
    let reqBody = '';
    try { if (init?.body && typeof init.body === 'string') reqBody = init.body.slice(0, 8192); } catch (e) {}

    // capture Authorization header
    let auth = ''
    try {
      if (init?.headers) {
        if (init.headers instanceof Headers) auth = init.headers.get('authorization') || init.headers.get('Authorization') || ''
        else if (typeof init.headers === 'object') {
          for (const [k, v] of Object.entries(init.headers)) {
            if (k.toLowerCase() === 'authorization') { auth = String(v); break }
          }
        }
      }
    } catch(e) {}

    const response = await _fetch.apply(this, arguments);

    try {
      if (auth) post({ kind: 'token', authHeader: auth })
      const ct = (response.headers.get('content-type') || '').toLowerCase();
      const isText = !ct || ct.includes('text/') || ct.includes('json') || ct.includes('javascript') || ct.includes('xml') || ct.includes('form');
      if (isText && response.status < 500) {
        const clone = response.clone();
        clone.text().then(body => {
          if (!body || body.length < 8) return;
          post({
            kind: 'fetch',
            url, method, status: response.status, contentType: ct,
            reqBody, respBody: body.slice(0, MAX_BODY),
          });
        }).catch(() => {});
      } else if (response.status < 500) {
        // non-text but got a response — at least log the URL
        post({ kind: 'fetch', url, method, status: response.status, contentType: ct, reqBody, respBody: '' });
      }
    } catch (e) {}

    return response;
  };

  // ====== XMLHttpRequest monkey-patch ======
  const XHR = XMLHttpRequest.prototype;
  const _open = XHR.open, _send = XHR.send;
  XHR.open = function (method, url) {
    this.__djf_url = url;
    this.__djf_method = method;
    return _open.apply(this, arguments);
  };
  const _setHeader = XHR.setRequestHeader;
  XHR.setRequestHeader = function (name, value) {
    if (name && name.toLowerCase() === 'authorization') this.__djf_auth = String(value || '');
    return _setHeader.apply(this, arguments);
  };
  XHR.send = function (body) {
    const self = this;
    let reqBody = '';
    try { if (typeof body === 'string') reqBody = body.slice(0, 8192); } catch (e) {}
    self.addEventListener('loadend', function () {
      if (self.__djf_auth) post({ kind: 'token', authHeader: self.__djf_auth })
      try {
        const ct = (self.getResponseHeader('content-type') || '').toLowerCase();
        const isText = !ct || ct.includes('text/') || ct.includes('json') || ct.includes('javascript') || ct.includes('xml') || ct.includes('form');
        if (isText && self.status < 500) {
          post({
            kind: 'xhr',
            url: self.__djf_url || '', method: self.__djf_method || 'GET', status: self.status, contentType: ct,
            reqBody, respBody: (self.responseText || '').slice(0, MAX_BODY),
          });
        } else if (self.status < 500) {
          post({ kind: 'xhr', url: self.__djf_url || '', method: self.__djf_method || 'GET', status: self.status, contentType: ct, reqBody, respBody: '' });
        }
      } catch (e) {}
    });
    return _send.apply(this, arguments);
  };

  // ====== Wappalyzer JS Globals Scanner (MAIN world) ======
  // 定期扫描 window 对象，收集可能匹配 Wappalyzer 指纹的全局变量
  const WAP_GLOBAL_PREFIXES = new Set([
    'React','Vue','angular','jQuery','$','_','Backbone','Ember','Knockout',
    'Sentry','Raven','ga','gtag','dataLayer','FB','twttr','stripe',
    'axios','fetch','XMLHttpRequest','Map','Chart','echarts','zrender',
    'NEXT','__NEXT','Nuxt','Storefront','w2ui','M','L','tinymce',
    'Shopify','WooCommerce','Magento','wp','elementor','yoast',
    'gtm','google','_gaq','mixpanel','amplitude','heap','hotjar',
    'Intercom','Zendesk','livechat','HelpCrunch','Smartsupp',
    'freshteam','freshdesk','helpscout','tawk','crisp',
    'wpml','polylang','qtranslate','bogo','translatepress',
    'swiper','Swiper','Splide','Glide','Flickity','Slick',
    'gsap','anime','ScrollMagic','LocomotiveScroll','AOS',
    'LazyLoad','vanillaLazyLoad','lozad','intersectionObserver',
    'prism','highlight','MathJax','katex','mermaid',
    'dayjs','moment','luxon','dateFns','timeago',
    'lodash','underscore','ramda','immutable','mori',
    'Rx','babel','coreJs','regeneratorRuntime',
    'webpack','__webpack','requirejs','System','SystemJS',
    'parcel','vite','rollup','browserSync',
    'DOMPurify','xss','sanitize','validator',
    'sortable','dragula','interact','droppable',
    'pdfjs','PDFObject','viewerjs','flowpaper',
    'videojs','plyr','mediaelement','jwplayer','flowplayer',
    'howler','Tone','pizzicato','wavesurfer',
    'three','THREE','babylon','pixi','phaser',
    'ace','monaco','codemirror','textarea','prosemirror',
    'draft','slate','quill','pell','wysiwyg',
    'cropper','uppy','dropzone','fineUploader','plupload',
    'pwa','serviceWorker','workbox','offline','backgroundSync',
    'socket','io','WebSocket','EventSource','SSEClient',
    'Firebase','firebase','Pusher','Ably','PubNub',
    'PayPal','stripe','braintree','square','authorize',
    'googleTagManager','googletag','doubleclick','adsbygoogle',
    'outbrain','taboola','mgid','revcontent','polar',
    'optimizely','VWO','ABTasty','convert','googleOptimize',
    'newRelic','datadog','sentry','rollbar','bugsnag','airbrake',
    'logRocket','fullStory','mouseflow','hotjar','clarity',
    'youtube','YT','vimeo','dailymotion','twitch',
    'googleMaps','mapbox','leaflet','Cesium','openLayers',
    'algolia','elasticsearch','fuse','flexSearch','lunr',
    'marked','showdown','remarkable','commonmark','markdown',
    'highlightJs','prismJs','rainbow','shiki','rehype',
    'tailwind','bootstrap','foundation','bulma','semanticUi',
    'materialize','antd','element','vuetify','quasar',
    'storybook','styleguidist','docz','docusaurus',
    'next','nuxt','gatsby','gridsome','eleventy',
    'webpack','rollup','parcel','vite','esbuild','swc',
  ])

  // Scan window globals every 3 seconds and send to content script
  function scanGlobals() {
    const globals = {}
    try {
      for (const key of Object.getOwnPropertyNames(window)) {
        if (key.length < 2 || key.length > 60) continue
        // Only include keys that match known Wappalyzer prefixes
        const firstPart = key.split('.')[0]
        if (!WAP_GLOBAL_PREFIXES.has(firstPart)) continue
        try {
          const val = window[key]
          if (val === undefined || val === null) continue
          if (typeof val === 'function') {
            globals[key] = '[Function]'
          } else if (typeof val === 'object' && !Array.isArray(val) && val !== window && val !== document) {
            try {
              const str = JSON.stringify(val).slice(0, 500)
              if (str.length > 3) globals[key] = str
            } catch(e) {
              globals[key] = '[Object]'
            }
            // Check common version properties
            for (const sub of ['version','VERSION','SDK_VERSION','VERSION_NUMBER','build']) {
              if (val[sub] !== undefined) {
                globals[key + '.' + sub] = String(val[sub]).slice(0, 100)
              }
            }
          } else if (typeof val === 'string' && val.length < 200) {
            globals[key] = val
          }
        } catch(e) {}
      }
    } catch(e) {}
    if (Object.keys(globals).length > 0) {
      window.__desjsfinder_globals__ = globals
      post({ kind: 'wap-globals', globals })
    }
  }

  // Initial scan after a short delay (let page load)
  setTimeout(scanGlobals, 1500)
  // Periodic rescan
  setInterval(scanGlobals, 5000)
})();