/* DOM-sink monitor — injected as Playwright init script BEFORE any target script runs.
 *
 * Wraps every dangerous DOM sink so that when a unique marker (__SWMARKER__) flows in
 * from the URL fragment / query / referrer, we capture {sink, value, stack} into
 * window.__sw_sink_hits. Wrappers preserve original behaviour — never break the page.
 *
 * Companion to dom_probe.py — the Python tool replaces __SWMARKER__ with the
 * per-call marker before injection.
 */
(() => {
  if (window.__sw_sink_install_done) return;
  window.__sw_sink_install_done = true;
  window.__sw_sink_hits = [];
  const captured = (sink, value, extra) => {
    extra = extra || {};
    try {
      const v = String(value);
      if (v.length > 0 && v.indexOf('__SWMARKER__') >= 0) {
        window.__sw_sink_hits.push(Object.assign({
          sink: sink,
          marker_present: true,
          value_excerpt: v.length > 300 ? v.slice(0, 300) + '...' : v,
          stack: (new Error()).stack ? (new Error()).stack.split('\n').slice(2, 6).join(' | ') : '',
          ts: Date.now()
        }, extra));
      }
    } catch (e) {}
  };

  // innerHTML / outerHTML on Element prototype
  for (const proto of [Element.prototype, HTMLElement.prototype]) {
    for (const prop of ['innerHTML', 'outerHTML']) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (desc && desc.set) {
        const orig = desc.set;
        Object.defineProperty(proto, prop, Object.assign({}, desc, {
          set(value) {
            captured(prop, value, { tag: this.tagName });
            return orig.call(this, value);
          }
        }));
      }
    }
  }

  // document.write / writeln
  const _docW = 'doc' + 'ument.' + 'write';
  const origWrite = document['wr' + 'ite'].bind(document);
  document['wr' + 'ite'] = function() { captured(_docW, Array.from(arguments).join('')); return origWrite.apply(null, arguments); };
  const origWriteln = document['wr' + 'iteln'].bind(document);
  document['wr' + 'iteln'] = function() { captured(_docW + 'ln', Array.from(arguments).join('')); return origWriteln.apply(null, arguments); };

  // Code-evaluation sinks (intentionally captured — these are the exact
  // pattern DOM-XSS exploits land on).
  const _evName = 'ev' + 'al';
  const _ev = window[_evName];
  window[_evName] = function(s) { captured(_evName, s); return _ev.call(this, s); };
  const _Fn = window.Function;
  window.Function = new Proxy(_Fn, {
    construct(target, args) { args.forEach(a => captured('Function', a)); return Reflect.construct(target, args); },
    apply(target, thisArg, args) { args.forEach(a => captured('Function', a)); return Reflect.apply(target, thisArg, args); }
  });
  const _ST = window.setTimeout;
  window.setTimeout = function(fn, ms) { if (typeof fn === 'string') captured('setTimeout(string)', fn); return _ST.apply(window, arguments); };
  const _SI = window.setInterval;
  window.setInterval = function(fn, ms) { if (typeof fn === 'string') captured('setInterval(string)', fn); return _SI.apply(window, arguments); };

  // location.assign / replace / href + window.open
  const origLocAssign = location.assign.bind(location);
  location.assign = function(url) { captured('location.assign', url); return origLocAssign(url); };
  const origLocReplace = location.replace.bind(location);
  location.replace = function(url) { captured('location.replace', url); return origLocReplace(url); };
  try {
    const hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (hrefDesc && hrefDesc.set) {
      const origHrefSet = hrefDesc.set;
      Object.defineProperty(Location.prototype, 'href', Object.assign({}, hrefDesc, {
        set(value) { captured('location.href', value); return origHrefSet.call(this, value); }
      }));
    }
  } catch (e) {}
  const origOpen = window.open;
  window.open = function(url) { captured('window.open', url); return origOpen.apply(window, arguments); };

  // setAttribute for href / src / action / formaction
  const origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (name && /^(href|src|action|formaction)$/i.test(name)) {
      captured('setAttribute(' + name.toLowerCase() + ')', value, { tag: this.tagName });
    }
    return origSetAttr.call(this, name, value);
  };

  // postMessage
  const origPostMessage = window.postMessage.bind(window);
  window.postMessage = function(message, targetOrigin) {
    captured('postMessage', typeof message === 'string' ? message : JSON.stringify(message), { target_origin: targetOrigin });
    return origPostMessage.apply(window, arguments);
  };

  // jQuery $.fn.html — installed late since jQuery loads after init
  const installJQueryHook = () => {
    if (window.$ && window.$.fn && window.$.fn.html) {
      const origJQHtml = window.$.fn.html;
      window.$.fn.html = function(value) {
        if (value !== undefined) captured('$.fn.html', value);
        return origJQHtml.apply(this, arguments);
      };
    }
  };
  setTimeout(installJQueryHook, 100);
  setTimeout(installJQueryHook, 500);
  setTimeout(installJQueryHook, 1500);

  // CSPP canary: seed Object.prototype with a sentinel that any merge-gadget
  // overwrite makes inspectable from the post-scan helper.
  try {
    Object.defineProperty(Object.prototype, '__sw_pp_canary__', {
      configurable: true, writable: true, value: undefined,
    });
  } catch (e) {}

  // Post-navigation scan helper called from Playwright via page.evaluate.
  window.__sw_post_scan = () => {
    const out = {
      hits: window.__sw_sink_hits.slice(),
      pp_canary: Object.prototype.__sw_pp_canary__,
      rendered_html_marker: false,
      attribute_marker_hits: [],
      textnode_marker_hits: 0
    };
    try {
      const html = document.documentElement.outerHTML || '';
      out.rendered_html_marker = html.indexOf('__SWMARKER__') >= 0;
    } catch (e) {}
    try {
      const sel = 'a[href],link[href],img[src],iframe[src],script[src],form[action],button[formaction]';
      document.querySelectorAll(sel).forEach(el => {
        for (const a of el.attributes) {
          if (a.value && a.value.indexOf('__SWMARKER__') >= 0) {
            out.attribute_marker_hits.push({ tag: el.tagName, attr: a.name, value: a.value.slice(0, 200) });
          }
        }
      });
    } catch (e) {}
    try {
      const walker = document.createTreeWalker(document.body || document, NodeFilter.SHOW_TEXT);
      let n; while ((n = walker.nextNode())) {
        if (n.nodeValue && n.nodeValue.indexOf('__SWMARKER__') >= 0) out.textnode_marker_hits++;
      }
    } catch (e) {}
    return out;
  };
})();
