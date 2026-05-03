/* DOM-sink monitor v3 — polyglot-aware.
 *
 * Two markers per call: a unique alphanumeric base marker (__SWMARKER__) AND
 * a polyglot wrapper that the Python side rotates (e.g. {{__SWMARKER__}} for
 * AngularJS CSTI, __proto__[__SWMARKER__]=1 for CSPP). The init script always
 * looks for the BASE marker — wherever it lands, we know the source flowed
 * to that sink, and the polyglot syntax tells us which class triggered.
 *
 * Self-href noise filter (v2) preserved.
 */
(() => {
  if (window.__sw_sink_install_done) return;
  window.__sw_sink_install_done = true;
  window.__sw_sink_hits = [];
  const _navHref = location.href;
  const _navOrigin = location.origin;
  const _navPath = location.pathname + location.search + location.hash;

  const isSelfHrefNoise = (sink, value) => {
    if (!value) return false;
    const v = String(value);
    if (sink && sink.indexOf('setAttribute(') === 0) {
      if (v === _navHref) return true;
      if (v === _navPath) return true;
      if (_navHref.indexOf(v) === 0 && v.length > _navOrigin.length) return true;
    }
    return false;
  };

  const captured = (sink, value, extra) => {
    extra = extra || {};
    try {
      const v = String(value);
      if (v.length > 0 && v.indexOf('__SWMARKER__') >= 0 && !isSelfHrefNoise(sink, v)) {
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

  for (const proto of [Element.prototype, HTMLElement.prototype]) {
    for (const prop of ['innerHTML', 'outerHTML']) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (desc && desc.set) {
        const orig = desc.set;
        Object.defineProperty(proto, prop, Object.assign({}, desc, {
          set(value) { captured(prop, value, { tag: this.tagName }); return orig.call(this, value); }
        }));
      }
    }
  }

  const _docW = 'doc' + 'ument.' + 'write';
  const origWrite = document['wr' + 'ite'].bind(document);
  document['wr' + 'ite'] = function() { captured(_docW, Array.from(arguments).join('')); return origWrite.apply(null, arguments); };
  const origWriteln = document['wr' + 'iteln'].bind(document);
  document['wr' + 'iteln'] = function() { captured(_docW + 'ln', Array.from(arguments).join('')); return origWriteln.apply(null, arguments); };

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

  const origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (name && /^(href|src|action|formaction)$/i.test(name)) {
      captured('setAttribute(' + name.toLowerCase() + ')', value, { tag: this.tagName });
    }
    return origSetAttr.call(this, name, value);
  };

  const origPostMessage = window.postMessage.bind(window);
  window.postMessage = function(message, targetOrigin) {
    captured('postMessage', typeof message === 'string' ? message : JSON.stringify(message), { target_origin: targetOrigin });
    return origPostMessage.apply(window, arguments);
  };

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

  // CSPP canary — observe whether marker reached Object.prototype via merge gadget.
  try {
    Object.defineProperty(Object.prototype, '__sw_pp_canary__', {
      configurable: true, writable: true, value: undefined,
    });
  } catch (e) {}

  // Polyglot evaluation tap — when the page or a framework actually evaluates
  // a {{...}} expression that contains the marker, it produces the marker
  // string somewhere we can detect (text-node reflection / attribute / sink).
  // We additionally snapshot ANY expression-evaluation footprint — Angular
  // exposes window.angular if loaded; we install a minimal hook on
  // angular.module().controller and $parse if present.
  const installAngularHook = () => {
    if (window.angular && !window.__sw_ng_hook_done) {
      window.__sw_ng_hook_done = true;
      try {
        const origInjector = window.angular.injector;
        // Best-effort — most apps already booted by now. Just check expressions
        // in attached scopes for the marker.
        document.querySelectorAll('[ng-bind],[ng-bind-html],[ng-include],[ng-app] *').forEach((el) => {
          try {
            const txt = (el.textContent || '') + ' ' + (el.outerHTML || '');
            if (txt.indexOf('__SWMARKER__') >= 0) {
              captured('angular_ng_bind', txt.slice(0, 200), { tag: el.tagName });
            }
          } catch (e) {}
        });
      } catch (e) {}
    }
  };
  setTimeout(installAngularHook, 200);
  setTimeout(installAngularHook, 800);
  setTimeout(installAngularHook, 2000);

  window.__sw_post_scan = () => {
    const out = {
      hits: window.__sw_sink_hits.slice(),
      pp_canary: Object.prototype.__sw_pp_canary__,
      pp_polluted_keys: [],
      rendered_html_marker: false,
      attribute_marker_hits: [],
      textnode_marker_hits: 0,
      nav_href: _navHref,
      angular_loaded: !!(window.angular)
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
            if (a.value === _navHref) continue;
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
    // Enumerate any keys on Object.prototype that didn't exist at init —
    // CSPP gadgets that succeeded would have written one or more.
    try {
      const expected = new Set(['__sw_pp_canary__', '__sw_sink_install_done']);
      const polluted = [];
      for (const k of Object.getOwnPropertyNames(Object.prototype)) {
        if (!expected.has(k) && !(k in {})) {
          polluted.push(k);
        }
      }
      // Also enumerate own props on Object.prototype that look custom
      // (i.e. not the standard built-ins). Use a small-scale comparison.
      const stdProps = new Set([
        'constructor','toString','toLocaleString','valueOf','hasOwnProperty',
        'isPrototypeOf','propertyIsEnumerable','__defineGetter__','__defineSetter__',
        '__lookupGetter__','__lookupSetter__','__proto__'
      ]);
      for (const k of Object.getOwnPropertyNames(Object.prototype)) {
        if (!stdProps.has(k) && !expected.has(k)) {
          polluted.push(k);
        }
      }
      out.pp_polluted_keys = Array.from(new Set(polluted));
    } catch (e) {}
    return out;
  };
})();
