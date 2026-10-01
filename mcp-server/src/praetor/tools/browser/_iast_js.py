"""The in-page IAST instrumentation shim (injected via add_init_script + evaluate).

Hooks the DOM sinks that drive client-side XSS / open-redirect / script-injection
and records every call into `window.__praetor_iast`, tagging each hit with which
known taint SOURCE (location.hash/search/href, document.referrer, window.name,
document.cookie) appears in the sink value.

NOTE (ceiling): source→sink correlation is a SUBSTRING heuristic, not char-level
taint propagation — it catches reflected/decoded source values reaching a sink
(the common DOM-XSS signal) but misses values transformed beyond a decode
(split/reversed/concatenated-through-vars). Upgrade path: a real taint engine
(string-wrapper propagation, DOMinator-style). Kept heuristic on purpose: zero
page-behaviour change, no perf cliff, works on any site with no setup.
"""

from __future__ import annotations

IAST_SHIM = r"""
(function(){
  if (window.__praetor_iast_installed) return;
  window.__praetor_iast_installed = true;
  window.__praetor_iast = window.__praetor_iast || [];
  var BUSY = false;
  function sourcesIn(value){
    var out = [];
    function add(label, sv){
      if (!sv) return;
      var cands = [sv];
      try { cands.push(decodeURIComponent(sv)); } catch(e){}
      if (sv[0] === '#' || sv[0] === '?'){
        var t = sv.slice(1); cands.push(t);
        try { cands.push(decodeURIComponent(t)); } catch(e){}
      }
      for (var i=0;i<cands.length;i++){
        if (cands[i] && cands[i].length >= 3 && value.indexOf(cands[i]) !== -1){
          out.push(label); return;
        }
      }
    }
    try {
      add('location.hash', location.hash);
      add('location.search', location.search);
      add('location.href', location.href);
      add('document.referrer', document.referrer);
      add('window.name', window.name);
      add('document.cookie', document.cookie);
    } catch(e){}
    return out;
  }
  function record(sink, value){
    if (BUSY) return;
    BUSY = true;
    try {
      value = (value == null) ? '' : String(value);
      var rec = {
        sink: sink,
        value: value.length > 300 ? value.slice(0,300) + '…' : value,
        sources: sourcesIn(value),
        url: location.href,
        ts: Date.now()
      };
      window.__praetor_iast.push(rec);
      if (window.__praetor_iast.length > 200) window.__praetor_iast.shift();
    } catch(e){} finally { BUSY = false; }
  }
  // eval / Function
  try { var _eval = window.eval;
    window.eval = function(c){ record('eval', c); return _eval(c); }; } catch(e){}
  try { var _Fn = window.Function;
    window.Function = function(){ record('Function', Array.prototype.join.call(arguments, ',')); return _Fn.apply(this, arguments); };
    window.Function.prototype = _Fn.prototype; } catch(e){}
  // document.write / writeln
  try { var _w = document.write.bind(document);
    document.write = function(){ record('document.write', Array.prototype.join.call(arguments, '')); return _w.apply(document, arguments); }; } catch(e){}
  try { var _wl = document.writeln.bind(document);
    document.writeln = function(){ record('document.writeln', Array.prototype.join.call(arguments, '')); return _wl.apply(document, arguments); }; } catch(e){}
  // innerHTML / outerHTML setters
  ['innerHTML','outerHTML'].forEach(function(prop){
    try {
      var desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (desc && desc.set){
        var set = desc.set;
        Object.defineProperty(Element.prototype, prop, {
          configurable: true, get: desc.get,
          set: function(v){ record(prop, v); return set.call(this, v); }
        });
      }
    } catch(e){}
  });
  // insertAdjacentHTML
  try { var _iah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(pos, html){ record('insertAdjacentHTML', html); return _iah.call(this, pos, html); }; } catch(e){}
  // setAttribute on dangerous attributes
  try { var _sa = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(n, v){
      if (/^(src|href|xlink:href|onclick|onerror|onload|action|formaction|data)$/i.test(n)) record('setAttribute('+n+')', v);
      return _sa.call(this, n, v);
    }; } catch(e){}
  // string-arg timers
  ['setTimeout','setInterval'].forEach(function(fn){
    try { var _t = window[fn];
      window[fn] = function(f){ if (typeof f === 'string') record(fn+'(string)', f); return _t.apply(window, arguments); }; } catch(e){}
  });
  // navigation sinks
  try { var _as = location.assign.bind(location);
    location.assign = function(u){ record('location.assign', u); return _as(u); }; } catch(e){}
  try { var _rp = location.replace.bind(location);
    location.replace = function(u){ record('location.replace', u); return _rp(u); }; } catch(e){}
  try { var _open = window.open;
    window.open = function(u){ if (u) record('window.open', u); return _open.apply(window, arguments); }; } catch(e){}
  // incoming postMessage data (passive)
  try {
    window.addEventListener('message', function(e){
      try { record('onmessage', typeof e.data === 'string' ? e.data : JSON.stringify(e.data)); } catch(_){}
    }, true);
  } catch(e){}
})();
"""
