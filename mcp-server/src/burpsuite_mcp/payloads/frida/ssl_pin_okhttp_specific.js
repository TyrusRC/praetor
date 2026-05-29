/*
 * OkHttp v3+v4 specific SSL pin bypass (Praetor W8).
 * Targets when universal hook is intercepted by app-side pin enforcement.
 */
Java.perform(function () {
  ['okhttp3.CertificatePinner', 'com.squareup.okhttp.CertificatePinner'].forEach(function (cls) {
    try {
      var CP = Java.use(cls);
      CP.check.overloads.forEach(function (ov) {
        ov.implementation = function () { return; };
      });
      console.log('[+] ' + cls + ' all overloads bypassed');
    } catch (e) { /* not present */ }
  });
});
