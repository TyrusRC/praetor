/*
 * Universal Android SSL pinning bypass (Praetor W8 / mobile-mastg).
 *
 * Hooks the four most-common pinning code paths used by Android apps in
 * 2024-2026: javax.net.ssl.X509TrustManager, javax.net.ssl.HostnameVerifier,
 * OkHttpClient3 CertificatePinner.check, and the legacy Apache TrustManager.
 *
 * Run: frida -U -l ssl_pin_universal_android.js -f <pkg>
 * Pattern source: pcipolloni CodeShare. Refresh per Frida release.
 */
Java.perform(function () {
  console.log('[+] Praetor SSL-pin bypass loaded');

  // 1. X509TrustManager — root of most pinning checks.
  var TrustManager = Java.registerClass({
    name: 'praetor.PraetorTrustManager',
    implements: [Java.use('javax.net.ssl.X509TrustManager')],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var TrustManagerArr = [TrustManager.$new()];
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;',
    '[Ljavax.net.ssl.TrustManager;',
    'java.security.SecureRandom'
  ).implementation = function (km, tm, sr) {
    console.log('[+] SSLContext.init() bypassed');
    this.init(km, TrustManagerArr, sr);
  };

  // 2. HostnameVerifier — accept any hostname.
  var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
  var HNVImpl = Java.registerClass({
    name: 'praetor.PraetorHostnameVerifier',
    implements: [HostnameVerifier],
    methods: { verify: function (hostname, session) { return true; } }
  });
  Java.use('javax.net.ssl.HttpsURLConnection')
    .setDefaultHostnameVerifier(HNVImpl.$new());

  // 3. OkHttp 3+4 CertificatePinner.check(host, certificates).
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function (host, certs) {
        console.log('[+] OkHttp CertificatePinner.check bypassed for ' + host);
        return;
      };
    CertPinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0')
      .implementation = function (host, fn) {
        console.log('[+] OkHttp check$okhttp bypassed for ' + host);
        return;
      };
  } catch (e) { /* OkHttp not present */ }

  // 4. Legacy Apache.
  try {
    var ApacheTM = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
    ApacheTM.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean')
      .implementation = function () { return; };
  } catch (e) { /* legacy not present */ }
});
