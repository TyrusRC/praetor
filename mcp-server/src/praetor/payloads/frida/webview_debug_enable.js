/*
 * Force-enable WebView debugging + enumerate addJavascriptInterface
 * exposed methods (Praetor W8).
 *
 * After loading: chrome://inspect/#devices on host shows the WebView.
 * Method signatures of every @JavascriptInterface are printed at load.
 */
Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');
  WebView.setWebContentsDebuggingEnabled.implementation = function (v) {
    console.log('[+] setWebContentsDebuggingEnabled forced to true');
    return this.setWebContentsDebuggingEnabled(true);
  };
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[+] addJavascriptInterface: name=' + name + ' class=' + obj.getClass().getName());
    var methods = obj.getClass().getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      console.log('    method: ' + methods[i].toString());
    }
    return this.addJavascriptInterface(obj, name);
  };
});
