/*
 * Android KeyStore + iOS Keychain hook (Praetor W8).
 * Dumps aliases / labels at lookup time.
 */
if (Java.available) {
  Java.perform(function () {
    var KS = Java.use('java.security.KeyStore');
    KS.getKey.implementation = function (alias, pwd) {
      console.log('[Keystore.getKey] alias=' + alias);
      return this.getKey(alias, pwd);
    };
    KS.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (p) {
      console.log('[Keystore.load] type=' + this.getType());
      return this.load(p);
    };
  });
}
if (ObjC.available) {
  // SecItemCopyMatching + SecItemAdd from Security framework.
  var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
  Interceptor.attach(SecItemCopyMatching, {
    onEnter: function (args) {
      var query = new ObjC.Object(args[0]);
      console.log('[Keychain.copyMatching] query=' + query.toString());
    }
  });
  console.log('[+] Keychain hooks installed');
}
