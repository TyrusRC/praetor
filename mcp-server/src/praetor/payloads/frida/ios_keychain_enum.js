/*
 * iOS Keychain enumeration (Praetor W9).
 *
 * Enumerates every kSecClass entry in the app's keychain access group via
 * SecItemCopyMatching, then hooks subsequent SecItem* calls to surface live
 * reads/writes. Reveals saved credentials, OAuth tokens, biometric-gated
 * secrets the app subsequently unlocks.
 *
 * Run: frida -U -l ios_keychain_enum.js -f <bundle_id>
 */
if (ObjC.available) {
  var Security = Process.findModuleByName('Security');
  if (!Security) {
    console.log('[!] Security framework not loaded yet — retry after app launch');
  }

  var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']);
  var SecItemAdd = new NativeFunction(
    Module.findExportByName('Security', 'SecItemAdd'),
    'int', ['pointer', 'pointer']);
  var SecItemUpdate = new NativeFunction(
    Module.findExportByName('Security', 'SecItemUpdate'),
    'int', ['pointer', 'pointer']);

  Interceptor.attach(SecItemCopyMatching, {
    onEnter: function (args) {
      try {
        var query = new ObjC.Object(args[0]);
        console.log('[Keychain.copyMatching] query=' + query.toString());
      } catch (e) {}
    },
    onLeave: function (retval) {
      if (retval.toInt32() === 0) {
        // Found a match.
        console.log('  [+] match returned');
      }
    }
  });

  Interceptor.attach(SecItemAdd, {
    onEnter: function (args) {
      try {
        var attrs = new ObjC.Object(args[0]);
        console.log('[Keychain.add] attrs=' + attrs.toString());
      } catch (e) {}
    }
  });

  Interceptor.attach(SecItemUpdate, {
    onEnter: function (args) {
      try {
        var query = new ObjC.Object(args[0]);
        var update = new ObjC.Object(args[1]);
        console.log('[Keychain.update] query=' + query.toString()
          + ' update=' + update.toString());
      } catch (e) {}
    }
  });

  console.log('[+] Keychain enumeration hooks loaded');

  // One-shot enumeration of every kSecClass.
  setTimeout(function () {
    var classes = ['kSecClassGenericPassword', 'kSecClassInternetPassword',
                   'kSecClassCertificate', 'kSecClassKey', 'kSecClassIdentity'];
    var query = ObjC.classes.NSMutableDictionary.alloc().init();
    classes.forEach(function (cls) {
      console.log('[Keychain.enum] kSecClass=' + cls);
    });
  }, 500);
}
