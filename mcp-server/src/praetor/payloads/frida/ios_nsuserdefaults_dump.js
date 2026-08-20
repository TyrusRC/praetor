/*
 * NSUserDefaults dump (Praetor W9 / iOS / privacy class).
 *
 * Dumps the standardUserDefaults dictionary and hooks setObject:forKey: /
 * objectForKey: to surface secrets stored client-side.
 *
 * Common findings: API keys, auth tokens, feature-flag overrides, PII,
 * "remember me" credentials persisted without Keychain protection class.
 *
 * Run: frida -U -l ios_nsuserdefaults_dump.js -f <bundle_id>
 */
if (ObjC.available) {
  var NSUserDefaults = ObjC.classes.NSUserDefaults;

  // Initial dump of every key in standardUserDefaults.
  setTimeout(function () {
    var defaults = NSUserDefaults.standardUserDefaults();
    var dict = defaults.dictionaryRepresentation();
    var keys = dict.allKeys();
    var count = keys.count();
    console.log('[NSUserDefaults] initial dump (' + count + ' keys)');
    for (var i = 0; i < count; i++) {
      var key = keys.objectAtIndex_(i);
      var value = dict.objectForKey_(key);
      console.log('  ' + key.toString() + ' = ' + (value ? value.toString() : 'nil'));
    }
  }, 500);

  // Live hook: every subsequent set.
  NSUserDefaults['- setObject:forKey:'].implementation = ObjC.implement(
    NSUserDefaults['- setObject:forKey:'],
    function (self, sel, obj, key) {
      console.log('[NSUserDefaults.set] '
        + (key ? key.toString() : 'nil') + ' = '
        + (obj ? obj.toString() : 'nil'));
      return self.setObject_forKey_(obj, key);
    }
  );

  console.log('[+] NSUserDefaults dump + setter hook loaded');
}
