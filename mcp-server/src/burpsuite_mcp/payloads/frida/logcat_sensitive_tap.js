/*
 * logcat tap — relay Log.* calls to Frida console (Praetor W8 / privacy class).
 * Reveals data the app writes to logcat even when device log level filters it.
 */
Java.perform(function () {
  var Log = Java.use('android.util.Log');
  ['v', 'd', 'i', 'w', 'e', 'wtf'].forEach(function (level) {
    Log[level].overload('java.lang.String', 'java.lang.String').implementation =
      function (tag, msg) {
        console.log('[Log.' + level + '] [' + tag + '] ' + msg);
        return this[level](tag, msg);
      };
  });
});
