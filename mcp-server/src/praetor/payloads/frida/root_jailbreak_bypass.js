/*
 * Root / jailbreak detection bypass (Praetor W8).
 * Android: RootBeer, common file existence checks, Build.TAGS.
 * iOS: hooks fork() + jailbreak path checks.
 */
if (Java.available) {
  Java.perform(function () {
    // RootBeer library.
    try {
      var RB = Java.use('com.scottyab.rootbeer.RootBeer');
      ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
       'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBusyBoxBinary',
       'checkForSuBinary', 'checkSuExists', 'checkForRWPaths', 'checkForDangerousProps',
       'checkForRootNative', 'detectRootCloakingApps'].forEach(function (m) {
        try { RB[m].implementation = function () { return false; }; } catch (e) {}
      });
      console.log('[+] RootBeer bypassed');
    } catch (e) {}

    // Common file existence root signals.
    var File = Java.use('java.io.File');
    var rootPaths = ['/system/bin/su','/system/xbin/su','/sbin/su',
      '/system/app/Superuser.apk','/system/etc/init.d/99SuperSUDaemon',
      '/dev/com.koushikdutta.superuser.daemon/','/data/local/tmp/su'];
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < rootPaths.length; i++)
        if (path === rootPaths[i]) return false;
      return this.exists.call(this);
    };

    // Build.TAGS check.
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    console.log('[+] Build.TAGS forced to release-keys');
  });
}

if (ObjC.available) {
  // iOS — fork() returning -1 confirms jailbreak; force EPERM to mask.
  Interceptor.attach(Module.findExportByName(null, 'fork'), {
    onLeave: function (ret) { ret.replace(0); }
  });
  // /Applications/Cydia.app and friends.
  var open = Module.findExportByName(null, 'open');
  Interceptor.attach(open, {
    onEnter: function (args) {
      var path = Memory.readUtf8String(args[0]);
      var blocked = ['/Applications/Cydia.app','/Library/MobileSubstrate/MobileSubstrate.dylib',
                     '/bin/bash','/usr/sbin/sshd','/etc/apt','/private/var/lib/apt/'];
      for (var i = 0; i < blocked.length; i++) if (path.indexOf(blocked[i]) === 0) {
        args[0] = Memory.allocUtf8String('/dev/null');
        return;
      }
    }
  });
  console.log('[+] iOS jailbreak detection bypassed');
}
