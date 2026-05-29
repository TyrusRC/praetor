/*
 * Cipher / Mac / SecretKeySpec key material dump (Praetor W8).
 * Prints key bytes, IV, plaintext/ciphertext pairs at use-time.
 */
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (data) {
    console.log('[Cipher] algorithm=' + this.getAlgorithm() + ' input.len=' + data.length);
    var out = this.doFinal(data);
    console.log('[Cipher] output.len=' + out.length);
    return out;
  };

  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
    var hex = Array.from(key).map(function (b) {
      return ('00' + (b & 0xff).toString(16)).slice(-2);
    }).join('');
    console.log('[SecretKeySpec] algo=' + algo + ' key=' + hex);
    return this.$init(key, algo);
  };

  var Mac = Java.use('javax.crypto.Mac');
  Mac.doFinal.overload('[B').implementation = function (data) {
    console.log('[Mac] algorithm=' + this.getAlgorithm());
    return this.doFinal(data);
  };
});
