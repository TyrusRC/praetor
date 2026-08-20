/*
 * Clipboard hook (Praetor W8 / privacy class).
 * Detects sensitive data passing through ClipboardManager.setText / getText.
 */
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (clip) {
    var item = clip.getItemAt(0);
    console.log('[Clipboard.set] ' + (item ? item.getText() : '(no text)'));
    return this.setPrimaryClip(clip);
  };
  CM.getPrimaryClip.implementation = function () {
    var clip = this.getPrimaryClip();
    if (clip) {
      var item = clip.getItemAt(0);
      console.log('[Clipboard.get] ' + (item ? item.getText() : '(no text)'));
    }
    return clip;
  };
});
