/*
 * Log every Intent / deep-link URI received by Activity.onCreate (Praetor W8).
 * Use to enumerate the deep-link attack surface as the operator drives the UI.
 */
Java.perform(function () {
  var Activity = Java.use('android.app.Activity');
  Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
    var intent = this.getIntent();
    var action = intent ? intent.getAction() : null;
    var data = intent ? intent.getData() : null;
    var extras = intent ? intent.getExtras() : null;
    console.log('[Intent] activity=' + this.getClass().getName()
      + ' action=' + action
      + ' data=' + (data ? data.toString() : 'null')
      + ' extras=' + (extras ? extras.toString() : 'null'));
    return this.onCreate(b);
  };
});
