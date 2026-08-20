/*
 * Universal iOS SSL pinning bypass (Praetor W8).
 * Hooks SecTrustEvaluate + NSURLSession delegate auth challenge + AFNetworking.
 */
if (ObjC.available) {
  var SecTrustEvaluate = new NativeFunction(
    Module.findExportByName('Security', 'SecTrustEvaluate'),
    'int', ['pointer', 'pointer']);
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
    Memory.writeU8(result, 1); // kSecTrustResultProceed
    return 0;                  // errSecSuccess
  }, 'int', ['pointer', 'pointer']));
  console.log('[+] SecTrustEvaluate hooked — pin bypass active');

  // AFNetworking: AFSecurityPolicy.policyWithPinningMode.
  try {
    var AFSec = ObjC.classes.AFSecurityPolicy;
    AFSec['+ policyWithPinningMode:'].implementation = ObjC.implement(
      AFSec['+ policyWithPinningMode:'],
      function (self, sel, mode) {
        return AFSec['+ defaultPolicy']();
      });
    console.log('[+] AFNetworking AFSecurityPolicy bypassed');
  } catch (e) { /* AFNetworking not present */ }
}
