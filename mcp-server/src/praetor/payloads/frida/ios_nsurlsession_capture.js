/*
 * NSURLSession request/response capture (Praetor W9 / iOS).
 *
 * Hooks NSURLSessionDataTask resume + delegate completion to log every URL,
 * method, headers, and response body bytes. Use when SSL pin bypass is
 * already loaded and you want to inventory app's API surface without
 * driving it through Burp.
 *
 * Run: frida -U -l ios_nsurlsession_capture.js -f <bundle_id>
 */
if (ObjC.available) {
  var NSURLSession = ObjC.classes.NSURLSession;
  var NSURLSessionTask = ObjC.classes.NSURLSessionTask;

  // Hook all dataTaskWithRequest: variants — they're the entry point for
  // most NSURLSession-driven HTTP.
  NSURLSession['- dataTaskWithRequest:'].implementation = ObjC.implement(
    NSURLSession['- dataTaskWithRequest:'],
    function (self, sel, request) {
      var url = request.URL().absoluteString();
      var method = request.HTTPMethod();
      var headers = request.allHTTPHeaderFields();
      console.log('[NSURLSession.dataTask] ' + method + ' ' + url);
      if (headers) console.log('  headers: ' + headers.toString());
      var body = request.HTTPBody();
      if (body) {
        var bodyStr = ObjC.classes.NSString.alloc()
          .initWithData_encoding_(body, 4 /* NSUTF8StringEncoding */);
        if (bodyStr) console.log('  body: ' + bodyStr.toString());
      }
      return self.dataTaskWithRequest_(request);
    }
  );

  // Hook NSURLSessionTask.resume to catch tasks created via shortcut APIs.
  NSURLSessionTask['- resume'].implementation = ObjC.implement(
    NSURLSessionTask['- resume'],
    function (self, sel) {
      try {
        var req = self.currentRequest();
        if (req) {
          console.log('[NSURLSessionTask.resume] ' + req.HTTPMethod()
            + ' ' + req.URL().absoluteString());
        }
      } catch (e) {}
      return self.resume();
    }
  );

  console.log('[+] NSURLSession capture loaded');
}
