package com.swissknife.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.handlers.MatchReplaceHandler;
import com.swissknife.util.PatternCache;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Applies operator-defined match-and-replace rules to live traffic.
 *
 * Rules live in {@link MatchReplaceHandler}; this hook reads the unmodifiable
 * snapshot per request so updates from {@code POST /api/match-replace/add} or
 * {@code DELETE /api/match-replace/{id}} take effect immediately without
 * re-registering the handler.
 *
 * Rule type semantics:
 * <ul>
 *   <li>{@code request} / {@code REQUEST_BODY} — regex over request body</li>
 *   <li>{@code REQUEST_HEADER} — regex over each request header value</li>
 *   <li>{@code response} / {@code RESPONSE_BODY} — regex over response body</li>
 *   <li>{@code RESPONSE_HEADER} — regex over each response header value</li>
 * </ul>
 *
 * Scope filter: {@code in_scope} skips out-of-scope traffic; {@code all}
 * applies to every request.
 */
public final class MatchReplaceHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final MatchReplaceHandler rulesProvider;

    public MatchReplaceHttpHandler(MontoyaApi api, MatchReplaceHandler rulesProvider) {
        this.api = api;
        this.rulesProvider = rulesProvider;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        List<MatchReplaceHandler.MatchReplaceRule> rules = rulesProvider.getMatchReplaceRules();
        if (rules.isEmpty()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        HttpRequest request = requestToBeSent;
        String requestUrl = request.url();

        for (MatchReplaceHandler.MatchReplaceRule rule : rules) {
            if (!rule.enabled) continue;
            if (!isRequestRule(rule.type)) continue;
            if (!scopeMatches(rule.scope, requestUrl)) continue;

            Pattern pattern;
            try {
                pattern = PatternCache.get(rule.match);
            } catch (Exception e) {
                continue;
            }

            if ("REQUEST_HEADER".equals(rule.type)) {
                request = applyHeaderReplace(request, pattern, rule.replace);
            } else {
                // REQUEST or REQUEST_BODY → body regex replace
                String body = request.bodyToString();
                if (body == null || body.isEmpty()) continue;
                Matcher m = pattern.matcher(body);
                if (m.find()) {
                    String replaced = m.replaceAll(Matcher.quoteReplacement(rule.replace));
                    if (!replaced.equals(body)) {
                        request = request.withBody(replaced);
                    }
                }
            }
        }

        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        List<MatchReplaceHandler.MatchReplaceRule> rules = rulesProvider.getMatchReplaceRules();
        if (rules.isEmpty()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpResponse response = responseReceived;
        // Use the initiating request's URL for scope matching. Falls back to
        // empty string when unavailable, which still works for "all" scope.
        String requestUrl = "";
        try {
            HttpRequest init = responseReceived.initiatingRequest();
            if (init != null) requestUrl = init.url();
        } catch (Exception ignored) {}

        for (MatchReplaceHandler.MatchReplaceRule rule : rules) {
            if (!rule.enabled) continue;
            if (!isResponseRule(rule.type)) continue;
            if (!scopeMatches(rule.scope, requestUrl)) continue;

            Pattern pattern;
            try {
                pattern = PatternCache.get(rule.match);
            } catch (Exception e) {
                continue;
            }

            if ("RESPONSE_HEADER".equals(rule.type)) {
                response = applyHeaderReplaceResponse(response, pattern, rule.replace);
            } else {
                String body = response.bodyToString();
                if (body == null || body.isEmpty()) continue;
                Matcher m = pattern.matcher(body);
                if (m.find()) {
                    String replaced = m.replaceAll(Matcher.quoteReplacement(rule.replace));
                    if (!replaced.equals(body)) {
                        response = response.withBody(replaced);
                    }
                }
            }
        }

        return ResponseReceivedAction.continueWith(response);
    }

    private static boolean isRequestRule(String type) {
        return "request".equals(type) || "REQUEST_HEADER".equals(type) || "REQUEST_BODY".equals(type);
    }

    private static boolean isResponseRule(String type) {
        return "response".equals(type) || "RESPONSE_HEADER".equals(type) || "RESPONSE_BODY".equals(type);
    }

    private boolean scopeMatches(String scope, String url) {
        if (scope == null || "all".equals(scope)) return true;
        if ("in_scope".equals(scope)) {
            try { return api.scope().isInScope(url); }
            catch (Exception e) { return false; }
        }
        return true;
    }

    private static HttpRequest applyHeaderReplace(HttpRequest request, Pattern pattern, String replacement) {
        HttpRequest out = request;
        for (var h : request.headers()) {
            String value = h.value();
            Matcher m = pattern.matcher(value);
            if (m.find()) {
                String replaced = m.replaceAll(Matcher.quoteReplacement(replacement));
                if (!replaced.equals(value)) {
                    out = out.withHeader(h.name(), replaced);
                }
            }
        }
        return out;
    }

    private static HttpResponse applyHeaderReplaceResponse(HttpResponse response, Pattern pattern, String replacement) {
        HttpResponse out = response;
        for (var h : response.headers()) {
            String value = h.value();
            Matcher m = pattern.matcher(value);
            if (m.find()) {
                String replaced = m.replaceAll(Matcher.quoteReplacement(replacement));
                if (!replaced.equals(value)) {
                    out = out.withUpdatedHeader(h.name(), replaced);
                }
            }
        }
        return out;
    }
}
