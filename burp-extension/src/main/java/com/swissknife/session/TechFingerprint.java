package com.swissknife.session;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight server/framework detection from response headers + body markers.
 * Lifted verbatim from SessionHandler.detectTechFromResponse — shared by
 * BatchProbeHandler, AttackSurfaceDiscovery, and AutoProbeOrchestrator.
 */
public final class TechFingerprint {

    private TechFingerprint() { }

    public static List<String> detectFromResponse(HttpRequestResponse result) {
        List<String> techs = new ArrayList<>();
        if (result == null || result.response() == null) return techs;
        HttpResponse resp = result.response();

        for (HttpHeader h : resp.headers()) {
            String n = h.name().toLowerCase(), v = h.value().toLowerCase();
            if ("server".equals(n)) {
                if (v.contains("iis")) techs.add("IIS");
                else if (v.contains("apache")) techs.add("Apache");
                else if (v.contains("nginx")) techs.add("Nginx");
                if (v.contains("tomcat")) techs.add("Tomcat");
            }
            if ("x-powered-by".equals(n)) {
                if (v.contains("asp")) techs.add("ASP.NET");
                else if (v.contains("php")) techs.add("PHP");
                else if (v.contains("express")) techs.add("Express");
                else if (v.contains("jsp")) techs.add("Java");
            }
        }

        String body = resp.bodyToString().toLowerCase();
        if (body.contains("ng-app") || body.contains("ng-controller")) techs.add("AngularJS");
        if (body.contains("__next")) techs.add("Next.js");
        if (body.contains("wp-content")) techs.add("WordPress");
        if (body.contains("laravel")) techs.add("Laravel");
        if (body.contains("django")) techs.add("Django");
        if (body.contains("flask")) techs.add("Flask");
        if (body.contains("spring")) techs.add("Spring");
        if (body.contains("rubyonrails") || body.contains("rails")) techs.add("Rails");

        return techs;
    }
}
