package com.swissknife.fuzz;

import burp.api.montoya.http.message.requests.HttpRequest;

/** A single mutated request to send during a fuzz run. Immutable carrier. */
public final class FuzzVariant {
    public final HttpRequest request;
    public final String paramName;
    public final String payload;

    public FuzzVariant(HttpRequest request, String paramName, String payload) {
        this.request = request;
        this.paramName = paramName;
        this.payload = payload;
    }
}
