package com.swissknife.fuzz;

import java.util.List;
import java.util.Map;

/** Outcome of executing a single FuzzVariant. */
public final class FuzzResult {
    public int payloadIndex;
    public String parameter;
    public String payload;
    public int statusCode;
    public int responseLength;
    public long responseTimeMs;
    public Map<String, Integer> grepMatches;
    public String grepExtracted;
    public List<String> anomalies;
    public String responseSnippet;
}
