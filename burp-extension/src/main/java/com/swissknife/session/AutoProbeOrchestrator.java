package com.swissknife.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.swissknife.handlers.Session;
import com.swissknife.http.HttpExchange;
import static com.swissknife.http.HttpResponses.sendJson;
import static com.swissknife.http.HttpResponses.sendError;
import com.swissknife.store.FindingsStore;
import com.swissknife.store.SessionStore;
import com.swissknife.ui.ConfigTab;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles {@code POST /api/session/auto-probe}: knowledge-base-driven
 * parameter probing with Collaborator integration, anomaly scoring,
 * confidence calibration, and Proxy-history highlighting.
 *
 * Behaviour-preserving lift from SessionHandler.handleAutoProbe (~400 lines).
 */
public final class AutoProbeOrchestrator {

    /** Monotonic counter shared with SessionProbeHelpers so probe markers
     *  stay unique even within the same millisecond. */
    private static final AtomicLong PROBE_MARKER_SEQ = com.swissknife.analysis.SessionProbeHelpers.PROBE_MARKER_SEQ;

    /** Bare {@code COLLABORATOR} placeholder (no braces). Matched as a whole word
     *  so substrings inside identifiers are untouched. {@code {{collaborator}}}
     *  is the canonical token; the bare form is kept for KBs authored before the
     *  canonical form existed. */
    private static final Pattern BARE_COLLABORATOR = Pattern.compile("(?<!\\{)\\bCOLLABORATOR\\b(?!\\})");

    private static final Map<String, String> CWE_MAP = Map.of(
        "sqli", "CWE-89",
        "xss", "CWE-79",
        "path_traversal", "CWE-22",
        "ssti", "CWE-1336",
        "command_injection", "CWE-78",
        "ssrf", "CWE-918",
        "xxe", "CWE-611",
        "idor", "CWE-639",
        "info_disclosure", "CWE-200"
    );

    private final MontoyaApi api;
    private final SessionRequestExecutor executor;
    private final FindingsStore findingsStore;

    public AutoProbeOrchestrator(MontoyaApi api, SessionRequestExecutor executor, FindingsStore findingsStore) {
        this.api = api;
        this.executor = executor;
        this.findingsStore = findingsStore;
    }

    @SuppressWarnings("unchecked")
    public void handle(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = store.getSession(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found"); return; }

        List<Map<String, Object>> targets = (List<Map<String, Object>>) body.get("targets");
        List<Map<String, Object>> knowledgeBase = (List<Map<String, Object>>) body.get("knowledge");
        int maxProbes = body.containsKey("max_probes_per_param")
            ? ((Number) body.get("max_probes_per_param")).intValue() : 20;

        if (targets == null || targets.isEmpty()) { sendError(exchange, 400, "Missing 'targets'"); return; }
        if (knowledgeBase == null || knowledgeBase.isEmpty()) { sendError(exchange, 400, "Missing 'knowledge'"); return; }

        synchronized (session) {
            List<Map<String, Object>> findings = new ArrayList<>();
            Set<String> seenFindingKeys = new HashSet<>();
            int totalProbes = 0;

            for (Map<String, Object> target : targets) {
                String method = (String) target.getOrDefault("method", "GET");
                String path = (String) target.get("path");
                String parameter = (String) target.get("parameter");
                String baselineValue = (String) target.getOrDefault("baseline_value", "1");
                String location = (String) target.getOrDefault("location", "query");

                Map<String, Object> baseParams = new LinkedHashMap<>();
                baseParams.put("method", method);
                baseParams.put("path", ProbeHelpers.injectParam(path, parameter, baselineValue, location));
                if ("body".equals(location)) baseParams.put("data", parameter + "=" + baselineValue);

                long baselineStartMs = System.nanoTime();
                HttpRequestResponse baselineResult = executor.send(session, baseParams);
                long baselineElapsedMs = (System.nanoTime() - baselineStartMs) / 1_000_000;
                if (baselineResult == null || baselineResult.response() == null) continue;
                executor.updateCookiesFromResponse(session, baselineResult);

                List<String> detectedTech = TechFingerprint.detectFromResponse(baselineResult);

                int probesRun = 0;
                for (Map<String, Object> kb : knowledgeBase) {
                    if (probesRun >= maxProbes) break;
                    String category = (String) kb.get("category");
                    Map<String, Object> contexts = (Map<String, Object>) kb.get("contexts");
                    if (contexts == null) continue;

                    for (Map.Entry<String, Object> ctxEntry : contexts.entrySet()) {
                        if (probesRun >= maxProbes) break;
                        String contextName = ctxEntry.getKey();
                        Map<String, Object> context = (Map<String, Object>) ctxEntry.getValue();

                        List<String> techMatch = (List<String>) context.getOrDefault("tech_match", List.of());
                        if (!techMatch.isEmpty() && detectedTech.stream().noneMatch(techMatch::contains)) continue;

                        List<String> paramMatch = (List<String>) context.getOrDefault("param_match", List.of());
                        if (!paramMatch.isEmpty() && !ProbeHelpers.paramMatcherHits(parameter, paramMatch)) continue;

                        List<Map<String, Object>> probes = (List<Map<String, Object>>) context.getOrDefault("probes", List.of());
                        for (Map<String, Object> probe : probes) {
                            if (probesRun >= maxProbes) break;

                            String payloadTemplate = (String) probe.get("payload");
                            Map<String, Object> variables = (Map<String, Object>) probe.getOrDefault("variables", Map.of());

                            long markerSeq = PROBE_MARKER_SEQ.incrementAndGet();
                            String marker = "probe_" + Long.toString(System.currentTimeMillis(), 36) + "_" + Long.toString(markerSeq, 36);
                            String payload = payloadTemplate
                                .replace("{{baseline}}", baselineValue)
                                .replace("{{marker}}", marker)
                                .replace("{{sleep}}", String.valueOf(
                                    variables.getOrDefault("sleep", variables.getOrDefault("sleep_seconds", "5"))));
                            for (Map.Entry<String, Object> v : variables.entrySet()) {
                                payload = payload.replace("{{" + v.getKey() + "}}", String.valueOf(v.getValue()));
                            }

                            String oobPayloadId = null;
                            String oobHost = null;
                            List<Map<String, Object>> probeMatchers = (List<Map<String, Object>>) probe.get("matchers");
                            boolean hasBracedToken = payload.contains("{{collaborator}}");
                            boolean hasBareToken = BARE_COLLABORATOR.matcher(payload).find();
                            boolean needsCollaborator = hasBracedToken || hasBareToken;
                            if (!needsCollaborator && probeMatchers != null) {
                                for (Map<String, Object> mt : probeMatchers) {
                                    if ("collaborator".equals(mt.get("type"))) { needsCollaborator = true; break; }
                                }
                            }
                            if (needsCollaborator) {
                                burp.api.montoya.collaborator.CollaboratorClient cc =
                                    com.swissknife.collaborator.CollaboratorPool.tryGetOrCreate(api);
                                if (cc != null) {
                                    try {
                                        burp.api.montoya.collaborator.CollaboratorPayload cp = cc.generatePayload();
                                        oobPayloadId = cp.id().toString();
                                        oobHost = cp.toString();
                                        if (hasBracedToken) payload = payload.replace("{{collaborator}}", oobHost);
                                        if (hasBareToken) payload = BARE_COLLABORATOR.matcher(payload).replaceAll(Matcher.quoteReplacement(oobHost));
                                    } catch (Throwable t) {
                                        api.logging().logToOutput(
                                            "[auto-probe] Collaborator payload allocation failed: "
                                            + t.getClass().getSimpleName() + ": " + t.getMessage()
                                            + " — skipping probe (param=" + parameter + ")");
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }

                            Map<String, Object> probeParams = new LinkedHashMap<>();
                            probeParams.put("method", method);
                            probeParams.put("path", ProbeHelpers.injectParam(path, parameter, payload, location));
                            if ("body".equals(location)) probeParams.put("data", parameter + "=" + payload);

                            int preHistorySize = api.proxy().history().size();
                            long startMs = System.nanoTime();
                            HttpRequestResponse probeResult = executor.send(session, probeParams);
                            long elapsedMs = (System.nanoTime() - startMs) / 1_000_000;
                            totalProbes++;
                            probesRun++;

                            if (probeResult == null || probeResult.response() == null) continue;
                            executor.updateCookiesFromResponse(session, probeResult);

                            String probeUrl = probeResult.request() != null ? probeResult.request().url() : "";

                            int postHistorySize = api.proxy().history().size();
                            int probeHistoryIndex = postHistorySize > preHistorySize ? postHistorySize - 1 : -1;

                            List<Map<String, Object>> matchers = (List<Map<String, Object>>) probe.get("matchers");

                            if (oobPayloadId != null && matchers != null) {
                                try {
                                    Thread.sleep(750);
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                }
                                burp.api.montoya.collaborator.CollaboratorClient cc =
                                    com.swissknife.collaborator.CollaboratorPool.tryGetOrCreate(api);
                                if (cc != null) {
                                    try {
                                        var filter = burp.api.montoya.collaborator.InteractionFilter
                                            .interactionPayloadFilter(oobPayloadId);
                                        var interactions = cc.getInteractions(filter);
                                        List<Map<String, Object>> simplified = new ArrayList<>();
                                        for (var ix : interactions) {
                                            Map<String, Object> entry = new LinkedHashMap<>();
                                            entry.put("type", ix.type().toString());
                                            entry.put("payload_id", ix.id().toString());
                                            simplified.add(entry);
                                        }
                                        for (Map<String, Object> mt : matchers) {
                                            if ("collaborator".equals(mt.get("type"))) {
                                                mt.put("_interactions", simplified);
                                            }
                                        }
                                    } catch (Throwable oobErr) {
                                        api.logging().logToOutput(
                                            "[auto-probe] Collaborator interaction poll failed: "
                                            + oobErr.getClass().getSimpleName() + ": " + oobErr.getMessage());
                                    }
                                }
                            }

                            Map<String, Object> matchResult = com.swissknife.analysis.MatcherEngine.evaluate(
                                matchers, probeResult.response(), elapsedMs, baselineResult.response(), payload
                            );

                            int probeStatus = probeResult.response().statusCode();
                            int probeLen = probeResult.response().body().length();
                            int baseStatus = baselineResult.response().statusCode();
                            int baseLen = baselineResult.response().body().length();

                            int anomalyScore = 0;
                            List<String> anomalies = new ArrayList<>();

                            if (probeStatus != baseStatus) {
                                int baseClass = baseStatus / 100;
                                int probeClass = probeStatus / 100;
                                if (baseClass == 2 && probeClass == 5) {
                                    anomalyScore += 20;
                                    anomalies.add("status:2xx->5xx");
                                }
                            }

                            int lenDiff = Math.abs(probeLen - baseLen);
                            int absFloor = Math.max(64, Math.min(1000, baseLen / 4));
                            if (baseLen > 0 && lenDiff > baseLen * 0.5 && lenDiff > absFloor) {
                                anomalyScore += 15;
                                anomalies.add("length:" + lenDiff + "B diff");
                            }

                            long timeDiff = elapsedMs - baselineElapsedMs;
                            if (timeDiff > 4000) {
                                anomalyScore += 20;
                                anomalies.add("timing:+" + timeDiff + "ms vs baseline");
                            }

                            boolean matcherHit = Boolean.TRUE.equals(matchResult.get("matched"));
                            int probeBoost = probe.containsKey("confidence_boost")
                                ? ((Number) probe.get("confidence_boost")).intValue() : 0;
                            int matcherBoost = ((Number) matchResult.getOrDefault("confidence_boost", 0)).intValue();
                            int rawScore = Math.min(100, probeBoost + matcherBoost + anomalyScore);

                            double confidence;
                            if (matcherHit) {
                                double base = 0.60 + (Math.min(probeBoost + matcherBoost, 100) / 250.0);
                                if (anomalyScore >= 20) base += 0.10;
                                if ((probeBoost + matcherBoost) >= 70 && anomalyScore >= 20) base = Math.max(base, 0.92);
                                confidence = Math.min(1.0, base);
                            } else if (anomalyScore >= 40 && anomalies.size() >= 2) {
                                confidence = 0.45 + Math.min(anomalyScore, 60) / 200.0;
                            } else if (anomalyScore > 0) {
                                confidence = 0.30 + anomalyScore / 500.0;
                            } else {
                                confidence = 0.20;
                            }

                            if (matcherHit) {
                                @SuppressWarnings("unchecked")
                                List<String> matched = (List<String>) matchResult.getOrDefault("matched_matchers", List.of());
                                String matcherSig = matched.isEmpty()
                                    ? "<no-matcher-tag>"
                                    : String.join(",", matched);
                                String findingKey = method + "|" + path + "|" + parameter
                                    + "|" + category + "|" + contextName + "|" + matcherSig;
                                if (!seenFindingKeys.add(findingKey)) continue;

                                String severity = (String) probe.getOrDefault("severity", "medium");
                                String description = (String) probe.getOrDefault("description", "");
                                String cwe = CWE_MAP.getOrDefault(category, "");

                                Map<String, Object> finding = new LinkedHashMap<>();
                                finding.put("parameter", parameter);
                                finding.put("endpoint", method + " " + path);
                                finding.put("category", category);
                                finding.put("context", contextName);
                                finding.put("probe", payload);
                                finding.put("status", probeStatus);
                                finding.put("score", rawScore);
                                finding.put("confidence", Math.round(confidence * 100.0) / 100.0);
                                finding.put("anomaly_score", anomalyScore);
                                finding.put("anomalies", anomalies);
                                finding.put("severity", severity);
                                finding.put("cwe", cwe);
                                finding.put("matched_matchers", matchResult.get("matched_matchers"));
                                finding.put("description", description);
                                finding.put("history_index", probeHistoryIndex);
                                finding.put("proxy_history_index", probeHistoryIndex);
                                findings.add(finding);

                                findingsStore.add(
                                    category + "/" + contextName + ": " + description,
                                    "Parameter: " + parameter + ", Payload: " + payload + ", Matchers: " + matchResult.get("matched_matchers"),
                                    severity,
                                    method + " " + path,
                                    "Status: " + probeStatus + ", Confidence: " + String.format("%.2f", confidence) + ", Score: " + rawScore + (cwe.isEmpty() ? "" : ", " + cwe)
                                );
                            } else if (anomalyScore >= 40 && anomalies.size() >= 2) {
                                String findingKey = method + "|" + path + "|" + parameter + "|" + category;
                                if (!seenFindingKeys.add(findingKey)) continue;

                                int normalizedAnomaly = Math.min(100, anomalyScore);
                                String cwe = CWE_MAP.getOrDefault(category, "");

                                Map<String, Object> finding = new LinkedHashMap<>();
                                finding.put("parameter", parameter);
                                finding.put("endpoint", method + " " + path);
                                finding.put("category", category);
                                finding.put("context", contextName);
                                finding.put("probe", payload);
                                finding.put("status", probeStatus);
                                finding.put("score", normalizedAnomaly);
                                finding.put("confidence", Math.round(confidence * 100.0) / 100.0);
                                finding.put("anomaly_score", normalizedAnomaly);
                                finding.put("anomalies", anomalies);
                                finding.put("severity", "info");
                                finding.put("cwe", cwe);
                                finding.put("matched_matchers", List.of());
                                finding.put("description", "Anomalous response (no matcher matched) — review manually");
                                finding.put("history_index", probeHistoryIndex);
                                finding.put("proxy_history_index", probeHistoryIndex);
                                findings.add(finding);

                                findingsStore.add(
                                    category + "/" + contextName + ": Anomalous response",
                                    "Parameter: " + parameter + ", Payload: " + payload + ", Anomalies: " + anomalies,
                                    "info",
                                    method + " " + path,
                                    "Status: " + probeStatus + ", Confidence: " + String.format("%.2f", confidence) + ", Anomaly score: " + normalizedAnomaly
                                );
                            }

                            com.swissknife.http.ProxyHighlight.Level level =
                                com.swissknife.http.ProxyHighlight.levelFromConfidence(confidence);
                            String note = String.format("%s/%s c=%.2f", category, contextName, confidence);
                            if (matcherHit) {
                                note += " match=" + matchResult.get("matched_matchers");
                            } else if (!anomalies.isEmpty()) {
                                note += " anomalies=" + anomalies;
                            } else {
                                note += " probe=" + (payload.length() > 30 ? payload.substring(0, 30) + "…" : payload);
                            }
                            com.swissknife.http.ProxyHighlight.tagLatest(api, probeUrl, level, note);
                        }
                    }
                }

                if (baselineResult != null && baselineResult.request() != null) {
                    com.swissknife.http.ProxyHighlight.tagLatest(
                        api, baselineResult.request().url(),
                        com.swissknife.http.ProxyHighlight.Level.BASELINE,
                        "baseline for " + parameter);
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("parameters_tested", targets.size());
            out.put("total_probes_sent", totalProbes);
            out.put("findings", findings);
            out.put("auto_saved_findings", findings.size());

            ConfigTab.log("auto-probe: " + targets.size() + " params, " + totalProbes + " probes, " + findings.size() + " findings");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

}
