package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.store.FindingsStore;
import com.praetor.store.SessionStore;
import com.praetor.ui.ConfigTab;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
    private static final AtomicLong PROBE_MARKER_SEQ = com.praetor.analysis.SessionProbeHelpers.PROBE_MARKER_SEQ;

    /** Bare {@code COLLABORATOR} placeholder (no braces). Matched as a whole word
     *  so substrings inside identifiers are untouched. {@code {{collaborator}}}
     *  is the canonical token; the bare form is kept for KBs authored before the
     *  canonical form existed. */
    private static final Pattern BARE_COLLABORATOR = Pattern.compile("(?<!\\{)\\bCOLLABORATOR\\b(?!\\})");

    /** First non-blank value, or null. Lets a target accept either spelling. */
    private static String firstNonBlank(Object... values) {
        for (Object v : values) {
            if (v instanceof String s && !s.trim().isEmpty()) return s;
        }
        return null;
    }

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

    /**
     * Matchers that apply to one probe: its own if it declares any, otherwise
     * the context's.
     *
     * <p>Knowledge files use two shapes. The common one puts a matcher list on
     * every probe; a few declare a single list for the whole context. Only the
     * first was ever read, so probes in the second shape were sent and scored
     * against nothing — {@code auto_probe} fired the payload, reported no
     * finding, and then wrote a documented negative for a class it had not
     * actually evaluated. That is worse than skipping the class, because
     * coverage tracking suppresses the re-test.
     *
     * <p>Returns without mutating either map: the knowledge base is shared
     * across probing threads.
     */
    static List<Map<String, Object>> resolveMatchers(
            Map<String, Object> probe, List<Map<String, Object>> contextMatchers) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> own = (List<Map<String, Object>>) probe.get("matchers");
        if (own != null && !own.isEmpty()) return own;
        return contextMatchers;
    }

    /**
     * True when a probe is documentation rather than something to send.
     *
     * <p>A few knowledge contexts inside otherwise-active files describe a
     * manual-review class and set {@code variables.reference_only}. Their
     * {@code payload} is prose for the operator ("compare tool descriptions
     * across versions"), not a payload — sending it is noise on the target and
     * scores against nothing while still counting toward coverage.
     */
    static boolean isReferenceOnly(Map<String, Object> variables) {
        if (variables == null) return false;
        Object flag = variables.get("reference_only");
        if (flag instanceof Boolean b) return b;
        return flag != null && "true".equalsIgnoreCase(String.valueOf(flag));
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
            // Which (target, category) pairs actually had a probe sent. The
            // budget below truncates mid-knowledge-base, so "the categories we
            // loaded" and "the categories we tested" are different sets. Only
            // this one may be recorded as coverage; reporting the loaded set
            // marked ~135 classes tested after ~2 ran, and the skip-already-
            // covered default then made those classes unreachable for good.
            List<Map<String, Object>> probedCategories = new ArrayList<>();

            for (Map<String, Object> target : targets) {
                String method = (String) target.getOrDefault("method", "GET");
                // Accept `url` for `path` and `param` for `parameter`: both are
                // natural spellings, and a caller who used them previously got
                // a NullPointerException from deep inside injectParam rather
                // than a message naming the key it wanted.
                String path = firstNonBlank(target.get("path"), target.get("url"));
                String parameter = firstNonBlank(target.get("parameter"), target.get("param"));
                if (path == null) {
                    sendError(exchange, 400,
                        "each target needs a 'path' (or 'url'); got keys " + target.keySet()
                        + ". Example: {\"path\":\"/x.asp?id=1\",\"parameter\":\"id\",\"method\":\"GET\"}");
                    return;
                }
                if (parameter == null) parameter = "";
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
                Set<String> catsProbed = new LinkedHashSet<>();
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
                        // Context-level matcher fallback. Most knowledge files put
                        // matchers on each probe, but some declare one matcher set
                        // for the whole context. Reading probe.matchers only meant
                        // those probes were SENT and could never MATCH — the payload
                        // went out, the finding never came back, and auto_probe then
                        // recorded a documented negative for a class it never
                        // actually evaluated. Resolved per probe below; the KB map is
                        // shared across probing threads and must not be mutated.
                        List<Map<String, Object>> contextMatchers =
                            (List<Map<String, Object>>) context.get("matchers");
                        for (Map<String, Object> probe : probes) {
                            if (probesRun >= maxProbes) break;

                            String payloadTemplate = (String) probe.get("payload");
                            Map<String, Object> variables = (Map<String, Object>) probe.getOrDefault("variables", Map.of());

                            // Reference-only probes document a manual-review class.
                            // Their "payload" is prose for the operator, not something
                            // to send — firing it puts junk traffic on the target,
                            // scores against nothing, and still marks the tuple
                            // covered. Skip before the request is built.
                            if (isReferenceOnly(variables)) continue;

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
                            List<Map<String, Object>> probeMatchers = resolveMatchers(probe, contextMatchers);
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
                                    com.praetor.collaborator.CollaboratorPool.tryGetOrCreate(api);
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
                            if (category != null) catsProbed.add(category);

                            if (probeResult == null || probeResult.response() == null) continue;
                            executor.updateCookiesFromResponse(session, probeResult);

                            String probeUrl = probeResult.request() != null ? probeResult.request().url() : "";

                            int postHistorySize = api.proxy().history().size();
                            int probeHistoryIndex = postHistorySize > preHistorySize ? postHistorySize - 1 : -1;

                            List<Map<String, Object>> matchers = probeMatchers;

                            if (oobPayloadId != null && matchers != null) {
                                try {
                                    Thread.sleep(750);
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                }
                                burp.api.montoya.collaborator.CollaboratorClient cc =
                                    com.praetor.collaborator.CollaboratorPool.tryGetOrCreate(api);
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

                            Map<String, Object> matchResult = com.praetor.analysis.MatcherEngine.evaluate(
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

                            com.praetor.http.ProxyHighlight.Level level =
                                com.praetor.http.ProxyHighlight.levelFromConfidence(confidence);
                            String note = String.format("%s/%s c=%.2f", category, contextName, confidence);
                            if (matcherHit) {
                                note += " match=" + matchResult.get("matched_matchers");
                            } else if (!anomalies.isEmpty()) {
                                note += " anomalies=" + anomalies;
                            } else {
                                note += " probe=" + (payload.length() > 30 ? payload.substring(0, 30) + "…" : payload);
                            }
                            com.praetor.http.ProxyHighlight.tagLatest(api, probeUrl, level, note);
                        }
                    }
                }

                if (baselineResult != null && baselineResult.request() != null) {
                    com.praetor.http.ProxyHighlight.tagLatest(
                        api, baselineResult.request().url(),
                        com.praetor.http.ProxyHighlight.Level.BASELINE,
                        "baseline for " + parameter);
                }

                // Report exactly what was probed for this target, and say
                // whether the budget cut the knowledge base short. `truncated`
                // is what stops the caller recording a clean bill of coverage
                // for classes the budget never reached.
                Map<String, Object> covered = new LinkedHashMap<>();
                covered.put("path", path);
                covered.put("parameter", parameter == null ? "" : parameter);
                covered.put("categories", new ArrayList<>(catsProbed));
                covered.put("probes_sent", probesRun);
                covered.put("truncated", probesRun >= maxProbes);
                probedCategories.add(covered);
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("parameters_tested", targets.size());
            out.put("total_probes_sent", totalProbes);
            out.put("probed_categories", probedCategories);
            out.put("findings", findings);
            out.put("auto_saved_findings", findings.size());

            ConfigTab.log("auto-probe: " + targets.size() + " params, " + totalProbes + " probes, " + findings.size() + " findings");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

}
