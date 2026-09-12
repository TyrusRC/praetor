package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.store.FindingsStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Scores a probe response vs baseline and records confirmed/anomalous findings + Burp
 *  highlight tags. Split out of AutoProbeOrchestrator so the handler stays under the
 *  line ceiling; logic is identical to the inline block. */
final class ProbeFindingRecorder {

    private ProbeFindingRecorder() {}

    static void record(List<Map<String, Object>> matchers, HttpResponse probeResp, HttpResponse baselineResp,
                       long elapsedMs, long baselineElapsedMs, Map<String, Object> probe, String payload,
                       String method, String path, String parameter, String category, String contextName,
                       int probeHistoryIndex, String probeUrl, MontoyaApi api, FindingsStore findingsStore,
                       List<Map<String, Object>> findings, Set<String> seenFindingKeys) {
                            String matchersCondition = String.valueOf(
                                probe.getOrDefault("matchers_condition", "and"));
                            Map<String, Object> matchResult = com.praetor.analysis.MatcherEngine.evaluate(
                                matchers, probeResp, elapsedMs, baselineResp,
                                payload, matchersCondition
                            );

                            int probeStatus = probeResp.statusCode();
                            int probeLen = probeResp.body().length();
                            int baseStatus = baselineResp.statusCode();
                            int baseLen = baselineResp.body().length();

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
                                if (!seenFindingKeys.add(findingKey)) return;

                                String severity = (String) probe.getOrDefault("severity", "medium");
                                String description = (String) probe.getOrDefault("description", "");
                                String cwe = AutoProbeOrchestrator.CWE_MAP.getOrDefault(category, "");

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
                                if (!seenFindingKeys.add(findingKey)) return;

                                int normalizedAnomaly = Math.min(100, anomalyScore);
                                String cwe = AutoProbeOrchestrator.CWE_MAP.getOrDefault(category, "");

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

    static void pollCollaborator(String oobPayloadId, List<Map<String, Object>> matchers,
                                burp.api.montoya.MontoyaApi api) {
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

    }
}
