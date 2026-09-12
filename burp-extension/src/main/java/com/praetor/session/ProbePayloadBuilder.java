package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

/** Resolves a probe's payload (template + variables + Collaborator token) and allocates an
 *  OAST payload when needed. Split out of AutoProbeOrchestrator. `skip` true = do not send. */
final class ProbePayloadBuilder {

    private ProbePayloadBuilder() {}

    record Prepared(String payload, String oobPayloadId, List<Map<String, Object>> probeMatchers, boolean skip) {}

    static Prepared prepare(String payloadTemplate, String baselineValue, Map<String, Object> probe,
                            List<Map<String, Object>> contextMatchers, MontoyaApi api, String parameter) {
                            Map<String, Object> variables = (Map<String, Object>) probe.getOrDefault("variables", Map.of());

                            // Reference-only probes document a manual-review class.
                            // Their "payload" is prose for the operator, not something
                            // to send — firing it puts junk traffic on the target,
                            // scores against nothing, and still marks the tuple
                            // covered. Skip before the request is built.
                            if (AutoProbeOrchestrator.isReferenceOnly(variables)) return new Prepared(null, null, null, true);

                            long markerSeq = AutoProbeOrchestrator.PROBE_MARKER_SEQ.incrementAndGet();
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
                            List<Map<String, Object>> probeMatchers = AutoProbeOrchestrator.resolveMatchers(probe, contextMatchers);
                            boolean hasBracedToken = payload.contains("{{collaborator}}");
                            boolean hasBareToken = AutoProbeOrchestrator.BARE_COLLABORATOR.matcher(payload).find();
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
                                        if (hasBareToken) payload = AutoProbeOrchestrator.BARE_COLLABORATOR.matcher(payload).replaceAll(Matcher.quoteReplacement(oobHost));
                                    } catch (Throwable t) {
                                        api.logging().logToOutput(
                                            "[auto-probe] Collaborator payload allocation failed: "
                                            + t.getClass().getSimpleName() + ": " + t.getMessage()
                                            + " — skipping probe (param=" + parameter + ")");
                                        return new Prepared(null, null, null, true);
                                    }
                                } else {
                                    return new Prepared(null, null, null, true);
                                }
                            }

        return new Prepared(payload, oobPayloadId, probeMatchers, false);
    }
}
