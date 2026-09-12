package com.praetor.fuzz;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.praetor.util.JsonUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates the request variants that drive a fuzz run.
 *
 * Four Intruder-style attack types:
 * <ul>
 *   <li>sniper — one param at a time, each payload</li>
 *   <li>battering_ram — same payload in every param at once</li>
 *   <li>pitchfork — payload[i] in param[i] (lockstep)</li>
 *   <li>cluster_bomb — cartesian product of payloads</li>
 * </ul>
 *
 * Mutates the base request via {@link #RequestMutator.modifyRequest(HttpRequest, String, String, String)}
 * which dispatches by position (query / body / header / path / cookie).
 */
public final class VariantBuilder {

    private final int maxRequests;

    public VariantBuilder(int maxRequests) {
        this.maxRequests = maxRequests;
    }

    public List<FuzzVariant> generate(HttpRequest baseRequest,
                                      List<Map<String, Object>> parameters,
                                      String attackType) {
        List<FuzzVariant> variants = new ArrayList<>();
        switch (attackType) {
            case "battering_ram" -> generateBatteringRam(baseRequest, parameters, variants);
            case "pitchfork" -> generatePitchfork(baseRequest, parameters, variants);
            case "cluster_bomb" -> generateClusterBomb(baseRequest, parameters, variants);
            default -> generateSniper(baseRequest, parameters, variants);
        }
        return variants;
    }

    /** Sniper: one parameter at a time, each payload. */
    private void generateSniper(HttpRequest baseRequest,
                                List<Map<String, Object>> parameters,
                                List<FuzzVariant> variants) {
        for (Map<String, Object> param : parameters) {
            String name = (String) param.get("name");
            String position = (String) param.getOrDefault("position", "query");
            @SuppressWarnings("unchecked")
            List<String> payloads = RequestMutator.toStringList((List<Object>) param.get("payloads"));

            for (String payload : payloads) {
                if (variants.size() >= maxRequests) return;
                HttpRequest modified = RequestMutator.modifyRequest(baseRequest, name, position, payload);
                variants.add(new FuzzVariant(modified, name, payload));
            }
        }
    }

    /** Battering ram: same payload in all parameters simultaneously. */
    private void generateBatteringRam(HttpRequest baseRequest,
                                      List<Map<String, Object>> parameters,
                                      List<FuzzVariant> variants) {
        Set<String> allPayloads = new LinkedHashSet<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = RequestMutator.toStringList((List<Object>) param.get("payloads"));
            allPayloads.addAll(payloads);
        }

        for (String payload : allPayloads) {
            if (variants.size() >= maxRequests) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            for (Map<String, Object> param : parameters) {
                String name = (String) param.get("name");
                String position = (String) param.getOrDefault("position", "query");
                modified = RequestMutator.modifyRequest(modified, name, position, payload);
                if (paramNames.length() > 0) paramNames.append(",");
                paramNames.append(name);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payload));
        }
    }

    /** Pitchfork: parallel payload lists (payload[i] in param[i]). */
    private void generatePitchfork(HttpRequest baseRequest,
                                   List<Map<String, Object>> parameters,
                                   List<FuzzVariant> variants) {
        int minLen = Integer.MAX_VALUE;
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = RequestMutator.toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
            minLen = Math.min(minLen, payloads.size());
        }
        if (minLen == 0 || minLen == Integer.MAX_VALUE) return;

        for (int i = 0; i < minLen; i++) {
            if (variants.size() >= maxRequests) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();
            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(i);
                modified = RequestMutator.modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));
        }
    }

    /** Cluster bomb: all combinations of all payloads across all parameters. */
    private void generateClusterBomb(HttpRequest baseRequest,
                                     List<Map<String, Object>> parameters,
                                     List<FuzzVariant> variants) {
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = RequestMutator.toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
        }

        int[] indices = new int[parameters.size()];
        long totalCombinationsLong = 1;
        for (List<String> payloads : allPayloads) {
            if (payloads.isEmpty()) return;
            totalCombinationsLong *= payloads.size();
            if (totalCombinationsLong > maxRequests) { totalCombinationsLong = maxRequests; break; }
        }
        int totalCombinations = (int) totalCombinationsLong;

        for (int combo = 0; combo < totalCombinations; combo++) {
            if (variants.size() >= maxRequests) return;

            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();

            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(indices[p]);
                modified = RequestMutator.modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));

            // Odometer increment.
            for (int p = parameters.size() - 1; p >= 0; p--) {
                indices[p]++;
                if (indices[p] < allPayloads.get(p).size()) break;
                indices[p] = 0;
            }
        }
    }

    // ── Request modification ──────────────────────────────────

}
