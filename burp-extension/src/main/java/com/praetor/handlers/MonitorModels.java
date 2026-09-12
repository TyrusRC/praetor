package com.praetor.handlers;

import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

// Traffic-monitor model classes, split out of TrafficMonitorHandler.

    final class MonitorHit {
        final int index;
        final String matchedText;
        final long timestamp;

        MonitorHit(int index, String matchedText, long timestamp) {
            this.index = index;
            this.matchedText = matchedText;
            this.timestamp = timestamp;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", index);
            m.put("matched_text", matchedText);
            m.put("timestamp", timestamp);
            return m;
        }
    }

    final class MonitorRule {
        /** Cap on retained hits per rule. Long sessions with chatty regex used
         *  to grow into hundreds of MB; truncate the oldest once we hit the
         *  cap and surface a {@code truncated} flag in the response. */
        static final int MAX_HITS = 2000;

        final String tag;
        final List<MonitorPattern> patterns;
        final CopyOnWriteArrayList<MonitorHit> hits = new CopyOnWriteArrayList<>();
        volatile int lastCheckedIndex;
        volatile boolean hitsTruncated;

        MonitorRule(String tag, List<MonitorPattern> patterns) {
            this.tag = tag;
            this.patterns = patterns;
            this.lastCheckedIndex = -1;
            this.hitsTruncated = false;
        }

        void appendHit(MonitorHit hit) {
            hits.add(hit);
            // Drop oldest entries beyond the cap. CopyOnWriteArrayList.remove(0)
            // is O(n) on copy but only fires once we cross the threshold and
            // the cap is bounded, so amortised cost stays low.
            while (hits.size() > MAX_HITS) {
                hits.remove(0);
                hitsTruncated = true;
            }
        }
    }

    final class MonitorPattern {
        final String location; // "url", "request_body", "response_body", "request_header", "response_header"
        final Pattern regex;

        MonitorPattern(String location, Pattern regex) {
            this.location = location;
            this.regex = regex;
        }
    }
