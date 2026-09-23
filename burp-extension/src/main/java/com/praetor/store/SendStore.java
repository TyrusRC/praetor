package com.praetor.store;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory store for direct HTTP sends that never entered Burp's proxy history.
 *
 * <p>A "direct" send — request smuggling (CL.TE / TE.CL), an absolute-target
 * routing-SSRF, or a pinned HTTP version — leaves Burp via {@code api.http()}
 * or a raw socket, so {@code api.proxy().history()} never records it and there
 * is no {@code proxy_history_index} to cite. Praetor can only read proxy
 * history, so before this store those sends could never back a finding. Each
 * such send is captured here under a monotonic {@code send-<n>} handle that the
 * save-finding evidence gate accepts alongside {@code proxy_history_index} /
 * {@code collaborator_interaction_id}.
 *
 * <p>Bounded: keeps the most recent {@link #MAX_ENTRIES} sends and evicts the
 * oldest, so a long engagement can't grow it without limit. Direct sends are
 * low-frequency (a handful per attack chain), so the ceiling is generous and
 * eviction is FIFO. NOTE: evidence for a very old direct send can be evicted —
 * cite it (save_finding) before firing hundreds more direct sends, or re-send
 * to mint a fresh handle.
 *
 * <p>Thread-safe: the map is a {@link ConcurrentHashMap} (lock-free reads) and
 * {@link #store} is {@code synchronized} to keep the id queue and the map
 * consistent during eviction.
 */
public final class SendStore {

    /** FIFO ceiling. Oldest handles beyond this are evicted on the next store. */
    public static final int MAX_ENTRIES = 1000;

    private static final SendStore INSTANCE = new SendStore(MAX_ENTRIES);

    private final int maxEntries;
    private final AtomicLong counter = new AtomicLong();
    private final ConcurrentHashMap<String, HttpRequestResponse> entries = new ConcurrentHashMap<>();
    private final Deque<String> order = new ConcurrentLinkedDeque<>();

    /** Package-private for tests that need an isolated instance with a small cap. */
    SendStore(int maxEntries) {
        this.maxEntries = maxEntries;
    }

    public static SendStore get() {
        return INSTANCE;
    }

    /**
     * Capture a direct send and return its {@code send-<n>} handle. Evicts the
     * oldest entries once the store exceeds the cap.
     */
    public synchronized String store(HttpRequestResponse rr) {
        String id = "send-" + counter.incrementAndGet();
        entries.put(id, rr);
        order.addLast(id);
        while (order.size() > maxEntries) {
            String evict = order.pollFirst();
            if (evict != null) entries.remove(evict);
        }
        return id;
    }

    /** The stored send for {@code id}, or null if unknown or evicted. */
    public HttpRequestResponse get(String id) {
        return id == null ? null : entries.get(id);
    }

    /** Live entry count (never exceeds {@link #MAX_ENTRIES}). */
    public int size() {
        return entries.size();
    }
}
