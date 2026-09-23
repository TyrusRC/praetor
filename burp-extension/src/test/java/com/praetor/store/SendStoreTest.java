package com.praetor.store;

import burp.api.montoya.http.message.HttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cover for {@link SendStore} — the store that makes a direct send (one that
 * never entered Burp's proxy history) citable under a send_ref handle.
 *
 * Montoya is a `provided` API with no mocking framework on the test path, so
 * each stored HttpRequestResponse is a JDK dynamic proxy: SendStore only ever
 * holds the reference (identity), never calls a method on it, so a no-op proxy
 * is a faithful stand-in and every instance is distinct.
 */
class SendStoreTest {

    private static HttpRequestResponse stub() {
        return (HttpRequestResponse) Proxy.newProxyInstance(
            HttpRequestResponse.class.getClassLoader(),
            new Class[]{HttpRequestResponse.class},
            (p, m, a) -> null);
    }

    @Test
    void storeReturnsMonotonicHandleAndRoundTrips() {
        SendStore store = new SendStore(10);
        HttpRequestResponse a = stub();
        HttpRequestResponse b = stub();

        String idA = store.store(a);
        String idB = store.store(b);

        assertTrue(idA.startsWith("send-"), "handle must be send-<n>");
        assertNotEquals(idA, idB, "handles must be unique");
        assertSame(a, store.get(idA), "get must return the exact instance stored");
        assertSame(b, store.get(idB));
        assertEquals(2, store.size());
    }

    @Test
    void unknownHandleReturnsNull() {
        SendStore store = new SendStore(10);
        assertNull(store.get("send-999"), "unknown handle -> null");
        assertNull(store.get(null), "null handle -> null, no NPE");
    }

    @Test
    void evictsOldestBeyondCap() {
        SendStore store = new SendStore(3);
        String id1 = store.store(stub());
        String id2 = store.store(stub());
        String id3 = store.store(stub());
        assertEquals(3, store.size());

        // Fourth store pushes the store over the cap -> oldest (id1) evicted.
        String id4 = store.store(stub());
        assertEquals(3, store.size(), "size must stay bounded at the cap");
        assertNull(store.get(id1), "oldest handle must be evicted");
        assertNotNull(store.get(id2), "second-oldest must survive");
        assertNotNull(store.get(id3));
        assertNotNull(store.get(id4), "newest must be present");
    }

    @Test
    void singletonIsShared() {
        assertSame(SendStore.get(), SendStore.get());
    }
}
