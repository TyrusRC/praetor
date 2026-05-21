package com.swissknife.store;

import com.swissknife.handlers.Session;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Seed coverage for {@link SessionStore} — singleton identity, put/get/remove
 * round-trip, and the UI getSessionInfoList() shape preserved from the
 * pre-split SessionHandler.getSessionInfoList().
 */
class SessionStoreTest {

    @Test
    void singletonReturnsSameInstance() {
        assertSame(SessionStore.get(), SessionStore.get(),
            "SessionStore.get() must always return the same instance");
        assertNotNull(SessionStore.get().getSessions(),
            "Sessions map must never be null");
    }

    @Test
    void putGetRemoveRoundTrip() {
        SessionStore store = SessionStore.get();
        // Cleanup any leftover from prior tests (singleton state).
        store.removeSession("test-rt");

        Session s = new Session();
        s.name = "test-rt";
        s.baseUrl = "https://example.test";

        assertNull(store.getSession("test-rt"), "session must not exist before put");
        store.putSession("test-rt", s);
        assertSame(s, store.getSession("test-rt"), "get must return the exact instance that was put");

        Map<String, Session> map = store.getSessions();
        assertTrue(map.containsKey("test-rt"), "live map must reflect put");

        Session removed = store.removeSession("test-rt");
        assertSame(s, removed, "remove must return the removed instance");
        assertNull(store.getSession("test-rt"), "session must not exist after remove");
    }

    @Test
    void sessionInfoListShape() {
        SessionStore store = SessionStore.get();
        store.removeSession("test-info-a");
        store.removeSession("test-info-b");

        Session a = new Session();
        a.name = "test-info-a";
        a.baseUrl = "https://a.test";
        a.cookies.put("sess", "abc");
        a.cookies.put("csrf", "xyz");
        a.variables.put("token", "tk");
        store.putSession(a.name, a);

        Session b = new Session();
        b.name = "test-info-b";
        b.baseUrl = "https://b.test";
        b.bearerToken = "jwt.token.here";
        store.putSession(b.name, b);

        try {
            List<String[]> list = store.getSessionInfoList();
            // Find our two rows (other tests may have added more).
            String[] rowA = list.stream().filter(r -> "test-info-a".equals(r[0])).findFirst().orElse(null);
            String[] rowB = list.stream().filter(r -> "test-info-b".equals(r[0])).findFirst().orElse(null);

            assertNotNull(rowA, "row for test-info-a must be present");
            assertEquals(5, rowA.length, "row must have 5 columns: name, baseUrl, cookies, vars, hasAuth");
            assertEquals("https://a.test", rowA[1]);
            assertEquals("2", rowA[2], "cookie count");
            assertEquals("1", rowA[3], "variable count");
            assertEquals("No", rowA[4], "hasAuth false when no bearer/user");

            assertNotNull(rowB, "row for test-info-b must be present");
            assertEquals("Yes", rowB[4], "hasAuth true when bearer set");
        } finally {
            store.removeSession("test-info-a");
            store.removeSession("test-info-b");
        }
    }
}
