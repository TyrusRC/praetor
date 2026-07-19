package com.praetor.store;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class FindingsStoreTest {

    @Test
    void newFindingDefaultsToOpenStatus() {
        FindingsStore s = new FindingsStore();
        Map<String, Object> f = s.add("t", "d", "LOW", "http://x/", "e");
        assertEquals("open", f.get("status"));
    }

    @Test
    void setStatusMutatesAndReturnsFinding() {
        FindingsStore s = new FindingsStore();
        Map<String, Object> f = s.add("t", "d", "LOW", "http://x/", "e");
        String id = String.valueOf(f.get("id"));
        Map<String, Object> updated = s.setStatus(id, "reopened");
        assertNotNull(updated);
        assertEquals("reopened", updated.get("status"));
        assertNull(s.setStatus("999999", "fixed"), "unknown id -> null");
    }

    @Test
    void jsonRoundTripPreservesFindingsStatusAndIdCounter() {
        FindingsStore s = new FindingsStore();
        s.add("a", "d", "HIGH", "http://x/a", "e1");
        Map<String, Object> b = s.add("b", "d", "LOW", "http://x/b", "e2");
        s.setStatus(String.valueOf(b.get("id")), "fixed");
        String json = s.exportJson();

        FindingsStore restored = new FindingsStore();
        restored.loadFromJson(json);
        assertEquals(2, restored.getAll(null).size());
        assertEquals("fixed", restored.getAll(null).get(1).get("status"));
        // idCounter must continue past the restored max so new ids don't collide
        Map<String, Object> c = restored.add("c", "d", "LOW", "http://x/c", "e3");
        assertEquals(3, ((Number) c.get("id")).intValue());
    }

    @Test
    void changeListenerFiresOnAddAndSetStatus() {
        FindingsStore s = new FindingsStore();
        AtomicInteger calls = new AtomicInteger(0);
        s.setChangeListener(calls::incrementAndGet);
        Map<String, Object> f = s.add("t", "d", "LOW", "http://x/", "e");
        s.setStatus(String.valueOf(f.get("id")), "confirmed");
        assertTrue(s.removeById(String.valueOf(f.get("id"))));
        assertEquals(3, calls.get(), "add + setStatus + remove each notify once");
    }
}
