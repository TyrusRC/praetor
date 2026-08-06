package com.praetor.session;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The crawl signature collapses value-variants of one endpoint so a forum's
 * showforum.asp?id=0,1,2… flood and the Templatize.asp self-recursion trap
 * cannot starve the page budget before Login/Register/Search are reached.
 * A live crawl against acuforum returned forms:0 for exactly that reason.
 */
public class AttackSurfaceCrawlDedupTest {

    private final AttackSurfaceDiscovery d = new AttackSurfaceDiscovery(null, null);

    @Test
    public void valueVariantsOfOneEndpointShareASignature() {
        assertEquals(d.pathSignature("/showforum.asp?id=0"),
                     d.pathSignature("/showforum.asp?id=2"));
        assertEquals(d.pathSignature("/showforum.asp?id=0"),
                     d.pathSignature("/showforum.asp?id=999"));
    }

    @Test
    public void templatizeSelfRecursionCollapsesToOneSignature() {
        String a = d.pathSignature("/Templatize.asp?item=html/about.html");
        String b = d.pathSignature("/Templatize.asp?item=html/Templatize.asp?item=html/about.html");
        assertEquals(a, b);
    }

    @Test
    public void differentParameterNamesStayDistinct() {
        assertNotEquals(d.pathSignature("/Search.asp?tfSearch=x"),
                        d.pathSignature("/Search.asp?goButton=go"));
    }

    @Test
    public void formPagesEachGetTheirOwnSignature() {
        // The three pages that carry forms must not collapse into each other.
        String login = d.pathSignature("/Login.asp?RetURL=%2F");
        String register = d.pathSignature("/Register.asp?RetURL=%2F");
        String search = d.pathSignature("/Search.asp");
        assertNotEquals(login, register);
        assertNotEquals(login, search);
        assertNotEquals(register, search);
    }

    @Test
    public void signatureIgnoresParameterOrder() {
        assertEquals(d.pathSignature("/x.asp?a=1&b=2"),
                     d.pathSignature("/x.asp?b=9&a=8"));
    }

    @Test
    public void caseIsNormalised() {
        assertEquals(d.pathSignature("/Login.asp"), d.pathSignature("/login.asp"));
    }
}
