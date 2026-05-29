---
description: SAML XML Signature Wrapping (XSW) attacks — 8 standard variants per Somorovsky-Mainka-Schwenk research. Manual XML payload construction. Load when target uses SAML 2.0 (SSO via Salesforce / Okta / Ping / OneLogin / ADFS / Shibboleth).
globs:
---

# SAML XSW Deep-Dive

Load when: target uses SAML 2.0 SSO. Identifiers: `SAMLRequest` / `SAMLResponse` POST body, `RelayState` parameter, `https://.../sso/SAML2`, IDP-initiated or SP-initiated flows.

This is the most operator-driven class in Praetor — no auto_probe coverage. Manual XML construction required. KB `saml_xsw` (W1) is operator-built reference; this playbook is the workflow.

## What is XSW

The SAML assertion is signed with the IDP's XML Digital Signature. The signature `Reference` element points (via `URI` or XPath) at the signed element. SAML processors split into **verifier** and **consumer**:

- **Verifier** — finds the signed element (per Reference), validates the signature.
- **Consumer** — finds the assertion element (per assertion-locator logic), reads claims.

If the verifier finds one element and the consumer finds a different one, **wrapping attack succeeds**: attacker inserts a fake assertion that the consumer reads while the verifier validates the legitimate (untouched) one.

## 8 standard XSW variants (Somorovsky et al.)

| XSW | Wrap location | Attack | Common targets |
|---|---|---|---|
| **XSW1** | Wrap in `Response/Extensions` | Move legit assertion to Extensions; insert evil at root | Older Shibboleth |
| **XSW2** | Wrap in sibling under `Response` | Same as XSW1 with sibling-not-extensions | OneLogin, custom SPs |
| **XSW3** | Wrap legit inside evil `Assertion` | Evil assertion contains the legit (signed) one | OpenSAML pre-2.6 |
| **XSW4** | Same as XSW3 but with `Subject` swap | More targeted: only Subject is swapped | SP that re-validates Subject |
| **XSW5** | Wrap in `Assertion/Subject` | Insert evil Subject inside legit assertion's Subject | SimpleSAMLphp variants |
| **XSW6** | Same as XSW5 with `AttributeStatement` swap | Attribute-level swap | Programs that read by AttributeName |
| **XSW7** | Wrap legit inside evil with `Extensions` shielding | Combine XSW1 + XSW3 | Defence-in-depth bypass |
| **XSW8** | Same as XSW7 with double wrapping | XSW4 + XSW7 combo | Strongest known-bypass class |

Source: Somorovsky, Mainka, Schwenk — "On Breaking SAML: Be Whoever You Want To Be" (USENIX Security 2012). Still relevant — many SPs accept ≥1 variant.

## Detection workflow

1. **Capture SAML flow** — drive SSO login through Burp; capture the `SAMLResponse` POST to the SP's ACS endpoint.
2. **Decode** — `decode_encode(saml_response, ops=['base64'])` → XML.
3. **Inspect** — note: which element has the `Reference URI`, where is the actual assertion, what claims appear (NameID / AttributeStatement).
4. **Construct XSW1** as a baseline — easiest to detect:
   ```xml
   <Response>
     <Extensions>
       <!-- Original SIGNED assertion goes here, untouched -->
       <Assertion ID="legit"><Subject>victim</Subject></Assertion>
     </Extensions>
     <!-- EVIL assertion at root with attacker NameID -->
     <Assertion ID="evil">
       <Subject><NameID>attacker@victim.tld</NameID></Subject>
       <AttributeStatement>...</AttributeStatement>
     </Assertion>
   </Response>
   ```
5. **Submit + observe** — SP returns 200 with attacker session = XSW1 succeeds.
6. **Cycle through XSW2-XSW8** if XSW1 fails — different processors fall to different variants.

## Auto-detection signals (when to suspect XSW)

- SP has been around since 2012 and hasn't been audited (legacy enterprise SSO).
- SP rejects malformed XML signatures with generic error but accepts well-formed wrappers.
- SP processes the assertion BEFORE re-fetching the signed bytes (vulnerable processing order).
- SAML processing library version visible: OpenSAML < 3.4.0, SimpleSAMLphp < 1.18, Java SAML libraries < CVE-fix dates.

## Related attacks (not XSW but adjacent)

- **Assertion replay** — SP doesn't track `<Conditions NotOnOrAfter>` properly; replay old assertions.
- **Subject confirmation method weakness** — `urn:oasis:names:tc:SAML:2.0:cm:bearer` allows anyone with the assertion; chain with leak.
- **IDP confusion** — multi-IDP SP doesn't validate `Issuer` matches the IDP the assertion came from.
- **Audience restriction bypass** — `<AudienceRestriction>` not validated, assertion meant for App A used at App B.
- **XML Encryption attacks** — Bleichenbacher-style oracle on encrypted assertions (CVE-2019-3465 class).

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | SP returns 200 with attacker session for arbitrary `NameID` after XSW payload | yes |
| **CONFIRMED HIGH** | SP returns 200 with attacker session for foreign-tenant `NameID` (cross-tenant) | yes |
| **SUSPECTED** | SP accepts the XML but error message hints at processor confusion (e.g. "assertion not found" with 500) | NO save — keep tuning |
| **FAILED** | SP rejects with signature error every variant | NO |

## save_finding shape

```python
save_finding(
    vuln_type="saml_xsw",
    endpoint="https://app.target.com/sso/SAML2/POST",
    parameter="SAMLResponse",
    severity="critical",
    evidence={
        "logger_index": <xsw-accepted index>,
        "summary": "SAML XSW2 — wrapped legit assertion in sibling under Response, inserted attacker NameID at root. SP processes evil assertion's NameID while verifier validates legit signature. Result: arbitrary user impersonation.",
        "xsw_variant": "XSW2",                       # 1-8
        "saml_processor": "OpenSAML 2.5.1",          # from server header or library version
        "attacker_nameid": "<attacker.email@victim.tld>",
        "before_after_xml_diff": "<short diff or both blobs>",
    },
)
```

## NEVER_SUBMIT traps

- "SAML uses self-signed cert" — config issue, not XSW.
- "SAML metadata exposed" — metadata is intended public.
- "Tested XSW against SP, got 500" — that's REJECT, not exploit.
- "Theoretical XSW based on library version" — must demonstrate accepted XSW with attacker session.

## Severity discipline

- XSW that produces attacker session = CRITICAL (full ATO across any SP-protected app).
- XSW that produces cross-tenant access = CRITICAL (lateral movement in multi-tenant).
- XSW that's accepted by lib but rejected by SP business logic = HIGH (defence-in-depth gap, still reportable).

## Chain patterns

- **XSW + SP doesn't validate Conditions** = persistent session via long-validity wrap.
- **XSW + IDP confusion** = arbitrary attacker IDP can issue tokens for victim user.
- **XSW + privileged role claim** = direct privesc to admin.
- **XSW + multi-tenant** = cross-tenant ATO with single forged assertion.

## Related

- `knowledge/saml_xsw.json` — operator-built XML payload reference (ref-only by design; XML signature crafting can't be auto_probed)
- `chain-findings.md` — `saml_xsw_to_ato` chain pattern
- Original Somorovsky paper: https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf
- Burp SAML Raider extension — operator UI tool for XSW (binary extension, not Praetor-integrated)
- Rule 5 — never destructive
