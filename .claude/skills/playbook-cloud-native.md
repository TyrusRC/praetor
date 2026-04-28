---
name: playbook-cloud-native
description: Web-app exploitation against AWS / GCP / Azure-hosted apps. Use when target reveals cloud-native components (Cognito tokens, S3/GCS/Blob URLs, Lambda Function URLs, App Service, Cloud Run, AWS SDK errors, IAM names in JS bundles). Covers IMDSv1/v2 SSRF, cloud storage misconfig, federated identity flaws, cloud-specific JWT abuses — web-app techniques only.
prerequisite: At least one cloud-native signal in proxy history or JS bundles (cloud domain, SAS token, AWS access key prefix, Cognito issuer, Firebase URL). If no cloud signal → skip; don't speculate.
stop_condition: 10 tool calls with no IMDS hit, no leaked credential matched, no public bucket, no SAS scope error, no Cognito unauth-creds response → return to router. Cloud bugs hide in misconfigs, not raw payload spraying.
---

# Cloud-Native Web App Playbook (AWS / GCP / Azure)

The MCP tools are web-app focused (proxy, repeater, fuzzer, SSRF, JWT, CORS, OAuth, GraphQL). Use them against cloud-native components reachable from the web tier. **Do not** run cloud CLI commands or assume credentials — every technique below works from a browser-equivalent HTTP client through Burp.

## How to Detect a Cloud-Native Stack

Run `detect_tech_stack`, `extract_js_secrets`, `extract_links`, and `analyze_dom` on the home page and the main JS bundle. Cloud signatures to flag:

| Signal in response / JS bundle | Cloud / service |
|---|---|
| `s3.amazonaws.com`, `s3-<region>.amazonaws.com`, `s3.<region>.amazonaws.com` | AWS S3 |
| `cognito-idp.<region>.amazonaws.com`, `cognito-identity.<region>.amazonaws.com` | AWS Cognito |
| `<id>.execute-api.<region>.amazonaws.com` | AWS API Gateway |
| `<id>.lambda-url.<region>.on.aws` | AWS Lambda Function URL |
| `cloudfront.net` URLs | AWS CloudFront |
| `AKIA...`, `ASIA...` (20-char base32, AWS access key), `aws_access_key_id`, `x-amz-security-token` header | AWS IAM credentials in transit |
| `storage.googleapis.com`, `firebaseio.com`, `firebasestorage.googleapis.com` | GCP Storage / Firebase |
| `<project>.firebaseapp.com`, `<project>.web.app`, `googleapis.com/identitytoolkit` | Firebase Auth |
| `appspot.com`, `<region>-<project>.cloudfunctions.net`, `run.app` | App Engine / Cloud Functions / Cloud Run |
| `*.azurewebsites.net`, `*.scm.azurewebsites.net` | Azure App Service |
| `*.blob.core.windows.net`, `*.queue.core.windows.net`, `*.file.core.windows.net` | Azure Storage |
| `?sv=...&sig=...&se=...` query strings | Azure SAS token |
| `login.microsoftonline.com`, `*.b2clogin.com` | Azure AD / B2C |
| `*.azure-api.net` | Azure API Management |

Save anything found via `save_target_intel(domain, "profile", {"cloud_signals": [...]})`.

---

## AWS — Web App Techniques

### 1. IMDSv1 SSRF → temporary credentials → S3/internal API
- Run `test_cloud_metadata` against any URL/host param. The probe hits `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
- A successful response yields `AccessKeyId`, `SecretAccessKey`, `Token` for the EC2/ECS task role.
- Web-app exploitation: pipe the credentials into a follow-up SSRF that signs requests via SigV4 to internal AWS APIs reachable from the same VPC. The hunter does this *manually* through `send_http_request` with the Authorization header constructed offline.

### 2. IMDSv2 SSRF — needs PUT-then-GET
IMDSv2 requires:
```
PUT /latest/api/token   Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
→ returns token
GET /latest/meta-data/  Header: X-aws-ec2-metadata-token: <token>
```
Many SSRF surfaces only support GET — those are immune to IMDSv2. Surfaces vulnerable: any handler that proxies arbitrary methods AND headers (e.g. webhook proxies, fetcher services, image renderers that follow redirects with custom headers, GraphQL resolvers that take URL+method+headers as args). Use `find_injection_points` to locate request bodies that include `method` and `headers` fields.

If only GET-SSRF is available, IMDSv2 cannot be reached — STOP that path, pivot.

### 3. Cognito JWT abuses — all framework-agnostic
- Decode JWT with `test_jwt(token)`.
- **`alg:none`:** still works on misconfigured custom verifiers. Flip header `alg` to `none`, drop signature, retry.
- **`kid` injection:** if the verifier loads keys by `kid`, try path traversal (`../../../dev/null`) or SQLi.
- **Custom claims tampering:** Cognito tokens carry `cognito:groups`, `custom:role`. Flip them, re-sign with weak secret, replay.
- **ID token vs Access token confusion:** ID tokens are *not* meant for authorization. If the app accepts an ID token where it should require an access token, you can bypass scope/aud checks. Replay both via `send_http_request` and observe.
- **Identity Pool unauth credentials:** `cognito-identity.<region>.amazonaws.com/?Operation=GetCredentialsForIdentity` may return creds without auth if the unauth role is misconfigured. Test by replaying the request seen in the JS bundle.

### 4. S3 bucket misconfigurations
Every `s3.amazonaws.com/<bucket>/...` URL discovered by `extract_links` or `extract_js_secrets` should be probed:
- `GET /<bucket>/?list-type=2` → public listing? CRITICAL.
- `GET /<bucket>/?acl` → public ACL? CRITICAL.
- `PUT /<bucket>/<key>` with body `<test>` from no auth → public write? CRITICAL.
- Presigned URL replay: capture a presigned URL, swap `<bucket>` or path, replay — does the signature still validate? (It must not, but check.)
- `?versions` to list object versions including deleted secrets.

Probe each bucket using `curl_request` (avoids same-origin) and confirm via `extract_regex` looking for `<ListBucketResult>` or `<AccessControlPolicy>`.

### 5. Lambda Function URL / API Gateway
- Lambda Function URLs at `*.lambda-url.<region>.on.aws` can be **AuthType: NONE** (publicly invokable). If the app calls one from JS, replay it from your own session — no CORS, no origin check.
- API Gateway endpoints often expose `/<stage>/<resource>` with stage variables. Try replacing `prod` with `dev`, `test`, `staging` — different IAM authorisers may apply.
- Look for `x-amzn-RequestId`, `x-amz-apigw-id` headers — confirms API Gateway.

### 6. CloudFront origin bypass
- If CloudFront fronts an S3 origin or ALB, the origin is sometimes reachable directly (origin server allows any Host header).
- Discover origin via `crt.sh` (`query_crtsh`) or DNS history (`fetch_wayback_urls` + DNS records).
- Test with `Host: <cloudfront-domain>` header against the origin IP — if it serves the same content, origin is exposed.

---

## GCP — Web App Techniques

### 1. GCP Metadata SSRF
- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- **Required header:** `Metadata-Flavor: Google` — without it, GCP returns 403. Many SSRF surfaces strip custom headers; if so, GCP IMDS is unreachable.
- High-value paths: `instance/service-accounts/default/token` (returns OAuth2 access token).
- The OAuth2 token can then be used against Google APIs over HTTPS via `send_http_request` with `Authorization: Bearer <token>`.

### 2. Firebase Realtime Database / Firestore — public rules
- Database URL: `https://<project>.firebaseio.com/.json` or `/<path>.json`
- Default permissive rules (`{"rules": {".read": "true"}}`) allow unauthenticated read of the entire DB.
- Probe with `curl_request("https://<project>.firebaseio.com/.json")` — a JSON dump = critical info disclosure.
- Firestore: `firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<collection>` — same idea.

### 3. Firebase Auth — anonymous sign-up + privilege
- `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>` — if the API key from the JS bundle works without referrer restriction, you can self-sign-up anonymous accounts.
- Replay the app's identity-toolkit calls swapping Authorization or claims.

### 4. GCS bucket misconfigurations
- `storage.googleapis.com/<bucket>/` — list with `?fields=items` if public.
- `gsutil`-style paths exposed in JS: enumerate, test public read/write.

### 5. Cloud Run / App Engine
- Cloud Run services at `*.run.app` may have `--allow-unauthenticated`. Test direct invocation.
- App Engine `appspot.com` services historically expose `/_ah/admin` and similar — probe via `discover_common_files` extended list.

---

## Azure — Web App Techniques

### 1. Azure Instance Metadata Service (IMDS)
- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **Required header:** `Metadata: true`. Same constraint as GCP — without header injection, IMDS is unreachable.
- High-value path: `/metadata/identity/oauth2/token?resource=https://management.azure.com/` — returns a Managed Identity bearer token.
- Use the token against `management.azure.com` ARM APIs via `send_http_request`.

### 2. Azure Storage SAS token abuse
- SAS query string: `?sv=&ss=&srt=&sp=&se=&st=&spr=&sig=`. If discovered in JS, check:
  - `sp` (signed permissions): `racwdlmeop` — `w` (write), `d` (delete), `l` (list) granted to the public means takeover.
  - `se` (signed expiry): far-future date = long-term key in client code = bug.
  - `srt` (signed resource types): `sco` includes container — list everything.
- Replay the SAS URL with modified path / blob name to test scope enforcement.

### 3. Azure AD / B2C OAuth flaws
- B2C custom policies are commonly misconfigured. Look at the OAuth flow in proxy history:
  - `redirect_uri` validation often allows wildcards on the same domain — abuse for token theft.
  - `state` reuse / CSRF — replay the auth response with a different `state`.
  - `id_token` accepted where `access_token` should be (audience confusion) — same as Cognito ID-token confusion.

### 4. App Service Kudu / SCM exposure
- `*.scm.azurewebsites.net` — Kudu admin console. Sometimes exposed without IP restriction. Probe `discover_common_files` extension: `/api/zipdeploy`, `/api/vfs/`, `/DebugConsole`.

### 5. Azure Function HTTP triggers
- Anonymous-auth functions (`authLevel: anonymous`) at `*.azurewebsites.net/api/<func>` are publicly invokable. Replay with modified inputs.

---

## Universal Cloud Web-App Wins

These work across any cloud:

1. **Leaked credentials in JS bundles** — `extract_js_secrets` catches AWS/GCP/Azure access keys, SAS tokens, Firebase API keys, service-account JSON. Treat any hit as critical until proven non-functional.
2. **Open redirects to cloud metadata** — chain `test_open_redirect` with `test_cloud_metadata` — if the redirect parameter is server-fetched (e.g. for OG-image preview), it's an SSRF to IMDS even when SSRF tests on direct params fail.
3. **CORS + cloud storage** — CORS misconfigs on `s3.amazonaws.com`/`storage.googleapis.com`/`*.blob.core.windows.net` allow cross-origin reads of presigned/public objects. Test with `test_cors`.
4. **Server-side request inspection** — many image processors / SSR fetchers / OG-tag generators / webhook proxies all qualify as IMDS pivot points. Find them via `find_injection_points` keyed on body params containing `url`/`webhook`/`callback`/`source`.
5. **Subdomain takeover on cloud-fronted assets** — `test_subdomain_takeover` against any `*.s3.amazonaws.com`, `*.azureedge.net`, `*.cloudfront.net`, `*.blob.core.windows.net` CNAME pointing at a deleted bucket.

## What This Tool Cannot Do (use external tools)

The Burp Swiss Knife MCP is web-app focused. For these you need separate tooling:

- AWS CLI / boto3 to actually use leaked AWS credentials against AWS APIs (you can hand-craft SigV4 in Burp but it's painful)
- `kube-hunter`, `kubectl` for Kubernetes API server probing
- Azure CLI for ARM API exploration once a Managed Identity token is captured
- `gcloud` / `gsutil` for GCS bulk operations

For those, dump the credentials/tokens into a separate authorised offensive workstation. Never run cloud-CLI commands from this Burp-MCP session — the tooling and scope discipline are different.

## Cross-references

- **SSRF basics:** `auto_probe(categories=['ssrf'])`, `test_cloud_metadata`
- **JWT abuse:** `verify-finding.md` § JWT Attacks, `test_jwt`
- **JS-leaked secrets:** `extract_js_secrets`, `static-dynamic-analysis.md`
- **Subdomain takeover:** `test_subdomain_takeover`, `playbook-cve-research.md`
- **PayloadsAllTheThings reference:** `Methodology and Resources/Cloud - <Provider> - Privilege Escalation.md`
- **HackTricks reference:** `pentesting-cloud/aws-security` and `pentesting-cloud/gcp-security`
