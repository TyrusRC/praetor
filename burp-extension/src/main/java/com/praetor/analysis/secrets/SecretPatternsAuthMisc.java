package com.praetor.analysis.secrets;

import java.util.List;

/** Auth-token and miscellaneous secret patterns — split from SecretPatterns to keep each file under 300 lines. */
final class SecretPatternsAuthMisc {
    private SecretPatternsAuthMisc() {}

    private static final String CRITICAL = SecretPatterns.CRITICAL;
    private static final String HIGH = SecretPatterns.HIGH;
    private static final String MEDIUM = SecretPatterns.MEDIUM;
    private static final String LOW = SecretPatterns.LOW;

    static void contribute(List<SecretPattern> p) {
        // =========================================================================
        // AUTH TOKENS
        // =========================================================================

        p.add(new SecretPattern("jwt-token",
                "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_.+/=-]{10,}", MEDIUM, false));
        p.add(new SecretPattern("bearer-token",
                "(?i)bearer\\s+[a-zA-Z0-9_.~+/=-]{20,}", MEDIUM, false));
        p.add(new SecretPattern("basic-auth",
                "(?i)basic\\s+[A-Za-z0-9+/=]{20,}", HIGH, false));
        p.add(new SecretPattern("oauth-client-secret",
                "(?i)(?:client.?secret|oauth.{0,10}secret)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{20,}", HIGH, true));
        p.add(new SecretPattern("oauth-refresh-token",
                "(?i)(?:refresh.?token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_.+/=-]{20,}", HIGH, true));

        // =========================================================================
        // PRIVATE KEYS & CERTIFICATES
        // =========================================================================

        p.add(new SecretPattern("rsa-private-key",
                "-----BEGIN RSA PRIVATE KEY-----", CRITICAL, false));
        p.add(new SecretPattern("ec-private-key",
                "-----BEGIN EC PRIVATE KEY-----", CRITICAL, false));
        p.add(new SecretPattern("dsa-private-key",
                "-----BEGIN DSA PRIVATE KEY-----", CRITICAL, false));
        p.add(new SecretPattern("openssh-private-key",
                "-----BEGIN OPENSSH PRIVATE KEY-----", CRITICAL, false));
        p.add(new SecretPattern("pgp-private-key",
                "-----BEGIN PGP PRIVATE KEY BLOCK-----", CRITICAL, false));
        p.add(new SecretPattern("pkcs8-private-key",
                "-----BEGIN PRIVATE KEY-----", CRITICAL, false));
        p.add(new SecretPattern("encrypted-private-key",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----", HIGH, false));

        // =========================================================================
        // DATABASE & CONNECTION STRINGS
        // =========================================================================

        p.add(new SecretPattern("postgres-url",
                "postgres(?:ql)?://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("mysql-url",
                "mysql://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("mongodb-url",
                "mongodb(?:\\+srv)?://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("redis-url",
                "redis(?:s)?://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("amqp-url",
                "amqps?://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("jdbc-url",
                "jdbc:[a-z]+://[^\\s'\"<>]{10,}", HIGH, false));
        p.add(new SecretPattern("odbc-connection-string",
                "(?i)(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+", HIGH, false));
        p.add(new SecretPattern("database-password",
                "(?i)(?:db|database).{0,10}(?:password|passwd|pwd|pass)[\"'\\s]*[:=][\"'\\s]*[^'\"\\s]{4,}", HIGH, true));

        // =========================================================================
        // WEBHOOKS & URLS
        // =========================================================================

        p.add(new SecretPattern("slack-webhook-url",
                "https://hooks\\.slack\\.com/(?:services|workflows)/[A-Za-z0-9/]+", HIGH, false));
        p.add(new SecretPattern("discord-webhook-url",
                "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", HIGH, false));
        p.add(new SecretPattern("teams-webhook-url",
                "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[^\\s'\"]+", HIGH, false));

        // =========================================================================
        // INTERNAL URLS & ENDPOINTS
        // =========================================================================

        p.add(new SecretPattern("internal-url",
                "(?i)https?://(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)[:/][^\\s'\"]*", MEDIUM, false));
        p.add(new SecretPattern("internal-hostname",
                "(?i)(?:staging|dev|internal|admin|debug|test|uat|preprod|qa)\\.\\w+\\.(?:com|net|org|io|dev|local)", LOW, false));

        // =========================================================================
        // HARDCODED CREDENTIALS (entropy-gated)
        // =========================================================================

        p.add(new SecretPattern("password-assignment",
                "(?i)(?:password|passwd|pwd|pass_?word)\\s*[:=]\\s*['\"][^'\"]{6,}['\"]", HIGH, true));
        p.add(new SecretPattern("secret-assignment",
                "(?i)(?:secret|secret_?key|private_?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("generic-api-key",
                "(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("generic-access-token",
                "(?i)(?:access[_-]?token|auth[_-]?token|session[_-]?token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("generic-client-secret",
                "(?i)(?:client[_-]?secret|app[_-]?secret)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("encryption-key",
                "(?i)(?:encryption[_-]?key|enc[_-]?key|aes[_-]?key|signing[_-]?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("private-key-data",
                "(?i)(?:private[_-]?key|priv[_-]?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));
        p.add(new SecretPattern("auth-header",
                "(?i)(?:authorization|x-api-key|x-auth-token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", HIGH, true));

        // =========================================================================
        // MISCELLANEOUS
        // =========================================================================

        p.add(new SecretPattern("age-secret-key",
                "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}", CRITICAL, false));
        p.add(new SecretPattern("hashicorp-tf-api-token",
                "(?i)(?:credentials|token)\\s+[\"']app\\.terraform\\.io[\"']\\s*\\{[^}]*token\\s*=\\s*[\"'][A-Za-z0-9.]{14,}[\"']", HIGH, false));
        p.add(new SecretPattern("ip-with-credentials",
                "(?i)(?:https?://)[^:]+:[^@]+@(?:\\d{1,3}\\.){3}\\d{1,3}", HIGH, false));
        p.add(new SecretPattern("generic-secret-hex32",
                "(?i)(?:secret|token|key|password|credential|auth)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32,64}", MEDIUM, true));

        // =========================================================================
        // ADDITIONAL HIGH-VALUE TOKENS (audit gap closures)
        // =========================================================================

        // Cloudflare API tokens (40-char base62-ish, often via "cf-" / "cloudflare" context)
        p.add(new SecretPattern("cloudflare-api-token",
                "(?i)(?:cloudflare|cf[-_])[a-z_-]{0,15}token[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{40,}", HIGH, false));
        // Cloudflare global API key (legacy 37-char hex)
        p.add(new SecretPattern("cloudflare-global-api-key",
                "(?i)(?:cloudflare|cf[-_])[a-z_-]{0,10}(?:global|api)[-_]?key[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{37}", CRITICAL, false));

        // Atlassian / JIRA / Confluence personal access tokens
        p.add(new SecretPattern("atlassian-api-token",
                "ATATT3xFfGF0[A-Za-z0-9_=\\-]{180,}", CRITICAL, false));
        // Generic Atlassian basic-auth pair (token after "atlassian"/"jira"/"confluence" keyword)
        p.add(new SecretPattern("atlassian-token-keyword",
                "(?i)(?:atlassian|jira|confluence)[a-z_-]{0,15}(?:token|api[-_]?key)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_=\\-]{24,}", HIGH, true));

        // Notion integration tokens
        p.add(new SecretPattern("notion-integration-token",
                "secret_[A-Za-z0-9]{43}", HIGH, false));

        // Vercel personal/deployment tokens
        p.add(new SecretPattern("vercel-token",
                "(?i)vercel[a-z_-]{0,15}token[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9]{24}", HIGH, false));

        // Okta SSWS API tokens (00-prefixed, 40+ char base64-ish)
        p.add(new SecretPattern("okta-api-token",
                "00[A-Za-z0-9_=\\-]{40}", CRITICAL, true));
        // Header-bound Okta SSWS
        p.add(new SecretPattern("okta-ssws-header",
                "(?i)authorization[\"'\\s]*[:=][\"'\\s]*ssws\\s+[A-Za-z0-9_=\\-]{40,}", CRITICAL, false));

        // Auth0 management/tenant tokens
        p.add(new SecretPattern("auth0-management-token",
                "(?i)auth0[a-z_-]{0,15}(?:token|api[-_]?key)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9._\\-]{40,}", HIGH, true));

        // Linear API keys
        p.add(new SecretPattern("linear-api-key",
                "lin_api_[A-Za-z0-9]{40}", HIGH, false));

        // Asana personal access tokens
        p.add(new SecretPattern("asana-pat",
                "0/[a-f0-9]{32}", MEDIUM, true));

        // Square OAuth refresh tokens (sq0rsp- / sq0idp-)
        p.add(new SecretPattern("square-refresh-token",
                "sq0rsp-[A-Za-z0-9_\\-]{43}", HIGH, false));
        p.add(new SecretPattern("square-id-token",
                "sq0idp-[A-Za-z0-9_\\-]{43}", MEDIUM, false));

        // Azure DefaultAzureCredential / managed-identity hints (suggest leaked principal)
        p.add(new SecretPattern("azure-managed-identity-hint",
                "(?i)(?:DefaultAzureCredential|managed_identity_client_id|AZURE_CLIENT_SECRET)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_\\-=.]{32,}", HIGH, true));

        // Postman API key
        p.add(new SecretPattern("postman-api-key",
                "PMAK-[a-f0-9]{24}-[a-f0-9]{34}", HIGH, false));

        // Confluence-specific PAT (different shape than ATATT)
        p.add(new SecretPattern("confluence-pat",
                "ATCTT3xFfGF0[A-Za-z0-9_=\\-]{180,}", HIGH, false));

    }
}
