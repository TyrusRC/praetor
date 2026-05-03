package com.swissknife.analysis;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts potential secrets, API keys, tokens, and sensitive data from JavaScript responses.
 * Patterns modeled after TruffleHog/Gitleaks with Shannon entropy checks for generic detectors.
 */
public final class JsSecretExtractor {

    private JsSecretExtractor() {}

    // --- Severity constants ---
    private static final String CRITICAL = "CRITICAL";
    private static final String HIGH = "HIGH";
    private static final String MEDIUM = "MEDIUM";
    private static final String LOW = "LOW";

    // Entropy threshold for generic patterns (passwords, generic API keys, etc.)
    private static final double ENTROPY_THRESHOLD = 3.5;

    // --- Pattern definitions (compiled once) ---
    private static final List<SecretPattern> PATTERNS;

    static {
        List<SecretPattern> p = new ArrayList<>();

        // =========================================================================
        // CLOUD PROVIDERS
        // =========================================================================

        // AWS
        p.add(new SecretPattern("aws-access-key-id",
                "AKIA[A-Z2-7]{16}", CRITICAL, false));
        p.add(new SecretPattern("aws-temp-access-key-id",
                "ASIA[A-Z2-7]{16}", CRITICAL, false));
        p.add(new SecretPattern("aws-secret-access-key",
                "(?i)(?:aws_secret_access_key|aws_secret|aws.{0,12}secret)[\"'\\s]*[:=][\"'\\s]*([A-Za-z0-9/+=]{40})", CRITICAL, false));
        p.add(new SecretPattern("aws-session-token",
                "(?i)(?:aws.{0,10}session.{0,5}token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9/+=]{100,}", HIGH, false));
        p.add(new SecretPattern("aws-sts-temp-creds",
                "(?i)aws_session_token[\"'\\s]*[:=][\"'\\s]*FQoG[A-Za-z0-9/+=]{200,}", CRITICAL, false));
        p.add(new SecretPattern("aws-account-id",
                "(?i)(?:aws.{0,10}account.{0,5}id)[\"'\\s]*[:=][\"'\\s]*[0-9]{12}", MEDIUM, false));
        p.add(new SecretPattern("aws-mws-key",
                "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", HIGH, false));

        // GCP
        p.add(new SecretPattern("gcp-api-key",
                "AIza[\\w-]{35}", HIGH, false));
        p.add(new SecretPattern("gcp-oauth-client-id",
                "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", MEDIUM, false));
        p.add(new SecretPattern("gcp-service-account",
                "\"type\"\\s*:\\s*\"service_account\"", HIGH, false));
        p.add(new SecretPattern("gcp-oauth-secret",
                "(?i)(?:client_secret|google.{0,10}secret)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{24}", HIGH, true));
        p.add(new SecretPattern("firebase-url",
                "[a-z0-9-]+\\.firebaseio\\.com", MEDIUM, false));
        p.add(new SecretPattern("firebase-api-key",
                "(?i)(?:firebase.{0,10}(?:api.?key|key))[\"'\\s]*[:=][\"'\\s]*AIza[\\w-]{35}", HIGH, false));

        // Azure
        p.add(new SecretPattern("azure-client-secret",
                "(?i)(?:azure.{0,15}(?:client.?secret|secret))[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9~._-]{34,}", HIGH, true));
        p.add(new SecretPattern("azure-storage-key",
                "(?i)(?:AccountKey|azure.{0,10}storage.{0,5}key)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9/+=]{86,88}==", CRITICAL, false));
        p.add(new SecretPattern("azure-connection-string",
                "(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{86,88}==", CRITICAL, false));
        p.add(new SecretPattern("azure-sas-token",
                "(?i)[?&](?:sv|sig)=[^&\\s]{10,}", MEDIUM, false));
        p.add(new SecretPattern("azure-ad-token",
                "(?i)(?:tenant.?id|client.?id)[\"'\\s]*[:=][\"'\\s]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", MEDIUM, false));

        // Alibaba Cloud
        p.add(new SecretPattern("alibaba-access-key",
                "LTAI[A-Za-z0-9]{12,20}", HIGH, false));
        p.add(new SecretPattern("alibaba-secret-key",
                "(?i)(?:alibaba|aliyun).{0,15}secret[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9]{30}", HIGH, true));

        // DigitalOcean
        p.add(new SecretPattern("digitalocean-pat",
                "dop_v1_[a-f0-9]{64}", HIGH, false));
        p.add(new SecretPattern("digitalocean-oauth",
                "doo_v1_[a-f0-9]{64}", HIGH, false));
        p.add(new SecretPattern("digitalocean-refresh",
                "dor_v1_[a-f0-9]{64}", HIGH, false));
        p.add(new SecretPattern("digitalocean-spaces-key",
                "(?i)(?:spaces|digitalocean).{0,15}(?:key|secret)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9/+=]{40,}", HIGH, true));

        // Heroku
        p.add(new SecretPattern("heroku-api-key",
                "(?i)(?:heroku.{0,15}(?:api.?key|key|token))[\"'\\s]*[:=][\"'\\s]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", HIGH, false));

        // =========================================================================
        // AI / ML SERVICES
        // =========================================================================

        p.add(new SecretPattern("openai-api-key",
                "sk-proj-[A-Za-z0-9_-]{40,}", CRITICAL, false));
        p.add(new SecretPattern("openai-service-account-key",
                "sk-svcacct-[A-Za-z0-9_-]{40,}", CRITICAL, false));
        p.add(new SecretPattern("openai-api-key-legacy",
                "sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", CRITICAL, false));
        p.add(new SecretPattern("anthropic-api-key",
                "sk-ant-api03-[A-Za-z0-9_-]{90,}", CRITICAL, false));
        p.add(new SecretPattern("huggingface-token",
                "hf_[A-Za-z0-9]{34,}", HIGH, false));
        p.add(new SecretPattern("cohere-api-key",
                "(?i)(?:cohere.{0,10}(?:api.?key|key))[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9]{40}", HIGH, true));
        p.add(new SecretPattern("deepseek-api-key",
                "(?i)(?:deepseek.{0,10}(?:api.?key|key))[\"'\\s]*[:=][\"'\\s]*sk-[A-Za-z0-9]{32,}", HIGH, false));
        p.add(new SecretPattern("replicate-api-key",
                "r8_[A-Za-z0-9]{36}", HIGH, false));

        // =========================================================================
        // SCM / CODE HOSTING
        // =========================================================================

        // GitHub
        p.add(new SecretPattern("github-pat",
                "ghp_[A-Za-z0-9]{36}", CRITICAL, false));
        p.add(new SecretPattern("github-fine-grained-pat",
                "github_pat_[A-Za-z0-9_]{22,}", CRITICAL, false));
        p.add(new SecretPattern("github-oauth",
                "gho_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("github-user-to-server",
                "ghu_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("github-server-to-server",
                "ghs_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("github-refresh-token",
                "ghr_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("github-app-id",
                "(?i)(?:github.{0,10}app.{0,5}id)[\"'\\s]*[:=][\"'\\s]*[0-9]{5,}", LOW, false));

        // GitLab
        p.add(new SecretPattern("gitlab-pat",
                "glpat-[A-Za-z0-9_-]{20,}", CRITICAL, false));
        p.add(new SecretPattern("gitlab-pipeline-token",
                "glptt-[A-Za-z0-9_-]{20,}", HIGH, false));
        p.add(new SecretPattern("gitlab-runner-token",
                "glrt-[A-Za-z0-9_-]{20,}", HIGH, false));

        // Bitbucket
        p.add(new SecretPattern("bitbucket-app-password",
                "(?i)(?:bitbucket.{0,15}(?:password|secret|token))[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9]{18,}", HIGH, true));

        // =========================================================================
        // COMMUNICATION / MESSAGING
        // =========================================================================

        // Slack
        p.add(new SecretPattern("slack-bot-token",
                "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", CRITICAL, false));
        p.add(new SecretPattern("slack-user-token",
                "xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", CRITICAL, false));
        p.add(new SecretPattern("slack-app-token",
                "xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", HIGH, false));
        p.add(new SecretPattern("slack-config-token",
                "xoxe\\.xox[bp]-1-[A-Za-z0-9]{60,}", HIGH, false));
        p.add(new SecretPattern("slack-webhook",
                "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", HIGH, false));
        p.add(new SecretPattern("slack-signing-secret",
                "(?i)(?:slack.{0,10}signing.{0,5}secret)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32}", HIGH, false));

        // Discord
        p.add(new SecretPattern("discord-bot-token",
                "[MN][A-Za-z0-9]{23,}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,}", HIGH, false));
        p.add(new SecretPattern("discord-webhook",
                "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", HIGH, false));

        // Telegram
        p.add(new SecretPattern("telegram-bot-token",
                "[0-9]{8,10}:[A-Za-z0-9_-]{35}", HIGH, false));

        // =========================================================================
        // PAYMENT PLATFORMS
        // =========================================================================

        // Stripe
        p.add(new SecretPattern("stripe-secret-key",
                "sk_(?:test|live)_[0-9a-zA-Z]{24,}", CRITICAL, false));
        p.add(new SecretPattern("stripe-publishable-key",
                "pk_(?:test|live)_[0-9a-zA-Z]{24,}", MEDIUM, false));
        p.add(new SecretPattern("stripe-restricted-key",
                "rk_(?:test|live)_[0-9a-zA-Z]{24,}", HIGH, false));
        p.add(new SecretPattern("stripe-webhook-secret",
                "whsec_[A-Za-z0-9]{32,}", HIGH, false));

        // Square
        p.add(new SecretPattern("square-access-token",
                "sq0atp-[0-9A-Za-z_-]{22}", HIGH, false));
        p.add(new SecretPattern("square-oauth-secret",
                "sq0csp-[0-9A-Za-z_-]{43}", HIGH, false));

        // Braintree
        p.add(new SecretPattern("braintree-access-token",
                "access_token\\$(?:production|sandbox)\\$[a-z0-9]{16}\\$[a-f0-9]{32}", HIGH, false));

        // PayPal
        p.add(new SecretPattern("paypal-braintree-token",
                "(?i)(?:paypal|braintree).{0,15}(?:secret|token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{32,}", HIGH, true));

        // =========================================================================
        // EMAIL / SMS SERVICES
        // =========================================================================

        p.add(new SecretPattern("twilio-api-key",
                "SK[0-9a-fA-F]{32}", HIGH, false));
        p.add(new SecretPattern("twilio-account-sid",
                "AC[0-9a-fA-F]{32}", MEDIUM, false));
        p.add(new SecretPattern("sendgrid-api-key",
                "SG\\.[0-9A-Za-z_-]{22,}\\.[0-9A-Za-z_-]{22,}", HIGH, false));
        p.add(new SecretPattern("mailgun-api-key",
                "key-[0-9a-zA-Z]{32}", HIGH, false));
        p.add(new SecretPattern("mailchimp-api-key",
                "[0-9a-f]{32}-us[0-9]{1,2}", HIGH, false));
        p.add(new SecretPattern("postmark-server-token",
                "(?i)(?:postmark|pmak).{0,10}(?:token|key)[\"'\\s]*[:=][\"'\\s]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", HIGH, false));

        // =========================================================================
        // PACKAGE REGISTRIES
        // =========================================================================

        p.add(new SecretPattern("npm-token",
                "npm_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("pypi-token",
                "pypi-[A-Za-z0-9_-]{50,}", HIGH, false));
        p.add(new SecretPattern("nuget-api-key",
                "oy2[a-z0-9]{43}", HIGH, false));
        p.add(new SecretPattern("rubygems-api-key",
                "rubygems_[a-f0-9]{48}", HIGH, false));
        p.add(new SecretPattern("docker-config-auth",
                "(?i)\"auth\"\\s*:\\s*\"[A-Za-z0-9+/=]{20,}\"", MEDIUM, false));

        // =========================================================================
        // MONITORING / OBSERVABILITY
        // =========================================================================

        p.add(new SecretPattern("datadog-api-key",
                "(?i)(?:datadog|dd).{0,15}(?:api.?key|key)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32}", HIGH, false));
        p.add(new SecretPattern("datadog-app-key",
                "(?i)(?:datadog|dd).{0,15}app.?key[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{40}", HIGH, false));
        p.add(new SecretPattern("new-relic-key",
                "(?i)(?:new.?relic).{0,15}(?:key|license)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{32,}", HIGH, true));
        p.add(new SecretPattern("sentry-dsn",
                "https://[a-f0-9]{32}@(?:o[0-9]+\\.)?(?:sentry\\.io|[^/]+)/[0-9]+", HIGH, false));
        p.add(new SecretPattern("grafana-api-key",
                "eyJrIjoi[A-Za-z0-9+/=]{40,}", HIGH, false));
        p.add(new SecretPattern("pagerduty-token",
                "(?i)(?:pagerduty).{0,15}(?:key|token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_+/-]{20}", HIGH, true));

        // =========================================================================
        // BACKEND / INFRASTRUCTURE
        // =========================================================================

        // Supabase
        p.add(new SecretPattern("supabase-anon-key",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[A-Za-z0-9_-]{50,}\\.[A-Za-z0-9_-]{20,}", MEDIUM, false));
        p.add(new SecretPattern("supabase-service-role-key",
                "(?i)(?:supabase.{0,10}service.{0,5}(?:role|key))[\"'\\s]*[:=][\"'\\s]*eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", CRITICAL, false));

        // HashiCorp Vault
        p.add(new SecretPattern("vault-token",
                "hvs\\.[A-Za-z0-9_-]{24,}", CRITICAL, false));
        p.add(new SecretPattern("vault-batch-token",
                "hvb\\.[A-Za-z0-9_-]{24,}", HIGH, false));

        // Doppler
        p.add(new SecretPattern("doppler-token",
                "dp\\.(?:st|ct|sa|scim|audit)\\.[A-Za-z0-9_-]{40,}", HIGH, false));

        // Mapbox
        p.add(new SecretPattern("mapbox-secret-token",
                "sk\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{20,}", HIGH, false));
        p.add(new SecretPattern("mapbox-public-token",
                "pk\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{20,}", LOW, false));

        // Shopify
        p.add(new SecretPattern("shopify-access-token",
                "shpat_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-shared-secret",
                "shpss_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-custom-app-token",
                "shpca_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-private-app-password",
                "shppa_[a-fA-F0-9]{32}", HIGH, false));

        // Algolia
        p.add(new SecretPattern("algolia-api-key",
                "(?i)(?:algolia).{0,15}(?:api.?key|admin.?key|key)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32}", HIGH, true));

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

        PATTERNS = Collections.unmodifiableList(p);
    }

    /**
     * Extract secrets from a response body (typically JavaScript).
     *
     * @param body the response body text
     * @return map with total_secrets, secrets list
     */
    public static Map<String, Object> extract(String body) {
        if (body == null || body.isEmpty()) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("total_secrets", 0);
            empty.put("secrets", Collections.emptyList());
            return empty;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> secrets = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (SecretPattern sp : PATTERNS) {
            Matcher matcher = sp.compiled.matcher(body);

            while (matcher.find()) {
                String match = matcher.group();

                // Entropy gate for generic patterns
                if (sp.requiresEntropy) {
                    String candidate = extractCandidate(match);
                    if (shannonEntropy(candidate) < ENTROPY_THRESHOLD) {
                        continue;
                    }
                }

                // Deduplicate by type + matched text
                String dedupeKey = sp.name + ":" + match;
                if (!seen.add(dedupeKey)) {
                    continue;
                }

                // Build surrounding context (50 chars each side)
                int ctxStart = Math.max(0, matcher.start() - 50);
                int ctxEnd = Math.min(body.length(), matcher.end() + 50);
                String context = body.substring(ctxStart, ctxEnd).replaceAll("[\\r\\n]+", " ");

                Map<String, Object> secret = new LinkedHashMap<>();
                secret.put("type", sp.name);
                secret.put("severity", sp.severity);
                secret.put("match", truncate(match, 200));
                secret.put("context", truncate(context, 300));
                secret.put("position", matcher.start());
                secrets.add(secret);
            }
        }

        // Sort by severity descending (CRITICAL > HIGH > MEDIUM > LOW)
        secrets.sort((a, b) -> severityRank((String) b.get("severity")) - severityRank((String) a.get("severity")));

        result.put("total_secrets", secrets.size());
        result.put("secrets", secrets);
        return result;
    }

    // -------------------------------------------------------------------------
    // Entropy calculation
    // -------------------------------------------------------------------------

    /**
     * Calculate Shannon entropy of a string. Higher values indicate more randomness.
     * Typical thresholds: random API keys >= 4.0, English words ~3.0, placeholders < 3.0.
     */
    static double shannonEntropy(String s) {
        if (s == null || s.length() < 2) return 0.0;

        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            freq[s.charAt(i) & 0xFF]++;
        }

        double entropy = 0.0;
        double len = s.length();
        for (int f : freq) {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /**
     * Extract the value portion from a key=value or key: value match.
     * For patterns like `password = "hunter2"`, returns `hunter2`.
     */
    private static String extractCandidate(String match) {
        // Try to find the value portion after = or : followed by quote
        int idx = -1;
        for (int i = 0; i < match.length(); i++) {
            char c = match.charAt(i);
            if (c == '=' || c == ':') {
                idx = i;
                break;
            }
        }
        if (idx < 0) return match;

        String valuePart = match.substring(idx + 1).trim();
        // Strip quotes
        if (valuePart.length() >= 2) {
            char first = valuePart.charAt(0);
            char last = valuePart.charAt(valuePart.length() - 1);
            if ((first == '\'' || first == '"') && first == last) {
                return valuePart.substring(1, valuePart.length() - 1);
            }
        }
        return valuePart;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static int severityRank(String severity) {
        return switch (severity) {
            case CRITICAL -> 4;
            case HIGH -> 3;
            case MEDIUM -> 2;
            case LOW -> 1;
            default -> 0;
        };
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    /**
     * Pre-compiled secret pattern with optional entropy gating.
     */
    private record SecretPattern(String name, String regex, String severity, boolean requiresEntropy, Pattern compiled) {
        SecretPattern(String name, String regex, String severity, boolean requiresEntropy) {
            this(name, regex, severity, requiresEntropy, Pattern.compile(regex));
        }
    }
}
