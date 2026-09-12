package com.praetor.analysis.secrets;

import java.util.List;

/** Cloud-provider secret patterns — split from SecretPatterns to keep each file under 300 lines. */
final class SecretPatternsCloud {
    private SecretPatternsCloud() {}

    private static final String CRITICAL = SecretPatterns.CRITICAL;
    private static final String HIGH = SecretPatterns.HIGH;
    private static final String MEDIUM = SecretPatterns.MEDIUM;
    private static final String LOW = SecretPatterns.LOW;

    static void contribute(List<SecretPattern> p) {


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

    }
}
