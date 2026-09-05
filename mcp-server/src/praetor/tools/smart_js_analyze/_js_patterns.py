"""Regex + constant tables for smart_js_analyze."""

import re


_RE_ENDPOINT = re.compile(
    r'["\'`](/(api|v\d+|graphql|gql|trpc|rest)/[A-Za-z0-9/_\-\.\?\&\=\{\}\$]{2,200})["\'`]'
)
_RE_FETCH = re.compile(
    r'(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|\$\.\w+)\s*\(\s*["\'`]([^"\'`\s]{4,300})["\'`]'
)
_RE_WEBSOCKET = re.compile(
    r'new\s+WebSocket\s*\(\s*["\'`](wss?://[^"\'`\s]+|/[^"\'`\s]+)["\'`]'
)
_RE_GRAPHQL_OP = re.compile(
    r'\b(query|mutation|subscription)\s+(\w+)\s*[\(\{]'
)
_RE_GRAPHQL_ENDPOINT = re.compile(
    r'["\'`](/[A-Za-z0-9/_\-]*graphql[A-Za-z0-9/_\-]*)["\'`]'
)

# React Server Components — Server Action IDs (CVE-2025-55182 direct ammo)
_RE_RSC_ACTION = re.compile(
    r'createServerReference\(\s*["\']([0-9a-f]{40,64})["\']'
)
_RE_RSC_ACTION_ALT = re.compile(
    r'["\']\$ACTION_ID_([0-9a-f]{40,64})["\']'
)

# Auth surface
_RE_AUTH_HEADER = re.compile(
    r'["\'`](Authorization|X-API-?Key|X-Auth-Token|X-CSRF-Token|X-XSRF-Token|'
    r'X-Access-Token|Bearer|Cookie)["\'`]\s*[,:]'
)

# DOM XSS sinks — name + capture group for arg context
_DOM_SINKS = {
    "innerHTML": re.compile(r'\.innerHTML\s*=\s*([^;]+)'),
    "outerHTML": re.compile(r'\.outerHTML\s*=\s*([^;]+)'),
    "dangerouslySetInnerHTML": re.compile(r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}]+)'),
    "document.write": re.compile(r'document\.write(?:ln)?\s*\(\s*([^)]+)\)'),
    "eval": re.compile(r'\beval\s*\(\s*([^)]+)\)'),
    "Function_ctor": re.compile(r'new\s+Function\s*\(\s*([^)]+)\)'),
    "setTimeout_string": re.compile(r'setTimeout\s*\(\s*["\'`]([^"\'`]+)["\'`]'),
    "setInterval_string": re.compile(r'setInterval\s*\(\s*["\'`]([^"\'`]+)["\'`]'),
    "location_href": re.compile(r'location\.href\s*=\s*([^;]+)'),
    "location_replace": re.compile(r'location\.replace\s*\(\s*([^)]+)\)'),
    "postMessage_recv": re.compile(r'addEventListener\s*\(\s*["\']message["\']'),
}

# Secrets — standard set, tight patterns to avoid false positives
_SECRETS = {
    "aws_access_key": re.compile(r'\b(AKIA|ASIA|AGPA)[A-Z0-9]{16}\b'),
    "aws_secret_key": re.compile(r'(?i)aws[_\-\.]?secret[_\-\.]?key[\'"\s:=]{1,5}[A-Za-z0-9/+=]{40}'),
    "google_api_key": re.compile(r'\bAIza[0-9A-Za-z\-_]{30,45}\b'),
    "google_oauth": re.compile(r'\bya29\.[0-9A-Za-z\-_]+\b'),
    "stripe_live_secret": re.compile(r'\bsk_live_[A-Za-z0-9]{20,}\b'),
    "stripe_test_secret": re.compile(r'\bsk_test_[A-Za-z0-9]{20,}\b'),
    "stripe_publishable": re.compile(r'\bpk_(live|test)_[A-Za-z0-9]{20,}\b'),
    "github_pat": re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    "slack_token": re.compile(r'\bxox[abprs]-[A-Za-z0-9\-]{10,}\b'),
    "jwt": re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'),
    "private_key_pem": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
    "supabase_anon": re.compile(r'\bsbp_[A-Za-z0-9]{40,}\b'),
    "openai_api_key": re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b'),
    "anthropic_api_key": re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b'),
}

# Source maps — leaked .map files often expose original source
_RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=([^\s\'"]+)')

# Framework fingerprints — drives synthesiser
_FRAMEWORKS = {
    "nextjs": (re.compile(r'__NEXT_DATA__|next/dist|next-route-announcer|self\.__next_'), 90),
    "nuxt": (re.compile(r'__NUXT__|window\.\$nuxt'), 80),
    "remix": (re.compile(r'__remix|@remix-run'), 80),
    "react": (re.compile(r'react\.production|react-dom|createElement|useState'), 50),
    "vue": (re.compile(r'__VUE__|Vue\.component|createApp\('), 60),
    "angular": (re.compile(r'@angular|ng-version|platformBrowserDynamic'), 70),
    "svelte": (re.compile(r'svelte/internal|__sveltekit'), 70),
    "apollo": (re.compile(r'@apollo/client|ApolloProvider|gql`'), 70),
    "relay": (re.compile(r'relay-runtime|RelayEnvironment'), 70),
    "trpc": (re.compile(r'@trpc/client|trpc\.useQuery'), 80),
    "swr": (re.compile(r'\buseSWR\(|\bswr/'), 50),
    "tanstack_query": (re.compile(r'useQuery|@tanstack/react-query'), 50),
}


# ----- Fetch helpers --------------------------------------------------------


__all__ = ['_RE_ENDPOINT', '_RE_FETCH', '_RE_WEBSOCKET', '_RE_GRAPHQL_OP', '_RE_GRAPHQL_ENDPOINT', '_RE_RSC_ACTION', '_RE_RSC_ACTION_ALT', '_RE_AUTH_HEADER', '_DOM_SINKS', '_SECRETS', '_RE_SOURCEMAP', '_FRAMEWORKS']
