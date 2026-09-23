"""Classify proxy-history entries as engagement noise so search / history reads
can drop them by default.

A real browser session captures thousands of third-party beacon, ad, and static-
asset rows interleaved with the handful of target app/API requests that matter.
Reading them all burns tokens and buries the signal. This classifies an entry by
its URL host + path + MIME as noise (third-party analytics / ads / telemetry /
static media) or signal (everything else — the target's own HTML/JS/JSON/API).

Deliberately conservative — it never drops:
  - the target's own hosts (only well-known third-party domains match by host);
  - JS / CSS / JSON / source maps (they carry endpoints and secrets — recon gold).
So a false-drop of a real finding is not possible from host+extension alone; only
images, fonts, media, and named third-party beacons are classed as noise.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Third-party host substrings that are never the target's own app logic. Grouped
# by category so a caller can filter on the reason (noise ~ ads).
_NOISE_HOSTS: dict[str, tuple[str, ...]] = {
    "analytics": (
        "google-analytics.com", "googletagmanager.com", "analytics.google",
        "segment.io", "segment.com", "mixpanel.com", "amplitude.com",
        "hotjar.com", "fullstory.com", "heap.io", "heapanalytics.com",
        "mouseflow.com", "quantserve.com", "clarity.ms", "optimizely.com",
        "launchdarkly.com", "statsig.com", "amplitude-", "matomo.",
    ),
    "ads": (
        "doubleclick.net", "googlesyndication.com", "adservice.google",
        "adnxs.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "pubmatic.com", "rubiconproject.com", "adsystem.com", "moatads.com",
        "scorecardresearch.com", "adsrvr.org", "2mdn.net", "adroll.com",
    ),
    "telemetry": (
        "sentry.io", "bugsnag.com", "datadoghq.com", "newrelic.com",
        "nr-data.net", "intercom.io", "connect.facebook.net", "facebook.com/tr",
        "platform.twitter.com",
        # Google / Chrome browser telemetry — the optimizationguide + gsi/log
        # beacons that flooded the operator's history behind a real Google login.
        "optimizationguide-pa.googleapis.com", "clients2.google.com",
        "clientservices.googleapis.com", "update.googleapis.com",
        "safebrowsing.googleapis.com", "accounts.google.com/gsi/log",
        "play.google.com/log", "gvt1.com", "gvt2.com", "beacons.gcp.gvt2.com",
    ),
    "asset": (
        # public font / asset CDNs — target app code is rarely served here
        "fonts.googleapis.com", "fonts.gstatic.com",
    ),
    # Browser-EXTENSION backends. A real operator profile runs Grammarly, a
    # password manager, an ad-blocker, a shopping helper — each of which fires its
    # own out-of-scope telemetry from every page, flooding history with traffic
    # that has nothing to do with the target. This list catches the common ones;
    # the robust general answer is Burp target scope (configure_scope) — anything
    # off-scope is noise for the engagement regardless of which extension sent it.
    "extension": (
        "grammarly.com", "grammarly.io", "gnar.grammarly.com",
        "languagetool.org", "languagetoolplus.com",
        "joinhoney.com", "honey.com",
        "getadblock.com", "adblockplus.org", "eyeo.com",
        "wikibuy.com", "capitaloneshopping.com",
        "improving.duckduckgo.com", "duckduckgo.com/e.js",
        "norton.com", "safeweb.norton.com", "safebrowse.io",
        "avast.com", "avg.com", "mcafee.com",
        "pocket.com", "getpocket.com", "loom.com",
        "lastpass.com", "1password.com", "dashlane.com", "bitwarden.com",
        "clients2.googleusercontent.com",
    ),
}

# Static media extensions carrying no app logic. JS / CSS / JSON / .map are KEPT
# on purpose — they hold endpoints and secrets.
_NOISE_EXT: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov", ".m4a", ".m4s",
)

_NOISE_MIME_PREFIX: tuple[str, ...] = ("image/", "font/", "video/", "audio/")


def classify(url: str, mime: str = "", keep_hosts: tuple[str, ...] = ()) -> str:
    """Noise category for a request, or "" when it looks like signal.

    Returns one of: analytics | ads | telemetry | extension | asset | "" (signal).

    `keep_hosts` are host substrings that are ALWAYS signal — scope wins over the
    deny-list. When the operator is actually testing one of these backends (e.g. a
    Grammarly engagement), the target host is passed here and is never classified
    as noise, so the hardcoded list can't hide it. Callers populate it from the
    host being filtered on / the configured target scope.
    """
    if not url:
        return ""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    full = url.lower()
    # keep_hosts exempts a host from the third-party DENY-LIST only (targeting a
    # Grammarly/CDN host on purpose), NOT from static-asset classification — an
    # image/font is still noise even on the target host, so assets keep dropping.
    exempt = bool(host) and any(k and k.lower() in host for k in keep_hosts)
    if not exempt:
        for category, subs in _NOISE_HOSTS.items():
            for sub in subs:
                # host substrings match the host; path-bearing markers (…/tr,
                # …/log, /gsi/log) match the full URL.
                target = full if "/" in sub else host
                if sub in target:
                    return category
    if parsed.path.lower().endswith(_NOISE_EXT):
        return "asset"
    if (mime or "").lower().startswith(_NOISE_MIME_PREFIX):
        return "asset"
    return ""


def is_noise(entry: dict, keep_hosts: tuple[str, ...] = ()) -> bool:
    """True when a proxy-history entry (needs url; mime_type optional) is noise.

    `keep_hosts` (host substrings that are always signal — the target scope /
    filtered host) exempts a request from noise classification, so a deliberately
    targeted extension/CDN host is never dropped.
    """
    return bool(classify(entry.get("url") or "", entry.get("mime_type") or "", keep_hosts))
