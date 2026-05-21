"""Shared CVE-package constants."""

# Same Chrome 131 UA as the rest of the tool surface — keeps CVE lookups
# indistinguishable from a normal browser. Avoid identifying strings; some
# intel hosts (NVD especially) throttle or null-route tool UAs.
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
