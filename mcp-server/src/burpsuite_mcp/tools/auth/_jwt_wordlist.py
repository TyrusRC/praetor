"""Built-in HS256 secret wordlist for crack_jwt_secret.

Sourced from public default-config disclosures and the standard JWT crack lists
(jwt_tool's jwt.secrets.list, rockyou frequency-trimmed, framework default
docs). Intentionally not exhaustive — operators with a real engagement should
pass `wordlist_path` to a larger file. 250 entries hits the long tail of
"vibes-driven" production secrets without ballooning the package size.

Categories represented:
- Empty / single-char
- "secret" variants (the most common default by 10x)
- Framework defaults (Express, Flask, Django, Spring, Auth0, Laravel)
- Tutorial / blog-copy strings (your-256-bit-secret, supersecret, jwt-secret)
- "Strong-sounding but bad" (P@ssw0rd!, ChangeMeNow, MyAppSecret123)
- Common dictionary + year suffix
"""

JWT_DEFAULT_WORDLIST: tuple[str, ...] = (
    # ── Trivial ──
    "", " ", "secret", "Secret", "SECRET",
    "secret123", "secret1234", "secret12345",
    "password", "Password", "PASSWORD", "pass", "passwd",
    "admin", "Admin", "administrator", "root",
    "12345", "123456", "1234567", "12345678", "123456789",
    "qwerty", "abc123", "letmein", "welcome", "monkey",

    # ── "secret" variations ──
    "supersecret", "topsecret", "mysecret", "jwt-secret", "jwtsecret",
    "jwt_secret", "JWT_SECRET", "JWTSecret", "JwtSecret",
    "your-secret", "your_secret", "your-secret-key", "your_secret_key",
    "secret-key", "secret_key", "secretkey", "SecretKey", "SECRET_KEY",
    "myappsecret", "MyAppSecret", "appsecret", "app_secret", "AppSecret",
    "thisisasecret", "this-is-a-secret", "this_is_my_secret",

    # ── Documentation / tutorial defaults ──
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
    "your-256-bit-secret-key", "your_256_bit_secret",
    "change-me", "changeme", "ChangeMe", "CHANGE_ME",
    "change-this-secret", "change_this_secret", "ChangeMeNow",
    "default-secret", "default_secret", "defaultsecret",
    "example", "example-secret", "test", "testing", "test-secret",
    "demo", "demo-secret", "sample", "samplesecret",
    "placeholder", "placeholder-secret",

    # ── Framework / library defaults ──
    "express-jwt-secret", "express-secret", "express",
    "flask-secret", "flask_secret_key", "flask-jwt-secret",
    "django-secret", "django-insecure", "django_secret_key",
    "spring-boot-secret", "spring-secret",
    "laravel", "laravel-secret", "laravel_app_key",
    "nestjs", "nestjs-secret", "nestjs-jwt-secret",
    "fastapi", "fastapi-secret", "fastapi-jwt-secret",
    "rails-secret", "rails_secret_key_base",
    "auth0", "auth0-secret", "okta-secret",
    "passport", "passport-jwt", "passport-secret",
    "jsonwebtoken", "json-web-token",

    # ── Strong-sounding but standard bad ──
    "P@ssw0rd", "P@ssw0rd!", "Pa$$w0rd", "Passw0rd",
    "Admin123!", "Admin@123", "admin@123", "Admin#2024",
    "Secret123!", "Secret@2024", "SuperSecret123",
    "Password123!", "Password@123",

    # ── Year-suffixed (common rotation laziness) ──
    "secret2023", "secret2024", "secret2025",
    "password2024", "admin2024", "jwt2024",

    # ── App-name placeholders ──
    "myapp", "myappkey", "myproject", "myproject-secret",
    "appkey", "app-key", "app_key", "APP_KEY",
    "api-secret", "api_secret", "API_SECRET", "apisecret",
    "api-key", "api_key", "API_KEY", "apikey",
    "key", "Key", "KEY",
    "token", "Token", "TOKEN",
    "auth", "auth-key", "auth_secret",

    # ── Hex / random-looking but actually static across docs ──
    "0123456789abcdef0123456789abcdef",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabe",

    # ── Project-name keywords (catch GitHub-leaked defaults) ──
    "company-name", "companyname", "company-secret",
    "product-name", "production-secret", "production",
    "staging", "staging-secret", "dev", "development",
    "internal", "internal-secret",
    "backend", "backend-secret",
    "frontend", "frontend-secret",

    # ── Random English + numbers (common human picks) ──
    "hello", "hello123", "world", "helloworld",
    "trust", "trustno1", "trust-me",
    "ninja", "dragon", "shadow", "master",
    "iloveyou", "princess", "sunshine",

    # ── Brand + role combos ──
    "github", "gitlab", "bitbucket",
    "google", "facebook", "twitter", "instagram",
    "amazon", "microsoft", "apple",

    # ── JWT-tool / kali standard short list (subset) ──
    "Sn1f", "0r3o", "default",
)
