"""Tier-1 per-vuln-class methodology deep-links (verified static HTML)."""

from __future__ import annotations


# Tier 1 — per-class methodology deep-links (verified static HTML).
_METHODOLOGY_LINKS: dict[str, dict[str, str]] = {
    "sqli": {
        "portswigger": "https://portswigger.net/web-security/sql-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/sql-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    },
    "xss": {
        "portswigger": "https://portswigger.net/web-security/cross-site-scripting",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
    },
    "ssrf": {
        "portswigger": "https://portswigger.net/web-security/ssrf",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
    },
    "ssti": {
        "portswigger": "https://portswigger.net/web-security/server-side-template-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    },
    "idor": {
        "portswigger": "https://portswigger.net/web-security/access-control",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/idor",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    },
    "rce": {
        "portswigger": "https://portswigger.net/web-security/os-command-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/command-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
    },
    "csrf": {
        "portswigger": "https://portswigger.net/web-security/csrf",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
    },
    "xxe": {
        "portswigger": "https://portswigger.net/web-security/xxe",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
    },
    "race_condition": {
        "portswigger": "https://portswigger.net/web-security/race-conditions",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/race-condition",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition",
        "owasp":       "",
    },
    "request_smuggling": {
        "portswigger": "https://portswigger.net/web-security/request-smuggling",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling",
        "owasp":       "",
    },
    "deserialization": {
        "portswigger": "https://portswigger.net/web-security/deserialization",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/deserialization",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization",
        "owasp":       "",
    },
    "open_redirect": {
        "portswigger": "https://portswigger.net/web-security/all-labs#open-redirection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/open-redirect",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
    },
    "prototype_pollution": {
        "portswigger": "https://portswigger.net/web-security/prototype-pollution",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution",
        "owasp":       "",
    },
    "auth_bypass": {
        "portswigger": "https://portswigger.net/web-security/authentication",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/login-bypass",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
    },
    "graphql": {
        "portswigger": "https://portswigger.net/web-security/graphql",
        "hacktricks":  "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection",
        "owasp":       "",
    },
    "websocket": {
        "portswigger": "https://portswigger.net/web-security/websockets",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/websocket-attacks",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
    },
    "cors": {
        "portswigger": "https://portswigger.net/web-security/cors",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/cors-bypass",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Cross_Origin_Resource_Sharing",
    },
    "business_logic": {
        "portswigger": "https://portswigger.net/web-security/business-logic-vulnerabilities",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/business-logic-vulnerabilities",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README",
    },
}
