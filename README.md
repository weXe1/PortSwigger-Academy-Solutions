# PortSwigger Web Security Academy Solutions

Scripts and exploits to help solve lab assignments at PortSwigger Web Security Academy

## Server-side topics

### SQLi

#### UNION based

- [Finding amount of columns in table](SQLi/column-number-finder.pl)

#### Blind

- [Lab: Blind SQL injection with conditional responses](SQLi/blind-conditional-responses.pl)
- [Lab: Blind SQL injection with conditional errors](SQLi/blind-conditional-errors.pl)
- [Lab: Blind SQL injection with time delays and information retrieval](SQLi/blind-time-delays.pl)

### Authentication

- [Lab: Broken brute-force protection, IP block](Authentication/broken-brute-force-protection.pl)
- [Lab: Username enumeration via account lock](Authentication/account-lock-brute-password.pl)
- [Lab: 2FA broken logic](Authentication/2fa-broken-logic.pl)
- [Lab: Brute-forcing a stay-logged-in cookie](Authentication/stay-logged-in-cookie.pl)

### Business logic vulnerabilities

- [Lab: Infinite money logic flaw](Business_logic_vulnerabilities/infinite-money.pl)

### File upload vulnerabilities

- [Lab: Remote code execution via web shell upload](File_upload_vulnerabilities/rce_webshell.php)
- [Lab: Web shell upload via extension blacklist bypass](File_upload_vulnerabilities/.htaccess)
- [Lab: Remote code execution via polyglot web shell upload](File_upload_vulnerabilities/exploit.php)

### SSRF

- [Lab: Basic SSRF against another back-end system](SSRF/basic-ssrf-another-system.pl)

## Client-side topics

### CSRF

- [Lab: CSRF where token validation depends on token being present](CSRF/csrf_is_token_present.html)
- [Lab: CSRF where token is not tied to user session](CSRF/csrf_is_token_present.html)
- [Lab: CSRF where token is tied to non-session cookie](CSRF/csrf_tied_cookie.html)
- [Lab: CSRF where token is duplicated in cookie](CSRF/csrf_duplicated_in_cookie.html)
- [Lab: SameSite Lax bypass via method override](CSRF/csrf_lax_method_override.html)
- [Lab: SameSite Strict bypass via client-side redirect](CSRF/csrf_strict_redirects.html)
- [Lab: SameSite Lax bypass via cookie refresh](CSRF/csrf_cookie_refresh.html)
- [Lab: CSRF where Referer validation depends on header being present](CSRF/csrf_referer_present.html)
- [Lab: CSRF with broken Referer validation](CSRF/csrf_referer_broken.html)

### WebSockets

- [Lab: Cross-site WebSocket hijacking](WebSockets/cross_site_websocket_hijacking.html)
