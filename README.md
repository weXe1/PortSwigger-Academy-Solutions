# PortSwigger Web Security Academy Solutions

Scripts and exploits to help solve lab assignments at PortSwigger Web Security Academy

## SQLi

### UNION based

- [Finding amount of columns in table](SQLi/column-number-finder.pl)

### Blind

- [Lab: Blind SQL injection with conditional responses](SQLi/blind-conditional-responses.pl)
- [Lab: Blind SQL injection with conditional errors](SQLi/blind-conditional-errors.pl)
- [Lab: Blind SQL injection with time delays and information retrieval](SQLi/blind-time-delays.pl)

## CSRF

- [Lab: CSRF where token validation depends on token being present](CSRF/csrf_is_token_present.html)
- [Lab: CSRF where token is not tied to user session](CSRF/csrf_is_token_present.html)
- [Lab: CSRF where token is tied to non-session cookie](CSRF/csrf_tied_cookie.html)
- [Lab: CSRF where token is duplicated in cookie](CSRF/csrf_duplicated_in_cookie.html)
- [Lab: SameSite Lax bypass via method override](CSRF/csrf_lax_method_override.html)
- [Lab: SameSite Strict bypass via client-side redirect](CSRF/csrf_strict_redirects.html)
- [Lab: SameSite Lax bypass via cookie refresh](CSRF/csrf_cookie_refresh.html)

## WebSockets

- [Lab: Cross-site WebSocket hijacking](WebSockets/cross_site_websocket_hijacking.html)
