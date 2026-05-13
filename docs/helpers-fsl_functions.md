# Core helper functions (`lib/fsl_functions.php`)

Encryption, sessions, XSS, JWT, HTTP client, CSRF, hashing, and optional Google OAuth / TinyURL utilities. Requires `option('global_encryption_key')` (and related options) where noted.

---

## Session hardening

### `fsl_init_secure_session(): void`

Applies secure PHP session settings (`httponly`, `secure`, `SameSite=Strict`, strict mode) and calls `session_start()` with a one-hour GC lifetime. Use when you manage sessions manually outside Limonade’s `option('session', …)` flow.

---

## Encryption

### `fsl_encrypt(string $string, ?string $key = null): string`

AES-256-CBC encrypts `$string`. Uses `option('global_encryption_key')` when `$key` is omitted. Returns **ciphertext + `:` + base64(IV)** (do not strip the IV portion).

Throws `RuntimeException` if the key is missing, still set to the placeholder `setyourkeyhere`, or if OpenSSL fails.

In `ENV_DEVELOPMENT`, triggers `E_USER_WARNING` if the demo default key from the repo is still in use.

### `fsl_decrypt(string $string, ?string $key = null): string`

Decrypts a string produced by `fsl_encrypt`. Same key resolution as encrypt. Throws if format is invalid, key is wrong, or decryption fails.

---

## XSS

### `fsl_scrub(string $string): string`

Runs the bundled `xss_filter` over `$string`. Use for untrusted text before storing or displaying (in addition to output escaping such as `h()` in views).

---

## Encrypted session values

Values are stored **encrypted** in `$_SESSION` using `fsl_encrypt`. Requires a valid `global_encryption_key` and an active PHP session (`option('session', …)` or manual `session_start`).

### `fsl_session_set(string $name, string $value, ?int $timeout = null): bool`

Stores `$value` under `$_SESSION[$name]`. Optionally sets `$_SESSION[$name . '_timeout']` to `time() + $timeout`. Regenerates the session ID periodically for fixation hardening.

### `fsl_session_check(string $name, ?string $value = null, ?int $timeout = null): mixed`

Returns the decrypted string if present and not expired; otherwise `false` (and clears the slot via `fsl_session_kill`). If `$value` or `$timeout` is passed, updates the stored value and/or timeout.

### `fsl_session_kill(string $name): bool`

Removes `$name` and its timeout key. If `$name === '*'`, clears the session array, expires the session cookie, and calls `session_destroy()`.

---

## JWT

Implemented via `JWT` class from `lib/jwt_helper.php` (loaded with other `lib/` files).

### `fsl_jwt_encode($array, $key)`

Encodes `$array` as a signed JWT string using `$key`.

### `fsl_jwt_decode($token, $key)`

Decodes and verifies `$token` with `$key`. Returns the payload structure provided by the JWT helper (typically an object or array depending on library version).

---

## URL shortening

### `fsl_get_tiny_url($url)`

**Legacy name in code:** `fsl_get_tiny_url` (comment block says `get_tiny_url`). Calls the TinyURL API and returns a shortened URL string (normalizes scheme to `https:` when the API returned `http:`).

---

## Google OAuth (optional)

These expect Google API PHP client classes (`Google_Client`, `Google_Oauth2Service`) and options: `clientId`, `clientSecret`, `redirectURL`. They are legacy helpers; verify behavior against your Google Cloud OAuth client before production use.

### `fsl_gauth_check(): bool`

Returns whether `$_SESSION['glogin'] == 1`.

### `fsl_gauth_getauthurl()`

Builds `Google_Client`, sets app options, returns `createAuthUrl()` for a “Sign in with Google” link.

### `fsl_gauth_gettoken()`

Handles OAuth callback (`$_GET['code']`), token storage, and profile fetch. Contains site-specific redirect logic; review and adapt before use.

---

## Password hashing

Uses the `Password` helper class from the FSL `lib` tree.

### `fsl_hash_create($string): string`

Creates a one-way hash suitable for storing passwords (implementation wraps `Password::create_hash`).

### `fsl_hash_validate($string, $good_hash): bool`

Returns whether `$string` matches the stored hash (`Password::validate_password`).

---

## HTTP client

### `fsl_curl(...) : array`

Makes an outbound HTTPS/HTTP request with cURL. Validates URL, enables SSL verification, 30s timeout, does **not** follow redirects by default.

**Positional signature:**

```php
function fsl_curl(
    string $url,
    string $method = 'GET',
    ?string $datatype = null,
    ?string $urlparams = null,
    mixed $postdata = null,
    ?string $authtype = null,
    ?string $authuser = null,
    ?string $authpassword = null,
    ?string $authtoken = null,
    ?array $customheader = null
): array
```

**Return value:** three-element array:

1. **HTTP status code** (int)  
2. **cURL info** array from `curl_getinfo()`  
3. **Raw response body** (string)

**`$method`:** `GET`, `POST`, `PUT`, or `DELETE` (others fall through to GET-like behavior; POST sets `CURLOPT_POSTFIELDS` from `$postdata`).

**`$datatype`:** sets `Content-Type` on the request:

| Value | Header |
|-------|--------|
| `JSON` | `application/json` |
| `XML` | `application/xml` |
| `FORM` | `application/x-www-form-urlencoded` |
| `null` | `*/*` |

**`$urlparams`:** query string **without** leading `?`; appended as `$url . '?' . $urlparams`.

**Auth:**

- `authtype: 'BASIC'` — use `authuser` + `authpassword`.
- `authtype: 'TOKEN'` — sends `Authorization: Bearer {authtoken}`.

**`$customheader`:** array of full header lines (e.g. `'x-api-key: …'`). Merged with defaults (User-Agent + Content-Type + Bearer if set).

**Named-argument examples** (as used elsewhere in FSL):

```php
[$code, $info, $body] = fsl_curl(
    url: 'https://api.example.com/v1/resource',
    method: 'POST',
    datatype: 'JSON',
    postdata: json_encode(['name' => 'Alice']),
    authtype: 'TOKEN',
    authtoken: $token,
);
```

---

## CSRF

### `fsl_csrf_token(): string`

Returns a per-session random token (hex). Creates `$_SESSION['_fsl_csrf_token']` on first use.

### `fsl_csrf_validate(string $token): bool`

Timing-safe compare of `$token` to the stored session token. Returns `false` if no token was ever issued.

Typical form field:

```html
<input type="hidden" name="_csrf_token" value="<?php echo h(fsl_csrf_token()); ?>">
```

Handler:

```php
if (!fsl_csrf_validate((string) ($_POST['_csrf_token'] ?? ''))) {
    status(HTTP_BAD_REQUEST);
    return json(['error' => 'Invalid CSRF token']);
}
```

---

## Quick reference

| Function | Purpose |
|----------|---------|
| `fsl_init_secure_session` | Strict `session_start()` defaults |
| `fsl_encrypt` / `fsl_decrypt` | AES-256-CBC with IV in ciphertext string |
| `fsl_scrub` | XSS filter on input |
| `fsl_session_set` / `fsl_session_check` / `fsl_session_kill` | Encrypted session payload + optional TTL |
| `fsl_jwt_encode` / `fsl_jwt_decode` | JWT sign/verify |
| `fsl_get_tiny_url` | TinyURL shorten |
| `fsl_gauth_check` / `fsl_gauth_getauthurl` / `fsl_gauth_gettoken` | Google OAuth (optional / legacy) |
| `fsl_hash_create` / `fsl_hash_validate` | Password-style hashing |
| `fsl_curl` | Outbound HTTP(S) with JSON/XML/form, Basic, Bearer, custom headers |
| `fsl_csrf_token` / `fsl_csrf_validate` | CSRF token issue and verify |

See also: [helpers-ai.md](helpers-ai.md), [helpers-mcp.md](helpers-mcp.md).
