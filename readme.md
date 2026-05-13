## FSL: Fresh Squeezed Limonade PHP Micro-Framework
![FSL banner](https://raw.githubusercontent.com/yesinteractive/fsl/master/public/banner-fsl.png "FSL Fresh Squeezed Limonade PHP Microframework for Microservices")

[![GitHub release](https://img.shields.io/github/release/yesinteractive/fsl?style=for-the-badge)](https://github.com/yesinteractive/fsl)
![MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![PHP from Packagist](https://img.shields.io/packagist/php-v/fsl/fsl?style=for-the-badge)

FSL is a lightweight PHP micro-framework for building web apps, REST APIs, and microservices. It runs great in Docker, K8s, and OpenShift.

---

## Quick Start

```php
<?php
require 'lib/fsl.php';

dispatch('/', function() {
    return html('Hello, world!');
});

dispatch_post('/greet/:name', function() {
    $name = params('name');
    return json(['message' => "Hello, $name!"]);
});

run();
```

That's it. Include one file, define routes, call `run()`.

---

## Why FSL?

- **Zero setup overhead** — one `require`, no boilerplate, no config required to get started
- **Flexible callbacks** — routes accept functions, closures, static methods, or object methods
- **Built-in security helpers** — AES-256-CBC encryption, secure sessions, XSS filtering, CSRF tokens, password hashing, JWT
- **REST-ready** — full HTTP verb support (GET, POST, PUT, PATCH, DELETE), JSON responses, built-in HTTP client
- **Docker-friendly** — official Docker image available, works out of the box in containerized environments
- **No framework lock-in** — plain PHP templates, no ORM required, bring your own database layer

---

## Installation

### Docker

```bash
docker pull yesinteractive/fsl

# Expose HTTP on 8100, HTTPS on 8143
docker run -d -p 8100:80 -p 8143:443 yesinteractive/fsl
```

Use as a base image:

```dockerfile
FROM yesinteractive/fsl
RUN echo <your commands here>
```

### Composer

```bash
composer require fsl/fsl
```

Then include the autoloader:

```php
require 'vendor/autoload.php';
```

### Without Composer

Download the repo and include the main file directly:

```php
require 'lib/fsl.php';
```

FSL requires **PHP 8.0 or newer**.

---

## Project Setup

> Skip to step 4 if using the FSL Docker image — it handles steps 1–3 automatically.

1. **Apache — enable mod_rewrite** and set `AllowOverride All` on your app directory so the included `.htaccess` is read.

2. **Subdirectory installs** — if FSL is not in your web root, update the `RewriteBase` in `.htaccess`:
    ```
    RewriteBase /myapp
    ```

3. **Nginx** — add to your server block:
    ```nginx
    location / { try_files $uri $uri/ @rewrite; }
    location @rewrite { rewrite ^/(.*)$ /index.php?u=$1&$args; }
    ```

4. **Config** — edit `config/fsl_config.php`. If installed in a subdirectory, set:
    ```php
    option('base_uri', '/myapp');
    ```
    Generate and set a unique encryption key:
    ```bash
    php -r "echo base64_encode(random_bytes(32));"
    ```
    ```php
    option('global_encryption_key', 'your-generated-key-here');
    ```

5. Open a browser and hit your install URL. The example app (`index.php`) includes working demo routes.

---

## Routing

Routes map an HTTP method + URL pattern to a callback. They are matched in the order declared.

```php
dispatch('/', 'my_function');           // GET (default)
dispatch_get('/users', 'list_users');
dispatch_post('/users', 'create_user');
dispatch_put('/users/:id', 'update_user');
dispatch_patch('/users/:id', 'patch_user');
dispatch_delete('/users/:id', 'delete_user');

run();
```

### URL Patterns

| Pattern | Example match | Access value |
|---------|--------------|______________|
| `/hello/:name` | `/hello/alice` | `params('name')` → `'alice'` |
| `/files/*.*` | `/files/readme.txt` | `params(0)` → `'readme'`, `params(1)` → `'txt'` |
| `/writing/*/to/*` | `/writing/email/to/bob` | `params(0)`, `params(1)` |
| `/files/**` | `/files/a/b/c.txt` | `params(0)` → `'a/b/c.txt'` |
| `^/items/(\d+)` | `/items/42` | `params(0)` → `'42'` |

Named wildcards:

```php
dispatch(array('/say/*/to/**', array('what', 'name')), 'greet');
function greet() {
    // GET /say/hello/to/alice
    $what = params('what'); // 'hello'
    $name = params('name'); // 'alice'
}
```

Default parameter values:

```php
dispatch('/hello/:name', 'hello', ['params' => ['greeting' => 'Hi']]);
function hello($greeting, $name) {
    return html("$greeting, $name!");
}
```

### Callback Types

```php
dispatch('/a', 'my_function');              // named function
dispatch('/b', 'MyClass::method');          // static method
dispatch('/c', [$obj, 'method']);           // object method
dispatch('/d', ['MyClass', 'method']);      // static method (array form)
dispatch('/e', function() {                 // closure
    return html('Hello!');
});
```

### HTML Form Method Override

HTML forms only support GET and POST. Use a hidden `_method` field to send PUT, PATCH, or DELETE:

```html
<form method="post" action="<?php echo url_for('/users/42'); ?>">
    <input type="hidden" name="_method" value="PUT">
    <!-- fields -->
    <button type="submit">Update</button>
</form>
```

### Controllers Directory

Callbacks can live in any PHP file inside `controllers/` — FSL auto-loads that directory before executing a route. Organize freely:

```
index.php          ← routes + run()
controllers/
  users.php        ← user_list(), user_show(), user_create() ...
  posts.php        ← post_index(), post_show() ...
```

Custom load path:

```php
option('controllers_dir', __DIR__ . '/src/controllers');
```

Custom loader (e.g. load admin controllers from a sub-folder):

```php
function autoload_controller($callback) {
    $path = option('controllers_dir');
    if (str_starts_with($callback, 'admin_')) $path .= '/admin';
    require_once_dir($path);
}
```

---

## Views & Templates

### Passing Variables

```php
// Set variables before rendering
set('title', 'My Page');
set('items', $array);
return render('page.html.php'); // variables available in template

// Or pass inline
return render('page.html.php', null, ['title' => 'My Page']);

// Set with a fallback default
set_or_default('name', params('name'), 'Guest');
```

### Layouts

```php
// Set a layout globally (e.g. in before())
layout('default_layout.php');

// Override per render
return render('page.html.php', 'custom_layout.php');

// Render without layout
return render('page.html.php', null);
```

In your layout file, `$content` contains the rendered view output:

```php
<body>
  <main><?php echo $content; ?></main>
</body>
```

### Content Types

Each function sets the correct `Content-Type` header and works the same as `render()`:

| Function | Content-Type | Notes |
|----------|-------------|-------|
| `html($view)` | `text/html` | Most common — use for pages |
| `json($data)` | `application/json` | Encodes data with `json_encode()`, UTF-8 safe |
| `xml($view)` | `text/xml` | |
| `css($view)` | `text/css` | |
| `js($view)` | `application/javascript` | |
| `txt($view)` | `text/plain` | |

```php
// JSON response
return json(['status' => 'ok', 'count' => 42]);

// JSON with custom encode flags
return json($data, JSON_PRETTY_PRINT);

// File download / static file
render_file(option('public_dir') . '/report.pdf');
```

### Inline Templates

A function can be used as a template instead of a file:

```php
function view_hello($vars) { extract($vars); ?>
    <h1>Hello, <?php echo h($name); ?>!</h1>
<?php }

// In your controller:
set('name', 'Alice');
return render('view_hello');
```

### Partials

Renders a view with no layout — useful for reusable blocks:

```php
// These are equivalent:
return partial('_sidebar.php', ['links' => $links]);
return render('_sidebar.php', null, ['links' => $links]);
```

### Content Captures

Capture blocks in a view for use in the layout:

```php
// In your view:
<?php content_for('sidebar'); ?>
  <ul><li>Item 1</li></ul>
<?php end_content_for(); ?>

// In your layout:
<aside><?php if (isset($sidebar)) echo $sidebar; ?></aside>
```

### Template Helpers

| Function | Description |
|----------|-------------|
| `h($string)` | HTML-escape a string (`htmlspecialchars` wrapper) — always use on user data |
| `url_for('path', 'segments')` | Build a URL relative to `base_uri` — returns HTML-safe `&amp;` separators |
| `partial($file, $locals)` | Render a sub-template with no layout |
| `flash_now($name)` | Read a flash message in the current view |

```php
// url_for examples
url_for('/users', '42');                          // ?/users/42  (or /users/42 with rewriting)
url_for('/search', ['q' => 'php', 'page' => 2]); // ?/search&amp;q=php&amp;page=2
```

---

## Configuration & Options

Define a `configure()` function in `config/fsl_config.php` — FSL calls it automatically at startup:

```php
function configure() {
    option('env', ENV_PRODUCTION);   // ENV_PRODUCTION or ENV_DEVELOPMENT
    option('base_uri', '/');
    option('session', 'myapp');      // session name, or false to disable
    option('global_encryption_key', 'your-key-here');
    option('fsl_session_length', 300); // session timeout in seconds

    // Database example (PDO)
    try {
        $db = new PDO('mysql:host=localhost;dbname=mydb;charset=utf8mb4', 'user', 'pass');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        option('db', $db);
    } catch (PDOException $e) {
        halt(SERVER_ERROR, $e->getMessage());
    }
}
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `env` | `ENV_PRODUCTION` | `ENV_PRODUCTION` or `ENV_DEVELOPMENT` |
| `base_uri` | auto-detected | Override if using URL rewriting or a subdirectory |
| `session` | session name string | Session name, `true` to enable with default name, `false` to disable |
| `encoding` | `'utf-8'` | Response character encoding |
| `debug` | `true` | Show PHP errors |
| `gzip` | `false` | Enable gzip output compression |
| `views_dir` | `ROOT/views/` | Template files location |
| `controllers_dir` | `ROOT/controllers/` | Controller files location |
| `lib_dir` | `ROOT/lib/` | Auto-loaded PHP library directory |
| `public_dir` | `ROOT/public/` | Static assets directory |
| `error_views_dir` | FSL internal views | Override error page templates |
| `global_encryption_key` | — | Key for `fsl_encrypt()` / session encryption |
| `fsl_session_length` | `300` | Encrypted session timeout in seconds |

`option()` also works as a general key/value store for your own app settings:

```php
option('api_base_url', 'https://api.example.com');
// later:
$url = option('api_base_url');
```

---

## Sessions & Flash

### Native Sessions

FSL starts a session automatically if `option('session')` is set (it is by default). You can use `$_SESSION` directly:

```php
$_SESSION['user_id'] = 42;
$id = $_SESSION['user_id'];
```

### FSL Encrypted Sessions

For sensitive values, use FSL's encrypted session helpers. Values are AES-256-CBC encrypted before being stored in `$_SESSION`:

```php
// Store (optionally with a timeout in seconds)
fsl_session_set('user_id', '42');
fsl_session_set('user_id', '42', 300); // expires in 5 minutes

// Retrieve — returns false if missing or timed out
$userId = fsl_session_check('user_id');
if ($userId === false) {
    redirect_to('/login');
}

// Delete one key
fsl_session_kill('user_id');

// Destroy the entire session
fsl_session_kill('*');
```

For hardened cookie settings (httponly, secure, samesite=Strict), call before session start:

```php
fsl_init_secure_session();
```

### Flash Messages

Flash values survive exactly one request — useful for form errors and success notices.

```php
// In your POST handler — set for the next request
flash('notice', 'Profile updated!');
redirect_to('/profile');

// In your view or next controller — read current request's flash
$msg = flash_now('notice');
// or in templates: $flash['notice']
```

---

## Hooks

Hooks are plain PHP functions that FSL calls automatically at defined points in the request lifecycle. Declare them anywhere before `run()`.

### `before($route)`
Runs before every request. Use it to set layouts, check auth, or pass common template variables.

```php
function before($route) {
    layout('default_layout.php');
    set('current_user', $_SESSION['user'] ?? null);
}
```

### `after($output, $route)`
Runs after every request. Receives and must return the output string. Use for output transformation.

```php
function after($output, $route) {
    // append timing comment in development
    if (option('env') === ENV_DEVELOPMENT) {
        $time = number_format(microtime(true) - LIM_START_MICROTIME, 4);
        $output .= "<!-- rendered in {$time}s -->";
    }
    return $output;
}
```

### `before_render($content, $layout, $locals, $view_path)`
Runs before the view is rendered. Return the (possibly modified) array of all four parameters.

```php
function before_render($content, $layout, $locals, $view_path) {
    // force JSON views to have no layout
    if (str_ends_with($content, '.json.php')) $layout = null;
    return [$content, $layout, $locals, $view_path];
}
```

### `autorender($route)`
Called when a controller returns `null`. Use to build convention-based rendering (e.g. render a view named after the callback).

```php
function autorender($route) {
    return html($route['callback'] . '.html.php');
}
```

### `before_exit($exit)`
Called at the start of the shutdown sequence.

```php
function before_exit($exit) {
    // close DB connections, flush logs, etc.
}
```

### `before_sending_header($header)`
Intercept any header FSL is about to send. Do not call `send_header()` unconditionally here — it will cause a loop.

```php
function before_sending_header($header) {
    if (str_contains($header, 'text/css')) {
        send_header('Cache-Control: max-age=600, public');
    }
}
```

### Hook Quick Reference

| Hook | Signature | Called when |
|------|-----------|-------------|
| `configure()` | `void` | App startup, before routes run |
| `initialize()` | `void` | After session start, before route matching |
| `autoload_controller($callback)` | `void` | After route match, to load controller files |
| `before($route)` | `void` | Before each request handler |
| `after($output, $route)` | `string` | After each request — must return `$output` |
| `before_render($content, $layout, $locals, $view_path)` | `array` | Before view rendering — must return all 4 params |
| `autorender($route)` | `string` | When controller returns `null` |
| `not_found($errno, $errstr, $errfile, $errline)` | `string` | On 404 |
| `server_error($errno, $errstr, $errfile, $errline)` | `string` | On 500 |
| `route_missing($method, $uri)` | `void` | When no route matches |
| `before_exit($exit)` | `void` | Before app shutdown |
| `before_sending_header($header)` | `void` | Before any `header()` call |

---

## Error Handling

### `halt()`

Stop execution immediately and trigger an error handler:

```php
halt(NOT_FOUND);                          // 404
halt(NOT_FOUND, "User not found.");       // 404 with message
halt(SERVER_ERROR, "Something broke.");   // 500
halt("Something broke.");                 // 500 (string shorthand)
```

PHP errors are also caught and routed to the server error handler.

### Custom 404 Handler

```php
function not_found($errno, $errstr, $errfile, $errline) {
    set('message', $errstr);
    return html('errors/404.html.php', null);
}
```

### Custom 500 Handler

```php
function server_error($errno, $errstr, $errfile, $errline) {
    $args = compact('errno', 'errstr', 'errfile', 'errline');
    return html('errors/500.html.php', error_layout(), $args);
}
```

### Map Specific Error Codes

```php
error(E_USER_WARNING, 'handle_warning');
function handle_warning($errno, $errstr, $errfile, $errline) {
    error_log("Warning $errno: $errstr");
    status(SERVER_ERROR);
    return html('<h1>Something went wrong</h1>');
}
```

`E_LIM_HTTP` matches all HTTP errors. `E_LIM_PHP` matches all PHP errors.

### HTTP Status Codes

Set a response status code before returning output:

```php
function create_user() {
    // ... create user ...
    status(201); // 201 Created
    return json(['id' => $newId]);
}
```

### Redirects

```php
redirect_to('/dashboard');                                         // 302
redirect_to('/dashboard', ['status' => HTTP_MOVED_PERMANENTLY]);   // 301
redirect_to('/users', '42', 'edit');                               // /users/42/edit
```

---

## FSL Helper Functions

All helpers are in `/lib/fsl_functions.php` and available globally once FSL is loaded.

### Encryption

AES-256-CBC. Uses `option('global_encryption_key')` by default.

```php
$encrypted = fsl_encrypt('sensitive value');
$plain     = fsl_decrypt($encrypted);

// Custom key
$encrypted = fsl_encrypt('value', $myKey);
$plain     = fsl_decrypt($encrypted, $myKey);
```

Set your key in `config/fsl_config.php` — generate with:
```bash
php -r "echo base64_encode(random_bytes(32));"
```

### XSS Filtering

```php
$clean = fsl_scrub($_POST['comment']); // strip XSS from user input
```

### Password Hashing

Uses bcrypt via the included Password helper:

```php
$hash  = fsl_hash_create('my_password');
$valid = fsl_hash_validate('my_password', $hash); // true or false
```

### JWT Tokens

```php
$payload = ['user_id' => 42, 'role' => 'admin'];
$token   = fsl_jwt_encode($payload, 'secret-key');

$decoded = fsl_jwt_decode($token, 'secret-key');
echo $decoded->user_id; // 42
```

### CSRF Protection

```php
// In your form template:
<input type="hidden" name="_csrf_token" value="<?php echo fsl_csrf_token(); ?>">

// In your POST handler:
function save_form() {
    if (!fsl_csrf_validate($_POST['_csrf_token'])) {
        halt(SERVER_ERROR, 'Invalid CSRF token.');
    }
    // safe to process...
}
```

### HTTP Client (`fsl_curl`)

Makes outbound HTTP requests. Returns `[http_code, curl_info, response_body]`.

```php
// GET
[$code, $info, $body] = fsl_curl('https://api.example.com/data');

// POST with JSON
[$code, $info, $body] = fsl_curl(
    url: 'https://api.example.com/users',
    method: 'POST',
    datatype: 'JSON',
    postdata: json_encode(['name' => 'Alice'])
);

// Bearer token auth
[$code, $info, $body] = fsl_curl(
    url: 'https://api.example.com/secure',
    authtype: 'TOKEN',
    authtoken: 'my-bearer-token'
);

// Basic auth
[$code, $info, $body] = fsl_curl(
    url: 'https://api.example.com/secure',
    authtype: 'BASIC',
    authuser: 'user',
    authpassword: 'pass'
);
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `$url` | string | required | Request URL |
| `$method` | string | `'GET'` | `GET`, `POST`, `PUT`, `DELETE` |
| `$datatype` | string\|null | `null` | `'JSON'`, `'XML'`, `'FORM'`, or `null` for `*/*` |
| `$urlparams` | string\|null | `null` | Query string appended to URL |
| `$postdata` | mixed | `null` | POST body |
| `$authtype` | string\|null | `null` | `'BASIC'` or `'TOKEN'` |
| `$authuser` | string\|null | `null` | Basic auth username |
| `$authpassword` | string\|null | `null` | Basic auth password |
| `$authtoken` | string\|null | `null` | Bearer token |
| `$customheader` | array\|null | `null` | Additional headers |
