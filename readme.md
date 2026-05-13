# FSL - Fresh Squeezed Limonade

FSL is a lightweight PHP micro-framework for building REST APIs, microservices, and web applications. It provides clean URL routing, multiple response types, lifecycle hooks, sessions, encryption, and an HTTP client — all in a small, dependency-free package.

**Requirements:** PHP 8.0+

---

## Quick Start

```php
<?php
require 'lib/fsl.php';

function configure() {
    option('env', ENV_DEVELOPMENT);
}

dispatch('/', function() {
    return html('<h1>Hello, FSL!</h1>');
});

run();
```

Point your web server at the project root, or run `php -S localhost:8080` for local development.

---

## Why FSL?

- **Minimal footprint** — one `require` and you're routing. No Composer required.
- **REST-first** — native JSON responses, HTTP method routing, and status code helpers.
- **Built-in security** — AES-256-CBC encryption, encrypted sessions, CSRF protection.
- **AI-ready** — built-in helpers for Anthropic and OpenAI APIs, plus MCP server support.
- **Flexible rendering** — HTML templates, JSON, XML, plain text, CSS, JS from one framework.

---

## Installation

Clone or download the repository:

```bash
git clone https://github.com/yesinteractive/fsl.git
cd fsl
```

No Composer, no dependencies. Drop the files into your project and `require 'lib/fsl.php'`.

---

## Directory Structure

```
fsl/
├── lib/
│   ├── fsl.php               # Core framework — require this
│   ├── fsl_functions.php     # Helper functions (encryption, sessions, curl, etc.)
│   ├── fsl_ai_functions.php  # AI/LLM helpers (Anthropic, OpenAI)
│   ├── fsl_mcp_functions.php # MCP server support
│   └── jwt_helper.php        # JWT encode/decode
├── config/
│   └── fsl_config.php        # App configuration (configure() function)
├── controllers/
│   └── fsl_controllers.php   # Route handlers
├── views/
│   └── *.php                 # HTML templates
└── index.php                 # Entry point
```

All files in `lib/` are auto-loaded — drop a new `.php` file there and its functions are immediately available.

---

## Configuration

Configuration lives in `configure()` inside `config/fsl_config.php`. FSL calls this automatically on startup.

```php
function configure() {
    option('env', ENV_DEVELOPMENT);     // ENV_DEVELOPMENT or ENV_PRODUCTION
    option('base_uri', '/');            // Set to subdirectory if not in web root
    option('session', 'myapp');         // Session name; omit to disable sessions
    option('fsl_session_length', 300);  // Session timeout in seconds
    option('global_encryption_key', 'your-base64-key-here');
}
```

Generate an encryption key:

```bash
php -r "echo base64_encode(random_bytes(32));"
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `env` | `ENV_PRODUCTION` | `ENV_DEVELOPMENT` enables error display |
| `base_uri` | `/` | URL prefix when app is in a subdirectory |
| `session` | `null` | Session name; `null` disables sessions |
| `fsl_session_length` | `300` | Session lifetime in seconds |
| `global_encryption_key` | — | Base64 AES-256 key for `fsl_encrypt`/`fsl_session_set` |
| `gzip` | `false` | Enable gzip output compression |
| `views_dir` | `views/` | Directory for HTML templates |
| `controllers_dir` | `controllers/` | Directory for controller files |
| `lib_dir` | `lib/` | Directory for auto-loaded libraries |

---

## Routing

### Basic Routing

```php
dispatch('/', 'home');              // any method
dispatch_get('/users', 'list_users');
dispatch_post('/users', 'create_user');
dispatch_put('/users/:id', 'update_user');
dispatch_patch('/users/:id', 'patch_user');
dispatch_delete('/users/:id', 'delete_user');
```

The second argument is a controller function name or an anonymous function:

```php
dispatch_get('/ping', function() {
    return json(['status' => 'ok']);
});
```

### URL Parameters

```php
dispatch_get('/users/:id', 'get_user');

function get_user() {
    $id = params('id');   // named param
    // ...
}
```

### Wildcards

```php
dispatch('/files/*', 'serve_file');       // * matches a single path segment
dispatch('/assets/**', 'serve_assets');   // ** matches multiple path segments
```

Access wildcard values with `params(0)`, `params(1)`, etc.

Named wildcards:

```php
dispatch(array('/users/:id/posts/*', 'post_slug'), 'get_post');
// params('id'), params('post_slug')
```

### Regex Routes

```php
dispatch('^/products/([0-9]+)$', 'get_product');
// params(0) = first capture group
```

### Query String & POST Data

```php
$q    = params('q');           // $_GET or $_POST
$page = params('page') ?? 1;
```

---

## Responses

### Content Types

| Function | Content-Type | Notes |
|----------|-------------|-------|
| `html($content)` | `text/html` | Wrap a string or template output |
| `json($data)` | `application/json` | Accepts array or string |
| `xml($content)` | `text/xml` | |
| `css($content)` | `text/css` | |
| `js($content)` | `text/javascript` | |
| `txt($content)` | `text/plain` | |

```php
// JSON response
function list_users() {
    return json(['users' => user_find_all()]);
}

// HTML template
function show_user() {
    $user = user_find(params('id'));
    return html(render('user_show', ['user' => $user]));
}
```

### Status Codes

```php
status(201);          // set HTTP status code
status(404);
```

### Redirects

```php
redirect_to('/login');                   // 302 redirect
redirect_to('/dashboard', array(), 301); // 301 redirect
```

### Errors

```php
halt(NOT_FOUND, 'User not found');     // 404
halt(SERVER_ERROR, 'DB unavailable');  // 500
halt(FORBIDDEN);                       // 403
```

Constants: `OK` (200), `CREATED` (201), `NO_CONTENT` (204), `MOVED` (301), `FOUND` (302), `NOT_MODIFIED` (304), `BAD_REQUEST` (400), `UNAUTHORIZED` (401), `FORBIDDEN` (403), `NOT_FOUND` (404), `SERVER_ERROR` (500).

---

## Templates

Templates are PHP files in the `views/` directory.

```php
// Controller
function show_profile() {
    return html(render('profile', ['name' => 'Alice', 'age' => 30]));
}

// views/profile.php
<h1><?php echo h($name); ?></h1>
<p>Age: <?php echo $age; ?></p>
```

### Template Helpers

| Helper | Description |
|--------|-------------|
| `h($str)` | HTML-escape a string (alias for `htmlspecialchars`) |
| `url_for($path, $params)` | Build a URL with query string (ampersands are HTML-encoded) |
| `partial($template, $vars)` | Include a sub-template |
| `flash_now($name, $msg)` | Set a flash message for the current request |
| `flash($name)` | Read and clear a flash message |

### Layouts

```php
// views/layout.php
<html><body>
  <?php echo $content; ?>
</body></html>

// In configure():
option('layout', 'layout');
```

### File Rendering

```php
return render_file('/path/to/file.html'); // send any file as HTML response
```

---

## Lifecycle Hooks

| Hook | When it runs |
|------|--------------|
| `configure()` | Once at startup — set options, open DB connections |
| `initialize()` | After configure, before routing — app-level setup |
| `before()` | Before every request — auth checks, logging |
| `after()` | After every request |
| `before_render($content)` | Before rendering output — modify content |
| `autorender($action_result)` | Custom rendering logic |
| `before_exit()` | Just before script exits |
| `before_sending_header($header)` | Intercept headers before sending |

```php
function before() {
    if (!is_logged_in() && request_uri() !== '/login') {
        redirect_to('/login');
    }
}

function after() {
    log_request(request_method(), request_uri(), status());
}
```

---

## Sessions

### Native Sessions

```php
// In configure():
option('session', 'myapp');

// Use $_SESSION directly:
$_SESSION['user_id'] = 42;
$id = $_SESSION['user_id'];
```

### Encrypted Sessions

`fsl_session_set` / `fsl_session_get` encrypt values with AES-256-CBC before storing in `$_SESSION`:

```php
fsl_session_set('user', ['id' => 42, 'role' => 'admin']);
$user = fsl_session_get('user');
```

Requires `global_encryption_key` to be set in `configure()`.

---

## FSL Helper Functions

### Encryption

```php
$encrypted = fsl_encrypt('secret data');  // returns base64-encoded ciphertext
$plain     = fsl_decrypt($encrypted);     // returns original string
```

Uses AES-256-CBC with the `global_encryption_key` from config.

### CSRF Protection

```php
// In your form template:
<input type="hidden" name="_csrf_token" value="<?php echo fsl_csrf_token(); ?>">

// In your form handler:
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

---

## AI / LLM Helpers

FSL includes thin wrappers for the Anthropic and OpenAI chat APIs. Configure your keys in `config/fsl_config.php`:

```php
function configure() {
    option('anthropic_api_key', getenv('ANTHROPIC_API_KEY'));
    option('anthropic_model',   'claude-sonnet-4-6');

    option('openai_api_key', getenv('OPENAI_API_KEY'));
    option('openai_model',   'gpt-4o');
}
```

### Anthropic

```php
$response = fsl_anthropic_chat([
    ['role' => 'user', 'content' => 'Summarize this in one sentence: ' . $text]
]);
$answer = $response['content'][0]['text'];
```

With a system prompt and model override:

```php
$response = fsl_anthropic_chat(
    messages:   [['role' => 'user', 'content' => $question]],
    model:      'claude-opus-4-7',
    max_tokens: 2048,
    system:     'You are a helpful assistant. Be concise.'
);
```

### OpenAI

```php
$response = fsl_openai_chat([
    ['role' => 'system', 'content' => 'You are a helpful assistant.'],
    ['role' => 'user',   'content' => $question]
]);
$answer = $response['choices'][0]['message']['content'];
```

Both functions return the full decoded API response array and throw `RuntimeException` on missing keys or non-2xx responses.

---

## MCP Server

FSL can act as a [Model Context Protocol](https://modelcontextprotocol.io) server, exposing your app's functions as tools that AI agents (Claude Desktop, Cursor, etc.) can call directly.

### Minimal MCP Server

```php
<?php
require 'lib/fsl.php';

fsl_mcp_tool(
    name: 'get_user',
    description: 'Look up a user by ID',
    schema: [
        'type'       => 'object',
        'properties' => ['id' => ['type' => 'integer', 'description' => 'User ID']],
        'required'   => ['id']
    ],
    callback: function(array $args): array {
        return user_find($args['id']);
    }
);

dispatch_post('/', 'fsl_mcp_handle');
run();
```

That's a complete, spec-compliant MCP server.

### How It Works

`fsl_mcp_handle()` is a standard FSL controller that handles JSON-RPC 2.0 requests from AI agents:

| JSON-RPC Method | What FSL does |
|-----------------|---------------|
| `initialize` | Returns server name, version, and capabilities |
| `tools/list` | Returns all registered tools with their schemas |
| `tools/call` | Calls the matching tool callback with the provided arguments |

### Registering Multiple Tools

```php
fsl_mcp_tool(
    name: 'search_products',
    description: 'Search the product catalog',
    schema: [
        'type'       => 'object',
        'properties' => [
            'query' => ['type' => 'string', 'description' => 'Search term'],
            'limit' => ['type' => 'integer', 'description' => 'Max results (default 10)'],
        ],
        'required' => ['query']
    ],
    callback: function(array $args): array {
        return product_search($args['query'], $args['limit'] ?? 10);
    }
);

fsl_mcp_tool(
    name: 'get_order',
    description: 'Retrieve an order by order ID',
    schema: [
        'type'       => 'object',
        'properties' => ['order_id' => ['type' => 'string']],
        'required'   => ['order_id']
    ],
    callback: function(array $args): array {
        return order_find($args['order_id']);
    }
);

dispatch_post('/', 'fsl_mcp_handle');
run();
```

### Server Name

Set a custom server name shown to AI agents during the handshake:

```php
option('mcp_server_name', 'My Product API');
```

### Adding Auth

Use FSL's `before()` hook to add authentication:

```php
function before() {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($token !== 'Bearer ' . option('mcp_api_key')) {
        halt(UNAUTHORIZED, 'Invalid token');
    }
}
```
