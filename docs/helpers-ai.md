# AI / LLM helpers (`lib/fsl_ai_functions.php`)

Thin wrappers around the Anthropic Messages API and the OpenAI Chat Completions API. Both use `fsl_curl()` and read credentials from `option()`.

## Configuration

In `config/fsl_config.php` inside `configure()`:

```php
$anthropic_key = getenv('ANTHROPIC_API_KEY');
if (!is_string($anthropic_key) || $anthropic_key === '') {
    $anthropic_key = null; // optional: dev key here; prefer env in production
}
option('anthropic_api_key', $anthropic_key);

option('anthropic_model', 'claude-sonnet-4-6');           // optional override
option('anthropic_api_version', '2023-06-01');            // optional; sent as `anthropic-version` header

option('openai_api_key', getenv('OPENAI_API_KEY'));
option('openai_model', 'gpt-4o');                         // optional override
```

If `option('anthropic_api_key')` is empty, `fsl_anthropic_chat()` also checks `option('ANTHROPIC_API_KEY')` as a fallback (legacy spelling).

---

## `fsl_anthropic_chat`

Sends a conversation to [Anthropic Messages](https://docs.anthropic.com/en/api/messages).

### Signature

```php
function fsl_anthropic_chat(
    array $messages,
    ?string $model = null,
    int $max_tokens = 1024,
    ?string $system = null
): array
```

| Parameter | Description |
|-----------|-------------|
| `$messages` | List of `['role' => 'user'\|'assistant', 'content' => '...']` entries. |
| `$model` | Model id; default `option('anthropic_model')` or `claude-sonnet-4-6`. |
| `$max_tokens` | Cap on completion tokens (default `1024`). |
| `$system` | Optional system prompt (added to the JSON body as `system`). |

### Returns

Decoded JSON **array** from the API. Assistant text is typically at `$response['content'][0]['text']`.

### Errors

- `RuntimeException` if no API key is configured.
- `RuntimeException` if HTTP status is not 2xx (message includes API error text when present).

### Example

```php
$response = fsl_anthropic_chat([
    ['role' => 'user', 'content' => 'Summarize in one sentence: ' . $text],
]);
$answer = $response['content'][0]['text'];
```

Named arguments (PHP 8+):

```php
$response = fsl_anthropic_chat(
    messages: [['role' => 'user', 'content' => $question]],
    model: 'claude-opus-4-7',
    max_tokens: 2048,
    system: 'You are a helpful assistant. Be concise.'
);
```

---

## `fsl_openai_chat`

Sends a conversation to [OpenAI Chat Completions](https://platform.openai.com/docs/api-reference/chat).

### Signature

```php
function fsl_openai_chat(
    array $messages,
    ?string $model = null,
    int $max_tokens = 1024
): array
```

| Parameter | Description |
|-----------|-------------|
| `$messages` | OpenAI-format messages (e.g. `system`, `user`, `assistant`). |
| `$model` | Default `option('openai_model')` or `gpt-4o`. |
| `$max_tokens` | Default `1024`. |

### Returns

Decoded JSON **array**. Assistant text is usually at `$response['choices'][0]['message']['content']`.

### Errors

Same pattern as Anthropic: missing key or non-2xx HTTP yields `RuntimeException`.

### Example

```php
$response = fsl_openai_chat([
    ['role' => 'system', 'content' => 'You are a helpful assistant.'],
    ['role' => 'user',   'content' => $question],
]);
$answer = $response['choices'][0]['message']['content'];
```

---

## Reading the user message in route handlers

`params()` only holds **route** placeholders (e.g. `:id`). For JSON POST bodies, read **`env()['POST']`** after the framework has parsed `Content-Type: application/json`:

```php
$message = env()['POST']['message'] ?? '';
```
