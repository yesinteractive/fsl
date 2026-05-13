# MCP server helpers (`lib/fsl_mcp_functions.php`)

FSL can act as a [Model Context Protocol](https://modelcontextprotocol.io) server over HTTP: clients send **JSON-RPC 2.0** requests; you register **tools** with JSON Schema and PHP callbacks.

## Public API

### `fsl_mcp_tool`

Registers one tool for agents to discover and invoke.

```php
function fsl_mcp_tool(
    string $name,
    string $description,
    array $schema,
    callable $callback
): void
```

| Argument | Description |
|----------|-------------|
| `$name` | Tool identifier (e.g. snake_case). |
| `$description` | Human-readable summary for the agent. |
| `$schema` | JSON Schema object for input (typically `type`, `properties`, `required`). |
| `$callback` | `function (array $args): array|string` — return value is sent back (non-strings are JSON-encoded in the MCP payload). |

Call **`fsl_mcp_tool()` before `run()`** (same as `dispatch_*`), so tools exist when the MCP route is hit.

### `fsl_mcp_handle`

Controller entrypoint: wire it to a **POST** route (e.g. `/mcp`). Reads `php://input`, validates JSON-RPC 2.0, dispatches by `method`, returns a JSON string suitable as the HTTP body (uses framework `json()` helper).

```php
function fsl_mcp_handle(): string
```

#### Supported JSON-RPC methods

| Method | Behavior |
|--------|----------|
| `initialize` | Returns `protocolVersion`, `capabilities`, `serverInfo` (name from `option('mcp_server_name')` or default `FSL MCP Server`, version from `option('fsl_version')`). |
| `tools/list` | Lists all registered tools with `name`, `description`, `inputSchema`. |
| `tools/call` | Expects `params.name` and optional `params.arguments` (object). Runs the matching callback; tool errors return JSON-RPC error `-32603`. |

Invalid requests return error code `-32600`; unknown methods `-32601`; bad tool params `-32602`.

---

## Minimal server

```php
<?php
require 'lib/fsl.php';

fsl_mcp_tool(
    name: 'get_user',
    description: 'Look up a user by ID',
    schema: [
        'type'       => 'object',
        'properties' => ['id' => ['type' => 'integer', 'description' => 'User ID']],
        'required'   => ['id'],
    ],
    callback: function (array $args): array {
        return user_find($args['id']);
    }
);

dispatch_post('/mcp', 'fsl_mcp_handle');
run();
```

---

## Options

| Option | Purpose |
|--------|---------|
| `mcp_server_name` | Shown in `initialize` as `serverInfo.name`. |
| `fsl_version` | Shown as `serverInfo.version` if set. |

---

## Auth

MCP has no built-in auth. Use the normal `before($route)` hook (or check headers inside a thin wrapper around `fsl_mcp_handle`) to validate `Authorization` or API keys before the handler runs. Return **JSON** errors yourself if you reject the request, so clients do not receive HTML error pages.

---

## Internal helpers (reference)

These are used by `fsl_mcp_handle` but are part of the same file; extension or debugging may call them rarely.

| Function | Role |
|----------|------|
| `fsl_mcp_registry(?array $tools = null): array` | Merges tool definitions into a static registry; pass `null` to read. |
| `fsl_mcp_initialize`, `fsl_mcp_tools_list`, `fsl_mcp_tools_call` | Per-method handlers. |
| `fsl_mcp_response(mixed $id, array $result): string` | JSON-RPC success envelope. |
| `fsl_mcp_error(mixed $id, int $code, string $message): string` | JSON-RPC error envelope. |
