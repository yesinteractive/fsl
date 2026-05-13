<?php
/*
 * MCP (Model Context Protocol) Server helpers for FSL Micro Framework
 *
 * Implements the Streamable HTTP transport of the MCP spec (2025).
 * Exposes registered tools to AI agents via a single POST endpoint.
 *
 * Usage — create an MCP server in ~10 lines:
 *
 *   require 'lib/fsl.php';
 *
 *   fsl_mcp_tool(
 *       name: 'get_weather',
 *       description: 'Get current weather for a city',
 *       schema: [
 *           'type' => 'object',
 *           'properties' => ['city' => ['type' => 'string', 'description' => 'City name']],
 *           'required' => ['city']
 *       ],
 *       callback: function(array $args): array {
 *           return ['city' => $args['city'], 'temperature' => 72, 'unit' => 'F'];
 *       }
 *   );
 *
 *   dispatch_post('/', 'fsl_mcp_handle');
 *   run();
 */

declare(strict_types=1);

/*
 * fsl_mcp_tool
 *
 * Register a tool that AI agents can discover and call.
 *
 * @name        string    Tool name (snake_case, no spaces or special characters)
 * @description string    Plain-English description shown to the AI agent
 * @schema      array     JSON Schema object describing the tool's input parameters
 * @callback    callable  Called with $args array when the tool is invoked; return value is sent back to the agent
 */
function fsl_mcp_tool(string $name, string $description, array $schema, callable $callback): void
{
    static $tools = [];
    $tools[$name] = [
        'name'        => $name,
        'description' => $description,
        'inputSchema' => $schema,
        'callback'    => $callback,
    ];
    // Store in a globally accessible static so fsl_mcp_handle can read it
    fsl_mcp_registry($tools);
}

/*
 * fsl_mcp_registry
 *
 * Internal registry store — sets or gets the tools array.
 *
 * @access private
 */
function fsl_mcp_registry(?array $tools = null): array
{
    static $registry = [];
    if ($tools !== null) {
        $registry = $tools;
    }
    return $registry;
}

/*
 * fsl_mcp_handle
 *
 * FSL controller — wire to a POST route to handle all MCP requests.
 * Implements JSON-RPC 2.0: initialize, tools/list, tools/call.
 *
 * @return string  JSON-RPC 2.0 response
 */
function fsl_mcp_handle(): string
{
    $raw = file_get_contents('php://input');
    $req = json_decode($raw, true);

    // Validate JSON-RPC structure
    if (!isset($req['jsonrpc']) || $req['jsonrpc'] !== '2.0' || !isset($req['method'])) {
        return fsl_mcp_error(null, -32600, 'Invalid JSON-RPC request');
    }

    $id     = $req['id'] ?? null;
    $method = $req['method'];
    $params = $req['params'] ?? [];

    return match ($method) {
        'initialize'  => fsl_mcp_initialize($id),
        'tools/list'  => fsl_mcp_tools_list($id),
        'tools/call'  => fsl_mcp_tools_call($id, $params),
        default       => fsl_mcp_error($id, -32601, "Method not found: $method"),
    };
}

/*
 * fsl_mcp_initialize
 *
 * Handles the MCP initialize handshake. Returns server info and capabilities.
 *
 * @access private
 */
function fsl_mcp_initialize(mixed $id): string
{
    return fsl_mcp_response($id, [
        'protocolVersion' => '2024-11-05',
        'capabilities'    => ['tools' => []],
        'serverInfo'      => [
            'name'    => option('mcp_server_name') ?? 'FSL MCP Server',
            'version' => option('fsl_version') ?? '1.0',
        ],
    ]);
}

/*
 * fsl_mcp_tools_list
 *
 * Returns all registered tools with their schemas.
 *
 * @access private
 */
function fsl_mcp_tools_list(mixed $id): string
{
    $tools = array_values(array_map(function(array $tool): array {
        return [
            'name'        => $tool['name'],
            'description' => $tool['description'],
            'inputSchema' => $tool['inputSchema'],
        ];
    }, fsl_mcp_registry()));

    return fsl_mcp_response($id, ['tools' => $tools]);
}

/*
 * fsl_mcp_tools_call
 *
 * Finds the requested tool and invokes its callback with the provided arguments.
 *
 * @access private
 */
function fsl_mcp_tools_call(mixed $id, array $params): string
{
    $name = $params['name'] ?? null;
    $args = $params['arguments'] ?? [];

    if ($name === null) {
        return fsl_mcp_error($id, -32602, 'Missing required parameter: name');
    }

    $registry = fsl_mcp_registry();

    if (!isset($registry[$name])) {
        return fsl_mcp_error($id, -32602, "Unknown tool: $name");
    }

    try {
        $result = ($registry[$name]['callback'])($args);
        return fsl_mcp_response($id, [
            'content' => [
                ['type' => 'text', 'text' => is_string($result) ? $result : json_encode($result)],
            ],
        ]);
    } catch (Throwable $e) {
        return fsl_mcp_error($id, -32603, 'Tool execution error: ' . $e->getMessage());
    }
}

/*
 * fsl_mcp_response
 *
 * Build a JSON-RPC 2.0 success response.
 *
 * @access private
 */
function fsl_mcp_response(mixed $id, array $result): string
{
    return json(['jsonrpc' => '2.0', 'id' => $id, 'result' => $result]);
}

/*
 * fsl_mcp_error
 *
 * Build a JSON-RPC 2.0 error response.
 *
 * @access private
 */
function fsl_mcp_error(mixed $id, int $code, string $message): string
{
    return json(['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => $code, 'message' => $message]]);
}
