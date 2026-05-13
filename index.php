<?php
##############################################################################
#  requirements - must be included in your index.php
##############################################################################

require_once 'lib/fsl.php';


##############################################################################
#  code to run before route execution
##############################################################################

function before($route)
{
    header("X-FSL-route-function: " . $route['callback']);
    option('routecallback', $route['callback']);
}

##############################################################################
#  routes
##############################################################################
#
#  HTTP Method |  Url path         |  Controller function
# -------------+-------------------+-------------------------------------------
#   GET        |  /                |  home            - HTML landing + demo links
#   POST       |  /chat            |  llm_chat        - LLM chat via Anthropic
#   POST       |  /mcp             |  fsl_mcp_handle  - MCP server (JSON-RPC 2.0)
#   GET        |  /api/status      |  api_status      - JSON health check
#   GET        |  /jwt             |  jwt             - JWT encode/decode demo
#   GET        |  /curl            |  curl            - HTTP client demo


// Framework home - returns identity and available endpoints
dispatch_get('/', 'home');

// LLM chat endpoint - POST {"message": "..."} to get an AI reply
dispatch_post('/chat', 'llm_chat');

// MCP server - handles initialize, tools/list, tools/call (JSON-RPC 2.0)
fsl_mcp_tool(
    name: 'get_status',
    description: 'Get the current server status and timestamp',
    schema: [
        'type'       => 'object',
        'properties' => (object)[],
        'required'   => [],
    ],
    callback: function(array $args): array {
        return [
            'status'    => 'ok',
            'timestamp' => date('c'),
            'framework' => 'FSL',
        ];
    }
);

fsl_mcp_tool(
    name: 'echo_message',
    description: 'Echo a message back - useful for testing MCP connectivity',
    schema: [
        'type'       => 'object',
        'properties' => [
            'message' => ['type' => 'string', 'description' => 'The message to echo back'],
        ],
        'required' => ['message'],
    ],
    callback: function(array $args): array {
        return [
            'echo'      => $args['message'],
            'timestamp' => date('c'),
        ];
    }
);

dispatch_post('/mcp', 'fsl_mcp_handle');

// API health check
dispatch_get('/api/status', 'api_status');

// Utility demos
dispatch_get('/jwt', 'jwt');
dispatch_get('/curl', 'curl');


##############################################################################
#  run after function
##############################################################################

function after($output, $route)
{
    return $output;
}


run();
