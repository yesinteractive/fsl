<?php

/*
 * FSL Demo Controllers
 *
 * Shows FSL's agentic, LLM, MCP, and API capabilities.
 */

function process_time(): string
{
    $time = number_format(microtime(true) - LIM_START_MICROTIME, 6);
    return "Request processed in $time seconds";
}

/*
 * home
 *
 * Returns framework identity and a map of available demo endpoints.
 */
function home(): string
{
    return json([
        'framework' => 'FSL - PHP Agentic Micro-Framework',
        'version'   => option('fsl_version'),
        'endpoints' => [
            'POST /chat'      => 'LLM chat via Anthropic - body: {"message":"..."}',
            'POST /mcp'       => 'MCP server - JSON-RPC 2.0 (tools/list, tools/call)',
            'GET /api/status' => 'API health check',
            'GET /jwt'        => 'JWT encode/decode demo',
            'GET /curl'       => 'HTTP client demo',
        ],
    ]);
}

/*
 * llm_chat
 *
 * Accepts a POST body with "message" and returns an LLM reply via Anthropic.
 * Requires option('anthropic_api_key') to be configured.
 *
 * Example: POST /chat   {"message": "What is MCP?"}
 */
function llm_chat(): string
{
    $message = params('message');
    if (empty($message)) {
        halt(BAD_REQUEST, 'Missing required parameter: message');
    }

    try {
        $response = fsl_anthropic_chat([
            ['role' => 'user', 'content' => $message],
        ]);
        return json([
            'reply'   => $response['content'][0]['text'],
            'model'   => $response['model'],
            'elapsed' => process_time(),
        ]);
    } catch (RuntimeException $e) {
        halt(SERVER_ERROR, $e->getMessage());
    }
}

/*
 * api_status
 *
 * Returns a JSON health check - useful as a liveness probe.
 */
function api_status(): string
{
    return json([
        'status'    => 'ok',
        'timestamp' => date('c'),
        'framework' => 'FSL',
        'version'   => option('fsl_version'),
        'elapsed'   => process_time(),
    ]);
}

/*
 * jwt
 *
 * Demonstrates JWT encode and decode via fsl_jwt_encode / fsl_jwt_decode.
 */
function jwt(): string
{
    $payload  = ['id' => 'demo123', 'name' => 'FSL'];
    $key      = 'demo-secret-key';
    $token    = fsl_jwt_encode($payload, $key);
    $decoded  = fsl_jwt_decode($token, $key);

    return json([
        'payload'  => $payload,
        'token'    => $token,
        'decoded'  => (array) $decoded,
        'elapsed'  => process_time(),
    ]);
}

/*
 * curl
 *
 * Demonstrates fsl_curl() making an outbound HTTP request with Bearer token auth.
 */
function curl(): string
{
    [$code, , $body] = fsl_curl(
        url:       'https://httpbin.org/get',
        method:    'GET',
        datatype:  'JSON',
        urlparams: 'demo=fsl',
        authtype:  'TOKEN',
        authtoken: 'demo-token'
    );

    return json([
        'http_code' => $code,
        'response'  => json_decode($body, true),
        'elapsed'   => process_time(),
    ]);
}
