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
 * HTML landing page with FSL overview and links/forms for demo endpoints.
 */
function home(): string
{
    $locals = [
        'fsl_version' => option('fsl_version'),
        'url_status'  => url_for('/api/status'),
        'url_jwt'     => url_for('/jwt'),
        'url_curl'    => url_for('/curl'),
        'url_chat'    => str_replace('&amp;', '&', url_for('/chat')),
        'url_mcp'     => str_replace('&amp;', '&', url_for('/mcp')),
        'url_github'  => 'https://github.com/yesinteractive/fsl',
        'url_license' => 'https://github.com/yesinteractive/fsl/blob/master/LICENSE.md',
    ];
    $body = render('home.html.php', null, $locals);
    send_header('Content-Type: text/html; charset=' . strtolower(option('encoding')));

    return $body;
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
    // Request body is in env()['POST'] (JSON or form); params() is only for route placeholders.
    $post    = env()['POST'] ?? [];
    $message = $post['message'] ?? params('message');
    $message = is_string($message) ? trim($message) : '';

    if ($message === '') {
        status(HTTP_BAD_REQUEST);

        return json([
            'error' => 'Missing required parameter: message',
            'hint'  => 'Send JSON: {"message":"your text"} or form field message.',
        ]);
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
        status(SERVER_ERROR);

        return json([
            'error' => $e->getMessage(),
        ]);
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
