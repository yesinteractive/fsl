<?php
/*
 * AI/LLM Helper functions for FSL Micro Framework
 *
 * Provides thin wrappers for Anthropic and OpenAI chat APIs.
 * Both functions use fsl_curl() under the hood and pull credentials
 * from the option() config system.
 *
 * Configure in config/fsl_config.php:
 *   option('anthropic_api_key', getenv('ANTHROPIC_API_KEY'));
 *   option('anthropic_model',   'claude-sonnet-4-6');
 *   option('openai_api_key',    getenv('OPENAI_API_KEY'));
 *   option('openai_model',      'gpt-4o');
 */

declare(strict_types=1);

/*
 * fsl_anthropic_chat
 *
 * Send messages to the Anthropic Messages API and return the decoded response.
 * Docs: https://docs.anthropic.com/en/api/messages
 *
 * @messages   array        Messages array: [['role' => 'user', 'content' => 'Hello']]
 * @model      string|null  Model ID. Defaults to option('anthropic_model').
 * @max_tokens int          Maximum tokens in the response (default 1024).
 * @system     string|null  Optional system prompt.
 * @return     array        Full decoded API response. Text is at $response['content'][0]['text'].
 */
function fsl_anthropic_chat(
    array $messages,
    ?string $model = null,
    int $max_tokens = 1024,
    ?string $system = null
): array {
    $api_key = option('anthropic_api_key') ?: option('ANTHROPIC_API_KEY');
    if (empty($api_key)) {
        throw new RuntimeException(
            'Anthropic API key not set. Use option(\'anthropic_api_key\', getenv(\'ANTHROPIC_API_KEY\')) or env ANTHROPIC_API_KEY in config/fsl_config.php.'
        );
    }

    $model = $model ?? option('anthropic_model') ?? 'claude-sonnet-4-6';
    $api_version = option('anthropic_api_version') ?? '2023-06-01';

    $body = [
        'model'      => $model,
        'max_tokens' => $max_tokens,
        'messages'   => $messages,
    ];
    if ($system !== null) {
        $body['system'] = $system;
    }

    [$code, , $raw] = fsl_curl(
        url: 'https://api.anthropic.com/v1/messages',
        method: 'POST',
        datatype: 'JSON',
        postdata: json_encode($body),
        customheader: [
            'x-api-key: ' . $api_key,
            'anthropic-version: ' . $api_version,
        ]
    );

    $response = json_decode($raw, true);

    if ($code < 200 || $code >= 300) {
        $error = $response['error']['message'] ?? $raw;
        throw new RuntimeException("Anthropic API error (HTTP $code): $error");
    }

    return $response;
}

/*
 * fsl_openai_chat
 *
 * Send messages to the OpenAI Chat Completions API and return the decoded response.
 * Docs: https://platform.openai.com/docs/api-reference/chat
 *
 * @messages   array        Messages array: [['role' => 'user', 'content' => 'Hello']]
 * @model      string|null  Model ID. Defaults to option('openai_model').
 * @max_tokens int          Maximum tokens in the response (default 1024).
 * @return     array        Full decoded API response. Text is at $response['choices'][0]['message']['content'].
 */
function fsl_openai_chat(
    array $messages,
    ?string $model = null,
    int $max_tokens = 1024
): array {
    $api_key = option('openai_api_key');
    if (empty($api_key)) {
        throw new RuntimeException(
            'OpenAI API key not set. Add option(\'openai_api_key\', ...) in config/fsl_config.php.'
        );
    }

    $model = $model ?? option('openai_model') ?? 'gpt-4o';

    $body = [
        'model'      => $model,
        'max_tokens' => $max_tokens,
        'messages'   => $messages,
    ];

    [$code, , $raw] = fsl_curl(
        url: 'https://api.openai.com/v1/chat/completions',
        method: 'POST',
        datatype: 'JSON',
        postdata: json_encode($body),
        authtype: 'TOKEN',
        authtoken: $api_key
    );

    $response = json_decode($raw, true);

    if ($code < 200 || $code >= 300) {
        $error = $response['error']['message'] ?? $raw;
        throw new RuntimeException("OpenAI API error (HTTP $code): $error");
    }

    return $response;
}
