# FSL documentation

Reference material for libraries shipped with the framework (beyond the Limonade-style core in `lib/fsl.php`).

| Document | Contents |
|----------|----------|
| [helpers-fsl_functions.md](helpers-fsl_functions.md) | Encryption, XSS scrub, encrypted session helpers, JWT, URL shortening, Google OAuth helpers, password hashing, `fsl_curl`, CSRF |
| [helpers-ai.md](helpers-ai.md) | `fsl_anthropic_chat`, `fsl_openai_chat` — configuration and examples |
| [helpers-mcp.md](helpers-mcp.md) | MCP tool registration, JSON-RPC handler, options, auth patterns |

All of these files live under `lib/` and are auto-loaded when the app runs (`require_once` of `lib/fsl.php` loads `lib/*.php` during `run()`; `fsl_mcp_functions.php` is also required early so tools can register before `run()`).
