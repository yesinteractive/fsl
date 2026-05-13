<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="FSL — AI-native PHP micro-framework. LLM helpers, MCP tools, JSON APIs, no Composer.">
    <title>FSL · Fresh Squeezed Limonade</title>
    <link rel="icon" href="<?php echo h(url_for('/public/favicon.ico')); ?>" type="image/x-icon">
    <style>
        :root {
            --bg: #0c0f12;
            --surface: #151a21;
            --border: #263041;
            --text: #e8ecf1;
            --muted: #8b98a8;
            --citrus: #f4c430;
            --citrus-dim: #c9a227;
            --mint: #3ecf8e;
            --radius: 12px;
            --font: "Segoe UI", system-ui, -apple-system, sans-serif;
            --mono: ui-monospace, "Cascadia Code", "Source Code Pro", Menlo, monospace;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: var(--font);
            background: radial-gradient(1200px 600px at 10% -10%, #1a2433 0%, var(--bg) 55%);
            color: var(--text);
            line-height: 1.55;
            min-height: 100vh;
        }
        a { color: var(--citrus); text-decoration: none; }
        a:hover { text-decoration: underline; color: #ffe066; }
        .wrap { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }

        header.site-header {
            --fsl-header-img: none;
            margin-bottom: 2rem;
            padding: 1.35rem 1.6rem 1.6rem;
            background-color: #fff;
            background-image:
                linear-gradient(
                    100deg,
                    rgba(255, 255, 255, 0.99) 0%,
                    rgba(255, 255, 255, 0.94) 32%,
                    rgba(255, 255, 255, 0.78) 52%,
                    rgba(255, 255, 255, 0.42) 72%,
                    rgba(255, 255, 255, 0.12) 88%,
                    rgba(255, 255, 255, 0) 100%
                ),
                var(--fsl-header-img);
            background-size: cover, min(440px, 58vw) auto;
            background-position: 0 0, right -5% center;
            background-repeat: no-repeat, no-repeat;
            border-radius: 24px;
            border: 1px solid rgba(15, 20, 28, 0.07);
            box-shadow:
                0 1px 3px rgba(15, 20, 28, 0.06),
                0 12px 40px rgba(15, 20, 28, 0.12);
            color: #1a2332;
            min-height: 220px;
        }
        .site-header__top {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1rem 1.25rem;
        }
        .site-header__left {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.85rem 1.1rem;
            min-width: 0;
        }
        .site-header__aside {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: flex-end;
            gap: 0.65rem 1.25rem;
        }
        header.site-header a {
            color: #1a2332;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
        }
        header.site-header a:hover {
            color: #0c0f12;
            text-decoration: underline;
        }
        header.site-header a.site-header__license {
            font-weight: 500;
            font-size: 0.88rem;
        }
        header.site-header a.btn-github {
            display: inline-block;
            margin-top: 0.15rem;
            padding: 0.55rem 1.2rem;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            color: #fff !important;
            background: #0b57d0;
            box-shadow: 0 2px 8px rgba(11, 87, 208, 0.28);
            text-decoration: none !important;
        }
        header.site-header a.btn-github:hover {
            background: #0948b0;
            color: #fff !important;
            text-decoration: none !important;
        }
        .site-header__welcome {
            margin-top: 1.15rem;
            max-width: min(32rem, 100%);
        }
        .site-header__welcome h2 {
            margin: 0 0 0.55rem;
            font-size: clamp(1.85rem, 4.5vw, 2.5rem);
            font-weight: 300;
            letter-spacing: 0.02em;
            color: #3d4d63;
            line-height: 1.15;
        }
        .site-header__welcome p {
            margin: 0 0 1rem;
            font-size: 1.05rem;
            line-height: 1.55;
            color: #4a5d72;
        }
        .site-header__github-icon {
            flex-shrink: 0;
        }
        .site-header__intro {
            margin-top: 1.25rem;
            padding-top: 1.2rem;
            border-top: 1px solid rgba(15, 20, 28, 0.08);
        }
        .site-header__intro h1 {
            font-size: clamp(1.5rem, 3.5vw, 1.95rem);
            font-weight: 700;
            margin: 0 0 0.45rem;
            letter-spacing: -0.02em;
            color: #0c0f12;
        }
        .logo {
            max-height: 80px;
            max-width: min(280px, 100%);
            width: auto;
            height: auto;
            object-fit: contain;
            display: block;
        }
        .badge {
            display: inline-block;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: #1a1410;
            background: var(--citrus);
            border: 1px solid rgba(200, 155, 0, 0.5);
            padding: 0.35rem 0.75rem;
            border-radius: 999px;
            white-space: nowrap;
        }
        .tagline {
            color: #3d4d63;
            font-size: 1rem;
            max-width: 52rem;
            margin: 0;
            line-height: 1.55;
        }
        .tagline code {
            background: #eef1f6;
            color: #0c0f12;
            padding: 0.12em 0.4em;
            border-radius: 5px;
            font-size: 0.9em;
            border: 1px solid rgba(15, 20, 28, 0.08);
        }
        .hero {
            background: linear-gradient(135deg, var(--surface) 0%, #1a222d 100%);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.75rem 1.5rem;
            margin-bottom: 2rem;
        }
        .hero p { margin: 0 0 1rem; color: var(--text); }
        .hero p:last-of-type { margin-bottom: 0; }
        .hero-lead { font-size: 1.05rem; }
        .hero-req { font-size: 0.9rem; color: var(--muted); }
        .hero-sub {
            font-size: 0.95rem;
            font-weight: 600;
            margin: 1.25rem 0 0.65rem;
            color: var(--citrus);
            letter-spacing: 0.03em;
            text-transform: uppercase;
        }
        .hero-list {
            margin: 0 0 1rem;
            padding-left: 1.2rem;
            color: #d1dae6;
            font-size: 0.95rem;
        }
        .hero-list li { margin-bottom: 0.45rem; }
        .hero-list li:last-child { margin-bottom: 0; }
        .hero-list strong { color: var(--text); }
        .pill-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }
        .pill {
            font-size: 0.8rem;
            color: var(--mint);
            border: 1px solid rgba(62, 207, 142, 0.35);
            padding: 0.25rem 0.65rem;
            border-radius: 999px;
            background: rgba(62, 207, 142, 0.08);
        }
        h2 {
            font-size: 1.1rem;
            font-weight: 600;
            margin: 0 0 1rem;
            color: var(--citrus);
            letter-spacing: 0.02em;
        }
        .grid {
            display: grid;
            gap: 1rem;
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            margin-bottom: 2.5rem;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.25rem 1.25rem 1.1rem;
            display: flex;
            flex-direction: column;
        }
        .card h3 {
            margin: 0 0 0.5rem;
            font-size: 1rem;
            font-weight: 600;
        }
        .card p {
            margin: 0 0 1rem;
            font-size: 0.9rem;
            color: var(--muted);
            flex: 1;
        }
        .card .actions { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
        .btn {
            display: inline-block;
            font-size: 0.85rem;
            font-weight: 600;
            padding: 0.45rem 0.9rem;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-family: inherit;
        }
        .btn-primary {
            background: var(--citrus);
            color: var(--bg);
        }
        .btn-primary:hover { background: #ffe066; text-decoration: none; color: var(--bg); }
        .btn-ghost {
            background: transparent;
            color: var(--text);
            border: 1px solid var(--border);
        }
        .btn-ghost:hover { border-color: var(--muted); text-decoration: none; color: var(--text); }
        .mono {
            font-family: var(--mono);
            font-size: 0.78rem;
            background: #0a0d11;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            overflow-x: auto;
            color: #c5d4e0;
            margin: 0.5rem 0 0;
        }
        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
        }
        .panel label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.35rem; }
        textarea {
            width: 100%;
            min-height: 88px;
            padding: 0.65rem 0.75rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: #0a0d11;
            color: var(--text);
            font-family: inherit;
            font-size: 0.9rem;
            resize: vertical;
        }
        #chat-out, #mcp-out {
            margin-top: 0.75rem;
            font-family: var(--mono);
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-word;
            color: var(--muted);
        }
        #chat-out.ok, #mcp-out.ok { color: var(--mint); }
        #chat-out.err, #mcp-out.err { color: #f87171; }
        footer {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            font-size: 0.85rem;
            color: var(--muted);
        }
    </style>
</head>
<body>
    <div class="wrap">
        <header class="site-header" style="--fsl-header-img: url('<?php echo htmlspecialchars(str_replace('&amp;', '&', url_for('/public/fsl.jpeg')), ENT_QUOTES, 'UTF-8'); ?>')">
            <div class="site-header__top">
                <div class="site-header__left">
                    <img class="logo" src="<?php echo h(url_for('/public/fsl-logobox.png')); ?>" alt="FSL — AI-native PHP microframework" width="260" height="76" loading="eager" onerror="this.style.display='none'">
                    <span class="badge">PHP <?php echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION; ?> · build <?php echo h((string) $fsl_version); ?></span>
                    <span class="badge"><a class="site-header__license" href="<?php echo h($url_license); ?>" target="_blank" rel="noopener noreferrer">MIT License</a></span>
                
            </div>
            <div class="site-header__welcome">
                <h2>Ahhhhh, refreshing!</h2>
                <p>Congratulations! Your Fresh Squeezed Limonade installation is up and running. For documentation and updates, visit the project page on GitHub.</p>
                <a class="btn-github" href="<?php echo h($url_github); ?>" target="_blank" rel="noopener noreferrer">View project and documentation on GitHub »</a>
            </div>
         
        </header>

     
        <p style="color:var(--muted);margin:-0.5rem 0 1rem;font-size:0.9rem;">
            
        FSL - Fresh Squeezed Limonade - is an AI-native PHP microframework for APIs, LLM services, MCP tools and rapid web/mobile app development — no Composer required. FSL is for developers who want to expose existing PHP as AI-callable APIs and MCP tools without Laravel, Symfony, Node, or a Composer workflow.
</p>

        <h2>Try the bundled demos</h2>
        <p style="color:var(--muted);margin:-0.5rem 0 1rem;font-size:0.9rem;">
            
       GET endpoints open in the browser. Chat and MCP use POST — use the forms below or copy the curl snippets.</p>

        <div class="grid">
            <article class="card">
                <h3>API status</h3>
                <p>JSON liveness probe: <code>status</code>, timestamp, version.</p>
                <div class="actions">
                    <a class="btn btn-primary" href="<?php echo h($url_status); ?>" target="_blank" rel="noopener">Open JSON</a>
                </div>
            </article>
            <article class="card">
                <h3>JWT demo</h3>
                <p>Encode and decode a sample payload with <code>fsl_jwt_encode</code> / <code>fsl_jwt_decode</code>.</p>
                <div class="actions">
                    <a class="btn btn-primary" href="<?php echo h($url_jwt); ?>" target="_blank" rel="noopener">Open JSON</a>
                </div>
            </article>
            <article class="card">
                <h3>HTTP client</h3>
                <p><code>fsl_curl</code> to httpbin with Bearer token — inspect the JSON response.</p>
                <div class="actions">
                    <a class="btn btn-primary" href="<?php echo h($url_curl); ?>" target="_blank" rel="noopener">Open JSON</a>
                </div>
            </article>
        </div>

        <div class="panel">
            <h2 style="margin-bottom:0.75rem;">LLM chat · POST /chat</h2>
            <p style="color:var(--muted);font-size:0.9rem;margin:0 0 1rem;">Requires <code>option('anthropic_api_key')</code> in <code>config/fsl_config.php</code> (or env). Sends <code>{"message":"…"}</code> as JSON.</p>
            <form id="chat-form">
                <label for="chat-msg">Message</label>
                <textarea id="chat-msg" name="message" placeholder="Ask something…" required></textarea>
                <div style="margin-top:0.75rem;">
                    <button type="submit" class="btn btn-primary">POST /chat</button>
                </div>
            </form>
            <div id="chat-out" aria-live="polite"></div>
            <pre class="mono" id="chat-curl"></pre>
        </div>

        <div class="panel">
            <h2 style="margin-bottom:0.75rem;">MCP server · POST /mcp</h2>
            <p style="color:var(--muted);font-size:0.9rem;margin:0 0 1rem;">Streamable HTTP transport: JSON-RPC <code>initialize</code>, <code>tools/list</code>, or <code>tools/call</code> (e.g. <code>get_status</code>, <code>echo_message</code>).</p>
            <div class="actions" style="margin-bottom:0.75rem;">
                <button type="button" class="btn btn-ghost" id="mcp-list">tools/list</button>
                <button type="button" class="btn btn-ghost" id="mcp-call">tools/call get_status</button>
            </div>
            <div id="mcp-out" aria-live="polite"></div>
            <pre class="mono" id="mcp-curl"></pre>
        </div>

        <footer>
            <p style="margin:0 0 0.5rem;">Docs and source: <a href="<?php echo h($url_github); ?>">github.com/yesinteractive/fsl</a> · <a href="<?php echo h($url_license); ?>">MIT License</a> · <a href="https://modelcontextprotocol.io">Model Context Protocol</a></p>
            <p style="margin:0;">© <?php echo date('Y'); ?> Yes Interactive, LLC · MIT License</p>
        </footer>
    </div>

    <script>
(function () {
    var CHAT_URL = <?php echo json_encode($url_chat, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES); ?>;
    var MCP_URL = <?php echo json_encode($url_mcp, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES); ?>;

    document.getElementById('chat-curl').textContent =
        'curl -sS -X POST ' + CHAT_URL + " \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"message\":\"What is MCP?\"}'";

    document.getElementById('mcp-curl').textContent =
        'curl -sS -X POST ' + MCP_URL + " \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'";

    document.getElementById('chat-form').addEventListener('submit', function (e) {
        e.preventDefault();
        var out = document.getElementById('chat-out');
        out.className = '';
        out.textContent = 'Sending…';
        var msg = document.getElementById('chat-msg').value;
        fetch(CHAT_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ message: msg })
        }).then(function (r) { return r.text().then(function (t) { return { ok: r.ok, status: r.status, t: t }; }); })
        .then(function (x) {
            try {
                var j = JSON.parse(x.t);
                out.textContent = JSON.stringify(j, null, 2);
            } catch (er) {
                out.textContent = x.t;
            }
            out.className = x.ok ? 'ok' : 'err';
        }).catch(function (err) {
            out.textContent = err.message || String(err);
            out.className = 'err';
        });
    });

    function mcpRpc(method, params) {
        var out = document.getElementById('mcp-out');
        out.className = '';
        out.textContent = 'POST ' + method + '…';
        return fetch(MCP_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params || {} })
        }).then(function (r) { return r.text().then(function (t) { return { ok: r.ok, t: t }; }); })
        .then(function (x) {
            try {
                out.textContent = JSON.stringify(JSON.parse(x.t), null, 2);
            } catch (e) {
                out.textContent = x.t;
            }
            out.className = x.ok ? 'ok' : 'err';
        }).catch(function (err) {
            out.textContent = err.message || String(err);
            out.className = 'err';
        });
    }

    document.getElementById('mcp-list').addEventListener('click', function () {
        mcpRpc('tools/list', {});
    });
    document.getElementById('mcp-call').addEventListener('click', function () {
        mcpRpc('tools/call', { name: 'get_status', arguments: {} });
    });
})();
    </script>
</body>
</html>
