<?php

declare(strict_types=1);

/**
 * security.php — Shared Security Module
 * ─────────────────────────────────────
 * 1. Mini WAF          — request-level protection (SQLi, XSS, path traversal, bad UA)
 * 2. Rate Limiting     — APCu per-IP, per-slug
 * 3. URL Safety Check  — blocklist + heuristics + Google Safe Browsing (optional)
 * 4. Blocked Response  — HTML warning page for unsafe destinations
 */

// ═══════════════════════════════════════════════════════════════
// 1. MINI WAF
// ═══════════════════════════════════════════════════════════════

function wafCheck(): void
{
    $method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $ua       = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $uri      = $_SERVER['REQUEST_URI'] ?? '/';
    $rawQuery = $_SERVER['QUERY_STRING'] ?? '';
    $host     = $_SERVER['HTTP_HOST'] ?? '';

    // ── Only allow safe HTTP methods ──
    if (!in_array($method, ['GET', 'HEAD'], true)) {
        http_response_code(405);
        header('Allow: GET, HEAD');
        exit;
    }

    // ── Block exploit/scanner User-Agents ──
    if (
        $ua !== '' && preg_match(
            '/sqlmap|nikto|nessus|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|' .
            'hydra|metasploit|nmap|acunetix|burpsuite|openvas|w3af|havij|pangolin|' .
            'netcat|ncrack|medusa|skipfish|arachni|vega\b|ratproxy|grabber|' .
            'python-requests\/[01]\.|go-http-client\/1\.|curl\/[0-6]\.' .
            '|libwww-perl|lwp-trivial|peach|zap|paros|webscarab|' .
            'httpx|katana|feroxbuster|ffuf|gospider|hakrawler|gau\//i',
            $ua
        )
    ) {
        http_response_code(403);
        exit;
    }

    // ── Null byte injection ──
    $rawAll = $uri . $rawQuery;
    if (strpos($rawAll, "\0") !== false || strpos(urldecode($rawAll), "\0") !== false) {
        http_response_code(400);
        exit;
    }

    // ── Path traversal ──
    $decodedUri = urldecode($uri);
    if (preg_match('/\.\.[\\/]|[\\/]\.\./', $decodedUri)) {
        http_response_code(400);
        exit;
    }

    // ── SQL injection in query string ──
    if ($rawQuery !== '') {
        $qs = strtolower(urldecode($rawQuery));
        if (
            preg_match(
                '/\b(union[\s\+\/\*]+select|select[\s\+\/\*]+.{1,40}from|' .
                'insert[\s\+\/\*]+into|delete[\s\+\/\*]+from|drop[\s\+\/\*]+table|' .
                'exec[\s\+\/\*]*\(|xp_\w+|load_file\s*\(|into[\s\+]+outfile|' .
                'benchmark\s*\(|sleep\s*\(\d|waitfor[\s\+]+delay|' .
                'extractvalue\s*\(|updatexml\s*\()\b/',
                $qs
            )
        ) {
            http_response_code(400);
            exit;
        }
    }

    // ── XSS in query string ──
    if (
        $rawQuery !== '' && preg_match(
            '/<script[\s>]|javascript\s*:|vbscript\s*:|data\s*:text\/html|' .
            'on(?:load|error|click|mouse\w+|key\w+|focus|blur|submit|change|' .
            'input|drag\w*|touch\w*|pointer\w*|animation\w*)\s*=/i',
            urldecode($rawQuery)
        )
    ) {
        http_response_code(400);
        exit;
    }

    // ── Oversized query string (>2 KB abnormal for a redirect) ──
    if (strlen($rawQuery) > 2048) {
        http_response_code(414);
        exit;
    }

    // ── Host header injection ──
    if (strlen($host) > 253 || preg_match('/[\r\n\0<>]/', $host)) {
        http_response_code(400);
        exit;
    }

    // ── Protocol-relative or exotic scheme in slug/query ──
    if (preg_match('/^\/\/|^(javascript|data|vbscript|file):/i', urldecode($rawQuery))) {
        http_response_code(400);
        exit;
    }
}


// ═══════════════════════════════════════════════════════════════
// 2. RATE LIMITING
// ═══════════════════════════════════════════════════════════════

function rateLimitByIp(int $maxPerMinute = 120): void
{
    if (!tp_apcu_enabled()) {
        return;
    }

    // CF/XFF only trusted when REMOTE_ADDR is a Cloudflare edge IP
    // (data/cf_ips.json, refreshed by ops/update_cf_ips.php). Otherwise
    // an attacker hitting origin directly could bypass per-IP throttling
    // by rotating the CF-Connecting-IP header.
    $trustProxy = function_exists('tp_request_via_cloudflare') && tp_request_via_cloudflare();

    $ip = '';
    if ($trustProxy && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = trim((string) $_SERVER['HTTP_CF_CONNECTING_IP']);
    } elseif ($trustProxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = trim((string) $_SERVER['REMOTE_ADDR']);
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }

    $key = 'rl_ip_' . md5($ip);
    tp_apcu_add($key, 0, 60);        // 60-second window
    $count = tp_apcu_inc($key);
    if (!is_int($count)) {
        return;
    }

    if ($count > $maxPerMinute) {
        http_response_code(429);
        header('Retry-After: 60');
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Too many requests. Please slow down.');
    }
}

function rateLimitBySlug(string $slug, int $maxPerMinute = 300): void
{
    if (!tp_apcu_enabled()) {
        return;
    }

    $key = 'rl_slug_' . md5($slug);
    tp_apcu_add($key, 0, 60);
    $count = tp_apcu_inc($key);
    if (!is_int($count)) {
        return;
    }

    if ($count > $maxPerMinute) {
        http_response_code(429);
        header('Retry-After: 60');
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Too many requests for this link.');
    }
}


// ═══════════════════════════════════════════════════════════════
// 3. URL SAFETY CHECK
// ═══════════════════════════════════════════════════════════════

/**
 * Returns true if the URL is safe to redirect to.
 * Results are cached in APCu: safe → 1 hour, unsafe → 24 hours.
 * The block reason ('blocklist'|'phishing'|'gsb'|'unsafe') is stored
 * in a parallel APCu key so go.php can pass it to blockedPage().
 */
function isDestinationSafe(string $url): bool
{
    $cacheKey = 'url_chk_' . md5($url);

    $cacheHit = false;
    $cached = tp_apcu_fetch($cacheKey, $cacheHit);
    if ($cacheHit) {
        return (bool) $cached;
    }

    $reason = _evaluateUrlSafetyReason($url);
    $safe   = ($reason === '');

    $ttl = $safe ? 3600 : 86400;
    tp_apcu_store($cacheKey, $safe ? 1 : 0, $ttl);
    if (!$safe) {
        tp_apcu_store('url_reason_' . md5($url), $reason, $ttl);
    }

    return $safe;
}

/**
 * Returns the block reason string, or '' if the URL is safe.
 * Reasons: 'blocklist' | 'phishing' | 'gsb' | 'unsafe'
 */
function getUrlBlockReason(string $url): string
{
    $reason = tp_apcu_fetch('url_reason_' . md5($url));
    return is_string($reason) ? $reason : 'unsafe';
}

function _evaluateUrlSafetyReason(string $url): string
{
    $parsed = parse_url($url);
    if (!$parsed || empty($parsed['host'])) {
        return 'unsafe';
    }

    $host   = strtolower($parsed['host']);
    $scheme = strtolower($parsed['scheme'] ?? '');

    // ── Only http/https ──
    if (!in_array($scheme, ['http', 'https'], true)) {
        return 'unsafe';
    }

    // ── Block raw IP destinations (C2, malware, botnet) ──
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return 'unsafe';
    }
    // IPv6 bracket form
    if (preg_match('/^\[[\da-f:]+\]$/i', $host)) {
        return 'unsafe';
    }

    // ── Decode IDN/punycode for inspection ──
    $checkHost = $host;
    if (function_exists('idn_to_utf8') && strpos($host, 'xn--') !== false) {
        $decoded = idn_to_utf8($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($decoded !== false) {
            $checkHost = $decoded;
        }
    }
    $domain = preg_replace('/^www\d*\./', '', $checkHost);

    // ── Blocklist ──
    if (_inBlocklist($domain, $host)) {
        return 'blocklist';
    }

    // ── Heuristic analysis (brand impersonation → phishing) ──
    if (_hasRiskyIndicators($domain, $host, $url, $parsed)) {
        return 'phishing';
    }

    // ── Google Safe Browsing (optional, fail-open) ──
    $gsbKey = getenv('GSB_API_KEY') ?: '';
    if ($gsbKey !== '' && !_checkGSB($url, $gsbKey)) {
        return 'gsb';
    }

    return ''; // safe
}

// ── Blocklist (file + hardcoded bad keywords) ──────────────────
function _inBlocklist(string $domain, string $fullHost): bool
{
    static $list = null;

    if ($list === null) {
        $list = [];
        $file = __DIR__ . '/../blocklist.txt';
        if (file_exists($file)) {
            foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = strtolower(trim($line));
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $list[$line] = true;
            }
        }
    }

    if (isset($list[$domain]) || isset($list[$fullHost])) {
        return true;
    }

    // Check parent domains: evil.sub.example.com → check example.com, sub.example.com
    $parts = explode('.', $domain);
    for ($i = 1, $len = count($parts); $i < $len - 1; $i++) {
        if (isset($list[implode('.', array_slice($parts, $i))])) {
            return true;
        }
    }

    return false;
}

// ── Heuristic risk indicators ──────────────────────────────────
/** @param array<string, mixed> $parsed */
function _hasRiskyIndicators(string $domain, string $fullHost, string $url, array $parsed): bool
{
    // 1. Too many subdomain levels (>4) — common phishing tactic
    if (substr_count($fullHost, '.') > 4) {
        return true;
    }

    // 2. Open redirector abuse: URL embedded inside URL
    if (preg_match('/https?:\/\/[^\/]+\/.+https?:\/\//i', $url)) {
        return true;
    }

    // 3. Dangerous URL schemes anywhere in the URL
    if (preg_match('/^(?:javascript|data|vbscript|file):/i', $url)) {
        return true;
    }

    // 4. Port scanning / non-standard ports (80 and 443 are normal)
    if (isset($parsed['port']) && !in_array((int)$parsed['port'], [80, 443, 8080, 8443], true)) {
        return true;
    }

    // 5. Excessive URL length (>2048 chars — phishing redirect chains are long)
    //    Raised to 2048 so long affiliate URLs with {clickid} are not blocked
    if (strlen($url) > 2048) {
        return true;
    }

    // 6. Brand impersonation check
    //    Indexed by canonical domain → allowed
    static $legitimateDomains = [
        // Global
        'google.com'        => 1, 'google.co.id'   => 1, 'google.co.uk'  => 1,
        'google.com.au'     => 1, 'google.com.sg'  => 1,
        'paypal.com'        => 1,
        'apple.com'         => 1,
        'facebook.com'      => 1, 'fb.com'         => 1, 'meta.com'      => 1,
        'amazon.com'        => 1, 'amazon.co.id'   => 1, 'amazon.co.uk'  => 1,
        'microsoft.com'     => 1, 'live.com'       => 1, 'outlook.com'   => 1,
                                  'office.com'     => 1, 'azure.com'     => 1,
        'instagram.com'     => 1,
        'twitter.com'       => 1, 'x.com'          => 1,
        'netflix.com'       => 1,
        'spotify.com'       => 1,
        'tiktok.com'        => 1,
        'whatsapp.com'      => 1, 'whatsapp.net'   => 1,
        'linkedin.com'      => 1,
        'youtube.com'       => 1, 'youtu.be'       => 1,
        'discord.com'       => 1, 'discordapp.com' => 1,
        'telegram.org'      => 1, 'telegram.me'    => 1, 't.me'          => 1,
        'shopify.com'       => 1,
        'wordpress.com'     => 1, 'wordpress.org'  => 1,
        'github.com'        => 1, 'github.io'      => 1,
        'dropbox.com'       => 1,
        'stripe.com'        => 1,
        'binance.com'       => 1,
        'coinbase.com'      => 1,
        'chase.com'         => 1,
        'bankofamerica.com' => 1,
        'wellsfargo.com'    => 1,
        'citibank.com'      => 1,
        // Indonesia
        'bca.co.id'         => 1, 'klikbca.com'    => 1,
        'bni.co.id'         => 1, 'bri.co.id'      => 1,
        'mandiri.co.id'     => 1, 'livin.id'        => 1,
        'danamon.co.id'     => 1, 'bsm.co.id'      => 1,
        'ojk.go.id'         => 1, 'bi.go.id'       => 1,
        'tokopedia.com'     => 1, 'shopee.co.id'   => 1,
        'lazada.co.id'      => 1, 'bukalapak.com'  => 1,
        'gojek.com'         => 1, 'grab.com'       => 1,
        'traveloka.com'     => 1, 'tiket.com'      => 1,
    ];

    static $brands = [
        'paypal', 'google', 'apple', 'facebook', 'amazon', 'microsoft',
        'instagram', 'twitter', 'netflix', 'spotify', 'tiktok', 'whatsapp',
        'linkedin', 'youtube', 'discord', 'telegram', 'dropbox', 'stripe',
        'binance', 'coinbase', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
        'bca', 'mandiri', 'bni', 'bri', 'danamon',
        'tokopedia', 'shopee', 'lazada', 'bukalapak',
        'gojek', 'grab', 'traveloka',
    ];

    foreach ($brands as $brand) {
        if (strpos($domain, $brand) === false) {
            continue;
        }
        // Is it the exact legitimate domain?
        if (isset($legitimateDomains[$domain])) {
            return false;
        }
        // Is it a legitimate subdomain? (e.g. accounts.google.com)
        foreach ($legitimateDomains as $legit => $_) {
            if (str_ends_with($domain, '.' . $legit)) {
                return false;
            }
        }
        // Contains brand but not recognized → phishing
        return true;
    }

    // 7. Free/abused TLDs with no redemptive value
    foreach (['.tk', '.ml', '.ga', '.cf', '.gq'] as $tld) {
        if (str_ends_with($domain, $tld)) {
            return true;
        }
    }

    // 8. Homoglyph / lookalike Unicode in IDN domain
    // e.g. pаypаl.com (Cyrillic а instead of Latin a)
    if (preg_match('/[\x{0400}-\x{04FF}\x{0370}-\x{03FF}\x{4E00}-\x{9FFF}]/u', $domain)) {
        return true;
    }

    return false;
}

// ── Google Safe Browsing API v4 (optional) ─────────────────────
// Enable by setting GSB_API_KEY in .env (Google Cloud Console →
// Enable "Safe Browsing API" → Credentials). Fail-open: if the API
// is unreachable within 2 seconds, the redirect proceeds normally.
function _checkGSB(string $url, string $apiKey): bool
{
    // Returns true if SAFE, false if threat found.
    if (!function_exists('curl_init')) {
        return true; // cURL unavailable → fail-open
    }

    $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode($apiKey);
    $body = json_encode([
        'client'     => ['clientId' => 'notrackng-rdr', 'clientVersion' => '2.0'],
        'threatInfo' => [
            'threatTypes'      => [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            'platformTypes'    => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries'    => [['url' => $url]],
        ],
    ]);

    if (!is_string($body)) {
        return true; // json_encode failed → fail-open
    }

    $ch = curl_init($endpoint);
    if ($ch === false) {
        return true;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => $body,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_TIMEOUT         => 2,  // hard 2-second limit — never block a redirect
        CURLOPT_CONNECTTIMEOUT  => 2,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_HTTPHEADER      => [
            'Content-Type: application/json',
            'Content-Length: ' . strlen($body),
        ],
    ]);

    $resp = curl_exec($ch);
    $curlErr = curl_errno($ch);
    curl_close($ch);

    if ($curlErr !== 0 || !is_string($resp) || $resp === '') {
        return true; // API unreachable → fail-open
    }

    $data = json_decode($resp, true);
    if (!is_array($data)) {
        return true; // malformed response → fail-open
    }

    return empty($data['matches']); // empty = safe, non-empty = threat found
}


// ═══════════════════════════════════════════════════════════════
// 4. BLOCKED DESTINATION PAGE
// ═══════════════════════════════════════════════════════════════

function blockedPage(string $slug, string $reason = 'unsafe'): void
{
    http_response_code(403);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'");
    $safeSlug = htmlspecialchars($slug, ENT_QUOTES, 'UTF-8');
    $messages = [
        'unsafe'    => ['Dangerous Site', 'The destination URL has been detected as a dangerous site and has been blocked to protect you.'],
        'phishing'  => ['Potential Phishing', 'The destination URL has been detected as a phishing page impersonating a legitimate site.'],
        'malware'   => ['Malware Detected', 'The destination URL has been identified as containing or distributing malware.'],
        'blocklist' => ['Blocked Domain', 'The destination domain is on the blocklist.'],
        'gsb'       => ['Flagged by Google Safe Browsing', 'This link has been flagged by Google Safe Browsing as malware, phishing, or unwanted software. This is not a mistake — the destination was reported as dangerous.'],
    ];
    [$title, $desc] = $messages[$reason] ?? $messages['unsafe'];
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>⛔ {$title}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#0f172a;color:#e2e8f0;min-height:100vh;
         display:flex;align-items:center;justify-content:center;padding:1rem}
    .card{background:#1e293b;border:1px solid #dc2626;border-radius:12px;
          padding:2rem;max-width:480px;width:100%;text-align:center}
    .icon{font-size:3rem;margin-bottom:1rem}
    h1{color:#ef4444;font-size:1.4rem;margin-bottom:.75rem}
    p{color:#94a3b8;line-height:1.6;font-size:.95rem}
    .badge{display:inline-block;background:#450a0a;color:#fca5a5;
           border:1px solid #991b1b;border-radius:6px;padding:.25rem .75rem;
           font-size:.8rem;margin-top:1rem;font-family:monospace}
    .back{display:inline-block;margin-top:1.5rem;padding:.6rem 1.4rem;
          background:#1d4ed8;color:#fff;border-radius:8px;border:none;cursor:pointer;
          font-size:.9rem;transition:background .2s}
    .back:hover{background:#2563eb}
    .info{margin-top:1rem;font-size:.8rem;color:#64748b}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⛔</div>
    <h1>{$title}</h1>
    <p>{$desc}</p>
    <div class="badge">/{$safeSlug}</div>
    <br>
    <button type="button" class="back" onclick="history.back()">← Go Back</button>
    <p class="info">If this is an error, contact the administrator.</p>
  </div>
</body>
</html>
HTML;
    exit;
}
