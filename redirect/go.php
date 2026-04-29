<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/runtime_compat.php';

/**
 * go.php - Shortlink Redirect Handler
 * High-traffic optimized + Security hardened:
 *   - Mini WAF (SQLi, XSS, path traversal, bad UA, method restriction)
 *   - Rate limiting per IP + per slug (APCu)
 *   - URL safety: blocklist + heuristics + Google Safe Browsing
 *   - APCu multi-layer cache (link data, resolved URL, negative 404)
 *   - Atomic hit batching via apcu_cas (no race condition)
 *   - MySQL connection timeouts (no hanging requests)
 *   - try-catch on all DB paths (graceful degradation)
 */

/** @param array<string, string> $values */
function goApplyEnvValues(array $values): void
{
    foreach ($values as $key => $value) {
        if (!is_string($key) || $key === '' || !is_string($value)) {
            continue;
        }

        if (getenv($key) !== false) {
            continue;
        }

        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
    }
}

// ── Load .env ──
function goLoadEnvFile(): void
{
    $envFile = __DIR__ . '/../.env';
    if (!is_file($envFile)) {
        return;
    }

    $mtime = (int) (@filemtime($envFile) ?: 0);
    $size = (int) (@filesize($envFile) ?: 0);
    $fingerprint = $mtime . ':' . $size;
    $cacheKey = 'go_env_' . md5($envFile);

    if ($fingerprint !== '0:0') {
        $cacheHit = false;
        $cached = tp_apcu_fetch($cacheKey, $cacheHit);
        if (
            $cacheHit
            && is_array($cached)
            && ($cached['fingerprint'] ?? '') === $fingerprint
            && is_array($cached['values'] ?? null)
        ) {
            goApplyEnvValues($cached['values']);

            return;
        }
    }

    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return;
    }

    $values = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        if (strpos($line, '=') === false) {
            continue;
        }
        [$key, $val] = explode('=', $line, 2);
        $key = trim($key);
        $val = trim($val);
        if ($key === '') {
            continue;
        }

        $values[$key] = $val;
    }

    if ($fingerprint !== '0:0') {
        tp_apcu_store($cacheKey, [
            'fingerprint' => $fingerprint,
            'values' => $values,
        ], 300);
    }

    goApplyEnvValues($values);
}

goLoadEnvFile();

// ── Security module ──
require_once __DIR__ . '/../module/security.php';
$redirectDecisionBootstrap = __DIR__ . '/../src/RedirectDecision/bootstrap.php';
if (is_file($redirectDecisionBootstrap)) {
    require_once $redirectDecisionBootstrap;
}

// ►► WAF: block bad requests before any processing ◄◄
wafCheck();

// ── PDO connection with timeout options ──
function goDb(): ?PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $pdo = tp_pdo_connect(true);
    return $pdo;
}

// ── Get real visitor IP (Cloudflare → X-Forwarded-For → REMOTE_ADDR) ──
function getVisitorIp(): string
{
    $candidates = [
        trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '')),
        trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))[0]),
        trim((string) ($_SERVER['REMOTE_ADDR'] ?? '')),
    ];
    foreach ($candidates as $ip) {
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            return $ip;
        }
    }
    return '';
}

// ── Base64URL encode (RFC 4648 §5, no padding) ──
function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function goTrackerPageNonce(): string
{
    try {
        return base64UrlEncode(tp_random_bytes(16));
    } catch (Throwable $e) {
        return base64UrlEncode((string) microtime(true));
    }
}

function goSendTrackerPageHeaders(string $nonce): void
{
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header(
        "Content-Security-Policy: default-src 'none'; " .
        "script-src 'nonce-" . $nonce . "'; " .
        "style-src 'nonce-" . $nonce . "'; " .
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; connect-src 'none'; img-src 'self' data:"
    );
}

function goTrackerFallbackSecret(): string
{
    // Only use dedicated signing secrets — never fall through to infrastructure
    // credentials (cPanel token, CF token, DB password) as HMAC keys.
    foreach (['APP_TOKEN', 'POSTBACK_SECRET'] as $key) {
        $value = trim((string) getenv($key));
        if ($value !== '') {
            return $value;
        }
    }

    return '';
}

function goTrackerFallbackUrl(string $targetUrl, int $ttlSeconds = 120): string
{
    $secret = goTrackerFallbackSecret();
    if ($secret === '' || !preg_match('/^https?:\/\//i', $targetUrl)) {
        return '';
    }

    $token = tp_redirect_tracker_fallback_token($targetUrl, $secret, time() + $ttlSeconds);
    if ($token === '') {
        return '';
    }

    return '/go.php?rtu=' . rawurlencode($token);
}

function goRenderTrackerLoaderDocument(string $targetUrl, string $fallbackUrl = ''): string
{
    $nonce = goTrackerPageNonce();
    goSendTrackerPageHeaders($nonce);

    $encodedTargetUrl = tp_redirect_tracker_encode_url($targetUrl);
    $encodedJson = json_encode($encodedTargetUrl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    if (!is_string($encodedJson)) {
        $encodedJson = '""';
    }

    // When a fallback token is available we lean on it for everything that is
    // not JS-driven: meta-refresh after 2s (covers silent JS failures),
    // a visible link (covers users who want to act manually), and the legacy
    // noscript block (covers JS disabled entirely). The fallback URL hits
    // go.php?rtu=... which does a server-side 302 so the real target is
    // never exposed in the HTML.
    $metaRefresh = '';
    $manualLink = '';
    $noscript = '<noscript><p class="manual">JavaScript is required to continue automatically.</p></noscript>';
    if ($fallbackUrl !== '') {
        $safeFallbackUrl = htmlspecialchars($fallbackUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $metaRefresh = '<meta http-equiv="refresh" content="1;url=' . $safeFallbackUrl . '">';
        $manualLink = '<a class="manual" href="' . $safeFallbackUrl . '" rel="noreferrer">Continue →</a>';
        $noscript = '<noscript><a class="manual" href="' . $safeFallbackUrl . '" rel="noreferrer">Continue →</a></noscript>';
    }

    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{$metaRefresh}
<title>Redirecting</title>
<style nonce="{$nonce}">
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%;background:#fff}
body{display:flex;align-items:center;justify-content:center;flex-direction:column;font:14px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a}
.ldr{width:48px;height:48px}
.ldr-track{stroke:#e5e7eb}
.ldr-arc{stroke:#2563eb}
@media (prefers-color-scheme:dark){
  body{background:#0b0b0c;color:#e5e7eb}
  .ldr-track{stroke:#1f2937}
  .ldr-arc{stroke:#60a5fa}
}
.manual{margin-top:18px;color:#6b7280;font-size:13px;text-decoration:none;opacity:0;animation:fadein .25s 2s forwards}
.manual:hover{text-decoration:underline}
@keyframes fadein{to{opacity:1}}
@media (prefers-reduced-motion:reduce){
  .manual{opacity:1;animation:none}
}
</style>
</head>
<body>
<svg class="ldr" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Loading">
  <circle class="ldr-track" cx="24" cy="24" r="20" fill="none" stroke-width="4"/>
  <g>
    <circle class="ldr-arc" cx="24" cy="24" r="20" fill="none" stroke-width="4" stroke-linecap="round" stroke-dasharray="31 94"/>
    <animateTransform attributeName="transform" type="rotate" from="0 24 24" to="360 24 24" dur="0.7s" repeatCount="indefinite"/>
  </g>
</svg>
{$manualLink}
{$noscript}
<script nonce="{$nonce}">
(function () {
    try {
        var encoded = {$encodedJson};
        if (!encoded) return;
        var normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
        while (normalized.length % 4 !== 0) {
            normalized += '=';
        }
        var targetUrl = window.atob(normalized);
        // Guard against empty / non-http target so location.replace('')
        // (same-page reload) never fires and meta-refresh takes over.
        if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) return;
        window.location.replace(targetUrl);
    } catch (e) {}
})();
</script>
</body>
</html>
HTML;
}

// ── Build the canonical raw clickid payload (comma-separated) ──
// Format: "subid,country,device,network,ip"
// This exact layout is what recv.php decodes, what the clicks row stores,
// and what postback URL placeholders receive.
function buildClickIdRaw(string $owner, string $country, string $device, string $network, string $ip): string
{
    return implode(',', [$owner, $country, $device, $network, $ip]);
}

// ── Build the base64url-encoded clickid token ──
function buildClickId(string $owner, string $country, string $device, string $network, string $ip): string
{
    return base64UrlEncode(buildClickIdRaw($owner, $country, $device, $network, $ip));
}

function goShortLinksLookupSchemaCacheKey(PDO $db): string
{
    $driver = (string) $db->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite') {
        $identity = __DIR__ . '/../data/sl_data.sqlite';
    } else {
        $identity = (string) getenv('DB_HOST') . '|' . (string) getenv('DB_NAME');
    }

    return 'go_short_links_lookup_schema_' . md5($driver . '|' . $identity);
}

function goShortLinksLookupSql(bool $legacySchema): string
{
    if ($legacySchema) {
        return 'SELECT id, slug, default_url, redirect_url, smartlink_network, smartlink_ids, country_rules,
                    title, description, image, owner, shimlink,
                    \'normal\' AS link_type, \'default\' AS short_service, \'\' AS external_url, 0 AS user_id
                FROM short_links
                WHERE slug = ? AND active = 1
                LIMIT 1';
    }

    return 'SELECT id, slug, default_url, redirect_url, smartlink_network, smartlink_ids, country_rules,
                title, description, image, owner, shimlink, link_type, short_service, external_url, user_id
            FROM short_links
            WHERE slug = ? AND active = 1
            LIMIT 1';
}

/** @return array<string, mixed>|false */
function goFetchShortLink(PDO $db, string $slug): array|false
{
    $cacheKey = goShortLinksLookupSchemaCacheKey($db);
    $cachedLegacy = tp_apcu_fetch($cacheKey, $schemaCacheHit);
    $preferLegacy = $schemaCacheHit && ($cachedLegacy === 1 || $cachedLegacy === true);
    $variants = $preferLegacy ? [true] : [false, true];

    foreach ($variants as $legacySchema) {
        try {
            $statement = $db->prepare(goShortLinksLookupSql($legacySchema));
            $statement->execute([$slug]);
            $row = $statement->fetch();
            tp_apcu_store($cacheKey, $legacySchema ? 1 : 0, 3600);

            return is_array($row) ? $row : false;
        } catch (Throwable $e) {
            if ($legacySchema) {
                throw $e;
            }

            tp_apcu_store($cacheKey, 1, 3600);
        }
    }

    return false;
}


function goFinishClientResponse(): void
{
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();

        return;
    }

    ignore_user_abort(true);
    $body = ob_get_level() > 0 ? (string) ob_get_clean() : '';
    if (!headers_sent()) {
        header('Connection: close');
        header('Content-Length: ' . strlen($body));
    }
    echo $body;
    flush();
}

function goDbCapabilityCacheKey(PDO $db, string $capability): string
{
    return 'go_db_cap_' . md5(goShortLinksLookupSchemaCacheKey($db) . '|' . $capability);
}

function goDbCapabilityBlocked(PDO $db, string $capability): bool
{
    $cached = tp_apcu_fetch(goDbCapabilityCacheKey($db, $capability), $cacheHit);

    return $cacheHit && ($cached === 1 || $cached === true);
}

function goMarkDbCapabilityBlocked(PDO $db, string $capability, int $ttl = 300): void
{
    tp_apcu_store(goDbCapabilityCacheKey($db, $capability), 1, $ttl);
}

function goShouldCacheSchemaFailure(Throwable $e): bool
{
    $message = strtolower(trim($e->getMessage()));
    if ($message === '') {
        return false;
    }

    foreach ([
        'no such table',
        'no such column',
        'has no column named',
        'doesn\'t exist',
        'unknown column',
        'base table or view not found',
        'on conflict clause does not match',
    ] as $needle) {
        if (str_contains($message, $needle)) {
            return true;
        }
    }

    return false;
}

/** @param array<string, mixed> $link */
function goDeferredHumanWork(
    array $link,
    string $country,
    string $visitorDevice,
    string $recordNetwork,
    string $visitorIp
): void {
    $db = goDb();
    if (!$db instanceof PDO) {
        return;
    }

    $clickId = buildClickId(
        (string) ($link['owner'] ?? ''),
        $country,
        $visitorDevice,
        $recordNetwork,
        $visitorIp
    );
    $subid = rawurlencode((string) ($link['owner'] ?? ''));

    if (!goDbCapabilityBlocked($db, 'link_hits')) {
        try {
            if ($db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
                $statement = $db->prepare(
                    'INSERT INTO link_hits (link_id, slug, hit_date, country, device, network, hits)
                     VALUES (?, ?, CURDATE(), ?, ?, ?, 1)
                     ON DUPLICATE KEY UPDATE hits = hits + 1'
                );
            } else {
                $statement = $db->prepare(
                    "INSERT INTO link_hits (link_id, slug, hit_date, country, device, network, hits)
                     VALUES (?, ?, date('now'), ?, ?, ?, 1)
                     ON CONFLICT(link_id, slug, hit_date, country, device, network)
                     DO UPDATE SET hits = hits + 1"
                );
            }

            $statement->execute([
                (int) ($link['id'] ?? 0),
                (string) ($link['slug'] ?? ''),
                $country,
                $visitorDevice,
                $recordNetwork,
            ]);
        } catch (Throwable $e) {
            if (goShouldCacheSchemaFailure($e)) {
                goMarkDbCapabilityBlocked($db, 'link_hits');
            }
        }
    }

    if (!goDbCapabilityBlocked($db, 'clicks')) {
        try {
            $statement = $db->prepare(
                'INSERT INTO clicks (user_id, slug, clickid, subid, country, device, network, ip)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            );
            $statement->execute([
                (int) ($link['user_id'] ?? 0),
                (string) ($link['slug'] ?? ''),
                $clickId,
                $subid,
                $country,
                $visitorDevice,
                $recordNetwork,
                $visitorIp,
            ]);
        } catch (Throwable $e) {
            if (goShouldCacheSchemaFailure($e)) {
                goMarkDbCapabilityBlocked($db, 'clicks');
            }
        }
    }

    $postbackUrls = [];
    $postbackCacheKey = 'sl_pb_click_' . (string) ($link['slug'] ?? '');
    $cachedPostbacks = tp_apcu_fetch($postbackCacheKey, $postbackCacheHit);
    if ($postbackCacheHit && is_array($cachedPostbacks)) {
        $postbackUrls = $cachedPostbacks;
    } elseif (!goDbCapabilityBlocked($db, 'postbacks')) {
        try {
            $limit = max(1, (int) (getenv('POSTBACK_QUERY_LIMIT') ?: 50));
            $statement = $db->prepare(
                "SELECT url FROM postbacks
                 WHERE active = 1 AND event = 'click' AND (slug = ? OR slug = '')
                 LIMIT ?"
            );
            $statement->execute([(string) ($link['slug'] ?? ''), $limit]);
            $rows = $statement->fetchAll(PDO::FETCH_COLUMN);
            $postbackUrls = is_array($rows) ? $rows : [];
            tp_apcu_store($postbackCacheKey, $postbackUrls, 300);
        } catch (Throwable $e) {
            if (goShouldCacheSchemaFailure($e)) {
                goMarkDbCapabilityBlocked($db, 'postbacks');
            }
        }
    }

    if ($postbackUrls === []) {
        return;
    }

    // HMAC signature — matches recv.php canonical:
    //   canonical = clickid|payout|status|subid|ts   (decoded values, pipe-joined)
    // We only sign when POSTBACK_SECRET is set; templates that carry {ts}/{sig}
    // tokens otherwise end up with literal "{ts}"/"{sig}" in the URL, which
    // downstream networks echo back on conversion and recv.php then rejects
    // with "missing or malformed signature".
    $pbTs = (string) time();
    $pbStatus = 'click';
    $pbPayout = '0';
    $pbSig = '';
    $postbackSecret = trim((string) getenv('POSTBACK_SECRET'));
    if ($postbackSecret !== '') {
        $canonical = implode('|', [$clickId, $pbPayout, $pbStatus, $subid, $pbTs]);
        $pbSig = hash_hmac('sha256', $canonical, $postbackSecret);
    }

    $resolvedPostbackUrls = [];
    foreach ($postbackUrls as $postbackUrl) {
        $resolvedUrl = tp_replace_postback_placeholders((string) $postbackUrl, [
            'subid' => $subid,
            'sid' => $subid,
            'sub_id' => $subid,
            's' => $subid,
            'clickid' => rawurlencode($clickId),
            'cid' => rawurlencode($clickId),
            'click_id' => rawurlencode($clickId),
            'c' => rawurlencode($clickId),
            'country' => rawurlencode($country),
            'device' => rawurlencode($visitorDevice),
            'network' => rawurlencode($recordNetwork),
            'slug' => rawurlencode((string) ($link['slug'] ?? '')),
            'payout' => $pbPayout,
            'status' => $pbStatus,
            'ts' => $pbTs,
            'sig' => $pbSig,
        ]);

        if (!filter_var($resolvedUrl, FILTER_VALIDATE_URL)) {
            continue;
        }

        $resolvedPostbackUrls[] = $resolvedUrl;
    }

    tp_enqueue_postbacks($resolvedPostbackUrls);
}

// ── Shimlink wrapper — apply at redirect time ──
// Wraps a destination URL inside a trusted host's open-redirect endpoint
// ("l.wl.co" or "l.facebook.com"). This is applied as the very last step
// of the redirect flow for humans so that:
//   1. Smart routing / country_rules still see the real destination
//   2. The URL safety check inspects the real destination, not the wrapper
//   3. The wrapper stays in sync with the `shimlink` column in the DB —
//      editing shimlink on an existing link takes effect immediately
//      (previously the wrapper was baked into default_url at CREATE time
//       which meant smart-routed URLs and updates bypassed it).
function applyShimlink(string $url, string $shimlink): string
{
    return match ($shimlink) {
        'wl'    => 'https://l.wl.co/l?u='            . rawurlencode($url),
        'fb'    => 'https://l.facebook.com/l.php?u=' . rawurlencode($url),
        default => $url,
    };
}

// ── Strip legacy shimlink wrapping ──
// Older rows in `short_links` may have default_url pre-wrapped because
// sl.php used to bake the shimlink prefix at CREATE time. This helper
// detects that wrapping and returns the raw inner URL so we can run the
// safety check on the real destination and re-wrap fresh at the end of
// the redirect flow. Idempotent — calling on an un-wrapped URL is a no-op.
function unwrapShimlink(string $url): string
{
    if ($url === '') {
        return $url;
    }
    // l.wl.co: u= is the only query param we emit, but be tolerant of extras.
    if (preg_match('#^https?://l\.wl\.co/l\?u=([^&]+)#i', $url, $m)) {
        $decoded = rawurldecode($m[1]);
        if (filter_var($decoded, FILTER_VALIDATE_URL)) {
            return $decoded;
        }
    }
    // l.facebook.com: FB also appends &h=... &s=... — we only care about u=.
    if (preg_match('#^https?://l\.facebook\.com/l\.php\?u=([^&]+)#i', $url, $m)) {
        $decoded = rawurldecode($m[1]);
        if (filter_var($decoded, FILTER_VALIDATE_URL)) {
            return $decoded;
        }
    }
    return $url;
}

// ── Replace subid / clickid placeholders in destination URL ──
// Called AFTER smart routing, BEFORE safety check.
// Smart routing result (with placeholders intact) is cached; replacement is per-visitor.
//
// Supported aliases (all case-insensitive):
//   subid   → {subid}   {sid}   {sub_id}   {s}     = rawurlencode(owner)
//   clickid → {clickid} {cid}   {click_id} {c}     = base64url(subid,country,device,network,ip)
/** @param array<string, string> $ctx */
function replacePlaceholders(string $url, array $ctx): string
{
    // Fast path — no placeholders at all
    if (strpos($url, '{') === false) {
        return $url;
    }
    // Quick pre-check: must contain at least one alias
    $needles = ['{subid}', '{sid}', '{sub_id}', '{s}', '{clickid}', '{cid}', '{click_id}', '{c}'];
    $hasAny  = false;
    foreach ($needles as $n) {
        if (stripos($url, $n) !== false) {
            $hasAny = true;
            break;
        }
    }
    if (!$hasAny) {
        return $url;
    }

    $owner   = (string) ($ctx['owner']   ?? '');
    $country = (string) ($ctx['country'] ?? '');
    $device  = (string) ($ctx['device']  ?? '');
    $network = (string) ($ctx['network'] ?? '');
    $ip      = (string) ($ctx['ip']      ?? '');

    $subid   = rawurlencode($owner);
    $clickid = buildClickId($owner, $country, $device, $network, $ip);

    $map = [
        '{subid}'    => $subid,
        '{sid}'      => $subid,
        '{sub_id}'   => $subid,
        '{s}'        => $subid,
        '{clickid}'  => $clickid,
        '{cid}'      => $clickid,
        '{click_id}' => $clickid,
        '{c}'        => $clickid,
    ];

    // Case-insensitive replace for all aliases in one pass.
    return preg_replace_callback(
        '/\{(subid|sid|sub_id|s|clickid|cid|click_id|c)\}/i',
        static function (array $m) use ($map): string {
            $key = '{' . strtolower($m[1]) . '}';
            return $map[$key] ?? $m[0];
        },
        $url
    ) ?? $url;
}

// ── Detect traffic source network ──
function detectNetworkSource(): string
{
    $utmSource = strtolower($_GET['utm_source'] ?? '');
    $utmMedium = strtolower($_GET['utm_medium'] ?? '');
    $referer   = strtolower($_SERVER['HTTP_REFERER'] ?? '');
    if ($utmSource || $utmMedium) {
        $combined = $utmSource . ' ' . $utmMedium;
        if (preg_match('/facebook|fb|instagram|ig|meta/', $combined)) {
            return 'Facebook';
        }
        if (preg_match('/google|gads|cpc|adwords/', $combined)) {
            return 'Google';
        }
        if (preg_match('/tiktok/', $combined)) {
            return 'TikTok';
        }
        if (preg_match('/twitter|x\.com/', $combined)) {
            return 'Twitter';
        }
        if (preg_match('/snapchat/', $combined)) {
            return 'Snapchat';
        }
        if (preg_match('/youtube/', $combined)) {
            return 'YouTube';
        }
        return strtolower($utmSource) ?: 'direct';
    }
    if ($referer) {
        if (preg_match('/facebook\.com|fb\.com|instagram\.com|l\.facebook\.com|lm\.facebook/', $referer)) {
            return 'Facebook';
        }
        if (preg_match('/tiktok\.com/', $referer)) {
            return 'TikTok';
        }
        if (preg_match('/google\./', $referer)) {
            return 'Google';
        }
        if (preg_match('/bing\./', $referer)) {
            return 'Bing';
        }
        if (preg_match('/yahoo\./', $referer)) {
            return 'Yahoo';
        }
        if (preg_match('/twitter\.com|t\.co|x\.com/', $referer)) {
            return 'Twitter';
        }
        if (preg_match('/youtube\.com/', $referer)) {
            return 'YouTube';
        }
        if (preg_match('/snapchat\.com/', $referer)) {
            return 'Snapchat';
        }
        // Unknown referrer → use referrer domain as network name
        $host = parse_url($_SERVER['HTTP_REFERER'] ?? '', PHP_URL_HOST) ?: '';
        return $host ? preg_replace('/^www\./', '', strtolower($host)) : 'Referral';
    }
    return 'Direct';
}

// ── Detect device ──
function detectDevice(string $ua): string
{
    return preg_match('/Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i', $ua)
        ? 'wap' : 'web';
}

function normalizeCountryCode(string $countryCode): string
{
    $normalized = strtoupper(trim($countryCode));
    if (preg_match('/^[A-Z]{2}$/', $normalized) !== 1) {
        return '';
    }

    return $normalized;
}

function detectVpnTraffic(): bool
{
    $countryCode = strtoupper(trim((string) ($_SERVER['HTTP_CF_IPCOUNTRY'] ?? '')));
    if ($countryCode === 'T1') {
        return true;
    }

    $headers = [
        $_SERVER['HTTP_X_TRAFFIC_VPN'] ?? '',
        $_SERVER['HTTP_X_VPN'] ?? '',
        $_SERVER['HTTP_X_PROXY'] ?? '',
        $_SERVER['HTTP_CF_VPN'] ?? '',
    ];

    foreach ($headers as $headerValue) {
        $normalized = strtolower(trim((string) $headerValue));
        if (in_array($normalized, ['1', 'true', 'yes', 'on'], true)) {
            return true;
        }
    }

    return false;
}

function goNetworkProfileResolver(): ?\App\RedirectDecision\NetworkProfileResolver
{
    static $resolver = false;

    if ($resolver !== false) {
        return $resolver;
    }

    if (
        !class_exists(\App\RedirectDecision\NetworkProfileResolver::class)
        || !class_exists(\App\RedirectDecision\NetworkProfileResolverFactory::class)
    ) {
        $resolver = null;

        return $resolver;
    }

    $geoLitePath = trim((string) getenv('GEOLITE2_COUNTRY_DB'));
    if ($geoLitePath === '') {
        $geoLitePath = __DIR__ . '/../data/geoip/GeoLite2-Country.mmdb';
    }

    $cacheRepository = null;
    $db = goDb();
    if ($db instanceof PDO) {
        $cacheRepository = new \App\RedirectDecision\Cache\PdoNetworkProfileCacheRepository($db);
    } else {
        $cachePath = trim((string) getenv('REDIRECT_PROFILE_CACHE_DB'));
        if ($cachePath === '') {
            $cachePath = __DIR__ . '/../data/geoip/network_profile_cache.sqlite';
        }
        $cacheRepository = new \App\RedirectDecision\Cache\NetworkProfileCacheRepository($cachePath);
    }

    $resolver = (new \App\RedirectDecision\NetworkProfileResolverFactory(
        $geoLitePath,
        trim((string) getenv('IPTOASN_ENDPOINT')),
        $cacheRepository,
        (int) (getenv('REDIRECT_PROFILE_CACHE_TTL') ?: 21600)
    ))->create();

    return $resolver;
}

/** @param array<string, string> $server */
function resolveVisitorNetworkProfile(string $ip, array $server): \App\RedirectDecision\Value\NetworkProfile
{
    $resolver = goNetworkProfileResolver();
    if ($resolver === null) {
        return new \App\RedirectDecision\Value\NetworkProfile();
    }

    try {
        return $resolver->resolve($ip, $server);
    } catch (Throwable $e) {
        return new \App\RedirectDecision\Value\NetworkProfile();
    }
}

function goDecisionAuditRepository(): ?\App\RedirectDecision\Audit\PdoDecisionAuditRepository
{
    static $repository = false;

    if ($repository !== false) {
        return $repository;
    }

    $db = goDb();
    if (!$db instanceof PDO) {
        $repository = null;

        return $repository;
    }

    $repository = new \App\RedirectDecision\Audit\PdoDecisionAuditRepository($db);

    return $repository;
}

function goDecisionAuditSampleRate(): int
{
    $sampleRate = (int) (getenv('REDIRECT_DECISION_AUDIT_SAMPLE_RATE') ?: 10);
    if ($sampleRate < 0) {
        return 0;
    }

    if ($sampleRate > 100) {
        return 100;
    }

    return $sampleRate;
}

function shouldSampleDecisionAudit(string $slug, string $ip, int $sampleRate, int $bucketUnix): bool
{
    if ($sampleRate <= 0) {
        return false;
    }

    if ($sampleRate >= 100) {
        return true;
    }

    $hash = crc32($slug . '|' . $ip . '|' . (string) $bucketUnix);

    return (((int) $hash) & 0x7FFFFFFF) % 100 < $sampleRate;
}

function extractUrlHost(string $url): string
{
    if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
        return '';
    }

    $host = parse_url($url, PHP_URL_HOST);

    return is_string($host) ? strtolower($host) : '';
}

/** @return array<string, bool> */
function goTrafficProfile(string $ua): array
{
    $socialAppPattern = '/WhatsApp|Instagram|Threads|\bFBAN\b|\bFBAV\b|FB_IAB|FBIOS/i';
    $botPattern = '/facebookexternalhit|facebookcatalog|Facebot|facebookbot|LinkedInBot|Twitterbot|Slackbot|TelegramBot|Discordbot|Googlebot|bingbot|Applebot|redditbot/i';

    $isSocialApp = $ua !== '' && preg_match($socialAppPattern, $ua) === 1;
    // Empty UA treated as bot: no hit count, no postback, no click recorded.
    $isBot = $ua === '' || (!$isSocialApp && preg_match($botPattern, $ua) === 1);

    return [
        'is_social_app' => $isSocialApp,
        'is_bot' => $isBot,
    ];
}

/**
 * @param array<string, mixed> $link
 * @param array<string, mixed> $decisionResult
 */
function recordDecisionAudit(
    array $link,
    array $decisionResult,
    \App\RedirectDecision\Value\NetworkProfile $networkProfile,
    string $country,
    string $visitorDevice,
    string $visitorNetwork,
    string $visitorIp,
    string $targetUrl,
    string $filterRedirectUrl,
    string $deliveryOutcome
): void {
    $repository = goDecisionAuditRepository();
    if ($repository === null) {
        return;
    }

    $createdAtUnix = time();
    $bucketUnix = (int) floor($createdAtUnix / 60) * 60;
    $sampleRate = goDecisionAuditSampleRate();
    $decision = trim((string) ($decisionResult['decision'] ?? 'normal'));
    $window = $decisionResult['window'] ?? [];
    $windowMode = is_array($window) ? trim((string) ($window['mode'] ?? 'unknown')) : 'unknown';
    $reasons = $decisionResult['reasons'] ?? [];
    $primaryReason = is_array($reasons) && isset($reasons[0]) ? (string) $reasons[0] : 'none';

    try {
        $repository->record([
            'created_at_unix' => $createdAtUnix,
            'link_id' => (int) ($link['id'] ?? 0),
            'slug' => (string) ($link['slug'] ?? ''),
            'decision' => $decision,
            'primary_reason' => $primaryReason,
            'window_mode' => $windowMode,
            'delivery_outcome' => $deliveryOutcome,
            'country_code' => $country,
            'device' => $visitorDevice,
            'visitor_network' => $visitorNetwork,
            'is_vpn_like' => $networkProfile->isVpnLike(),
            'is_bot' => $decision === 'meta_tag',
            'profile_country_code' => $networkProfile->countryCode(),
            'profile_asn' => $networkProfile->asn(),
            'profile_organization' => $networkProfile->organization(),
            'provider_sources' => $networkProfile->sources(),
            'reasons' => is_array($reasons) ? $reasons : [],
            'target_host' => extractUrlHost($targetUrl),
            'redirect_host' => extractUrlHost($filterRedirectUrl),
        ], shouldSampleDecisionAudit((string) ($link['slug'] ?? ''), $visitorIp, $sampleRate, $bucketUnix));
    } catch (Throwable $e) {
        return;
    }
}

/** @return array<string, mixed> */
function goCachedOgImageInfo(string $rawUrl, int $timeout = 2): array
{
    if ($rawUrl === '') {
        return ['url' => '', 'mime' => '', 'w' => 0, 'h' => 0];
    }

    $cacheKey = 'go_ogimg_' . md5($rawUrl);
    $cached = tp_apcu_fetch($cacheKey, $cacheHit);
    if ($cacheHit && is_array($cached)) {
        return [
            'url' => is_string($cached['url'] ?? null) ? $cached['url'] : '',
            'mime' => is_string($cached['mime'] ?? null) ? $cached['mime'] : '',
            'w' => is_int($cached['w'] ?? null) ? $cached['w'] : 0,
            'h' => is_int($cached['h'] ?? null) ? $cached['h'] : 0,
        ];
    }

    $resolved = _resolveOgImageUrl($rawUrl, $timeout);
    tp_apcu_store($cacheKey, $resolved, 300);

    return $resolved;
}

function goSmartlinkCountryCsvExpression(PDO $db, string $column): string
{
    $normalized = "REPLACE(UPPER(COALESCE({$column}, 'ALL')), ' ', '')";
    if ($db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        return "(',' || {$normalized} || ',')";
    }

    return "CONCAT(',', {$normalized}, ',')";
}

function goSmartlinkNetworkWhereSql(PDO $db): string
{
    if ($db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        return "LOWER(COALESCE(network, '')) = ?";
    }

    return 'network = ?';
}

function goSmartlinkCountryScoreSql(PDO $db, string $column): string
{
    $csvExpression = goSmartlinkCountryCsvExpression($db, $column);

    return "CASE
        WHEN ? <> '' AND {$csvExpression} LIKE ? THEN 4
        WHEN {$csvExpression} LIKE '%,ALL,%' THEN 2
        ELSE 0
    END";
}

function goSmartlinkCountryPattern(string $country): string
{
    return '%,' . strtoupper(trim($country)) . ',%';
}

/** @return array<int, string> */
function goSmartlinkDeviceVariants(string $device): array
{
    $normalized = strtolower(trim($device));
    if ($normalized === 'wap') {
        return ['wap', 'mobile'];
    }

    if ($normalized === 'web') {
        return ['web', 'desktop'];
    }

    if ($normalized === 'mobile') {
        return ['mobile', 'wap'];
    }

    if ($normalized === 'desktop') {
        return ['desktop', 'web'];
    }

    return [$normalized, $normalized];
}

function goSmartlinkDeviceScoreSql(string $column): string
{
    return "CASE
        WHEN LOWER(COALESCE({$column}, '')) IN (?, ?) THEN 2
        WHEN LOWER(COALESCE({$column}, '')) IN ('all', 'both') THEN 1
        ELSE 0
    END";
}

// ── Append extra params to a resolved smartlink URL ──
// params is a raw query-string fragment, e.g. "aff_click_id={clickid}&sub1={subid}".
// Placeholders are replaced later by replacePlaceholders(); this just appends the string.
function goAppendSmartlinkParams(string $url, string $params): string
{
    $params = trim($params);
    if ($params === '') {
        return $url;
    }
    $sep = (strpos($url, '?') !== false) ? '&' : '?';
    return $url . $sep . $params;
}

// ── Resolve smartlink by network name ──
function resolveSmartlinkByNetwork(PDO $db, string $network, string $device, string $country): ?string
{
    $network = trim($network);
    if ($network === '') {
        return null;
    }

    [$primaryDevice, $secondaryDevice] = goSmartlinkDeviceVariants($device);
    $countryScoreSql = goSmartlinkCountryScoreSql($db, 'country');
    $deviceScoreSql = goSmartlinkDeviceScoreSql('device');
    $networkWhereSql = goSmartlinkNetworkWhereSql($db);
    $stmt = $db->prepare(
        "SELECT url, COALESCE(params,'') AS params
         FROM smartlinks
         WHERE {$networkWhereSql}
         ORDER BY ({$countryScoreSql} + {$deviceScoreSql}) DESC, id ASC
         LIMIT 1"
    );
    $stmt->execute([
        $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? strtolower($network) : $network,
        $country,
        goSmartlinkCountryPattern($country),
        $primaryDevice,
        $secondaryDevice,
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !is_string($row['url']) || $row['url'] === '') {
        return null;
    }

    return goAppendSmartlinkParams($row['url'], (string) ($row['params'] ?? ''));
}

// ── Resolve smartlink by IDs ──
/** @param array<int, int> $ids */
function resolveSmartlinkUrl(PDO $db, array $ids, string $network, string $device, string $country): ?string
{
    $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static function (int $id): bool {
        return $id > 0;
    })));
    if ($ids === []) {
        return null;
    }

    [$primaryDevice, $secondaryDevice] = goSmartlinkDeviceVariants($device);
    $countryScoreSql = goSmartlinkCountryScoreSql($db, 'country');
    $deviceScoreSql = goSmartlinkDeviceScoreSql('device');
    $networkScoreSql = "CASE
        WHEN LOWER(COALESCE(network, '')) = ? THEN 8
        WHEN LOWER(COALESCE(network, '')) IN ('all', 'direct') THEN 1
        ELSE 0
    END";
    $ph = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $db->prepare(
        "SELECT url, COALESCE(params,'') AS params
         FROM smartlinks
         WHERE id IN ({$ph})
         ORDER BY ({$networkScoreSql} + {$countryScoreSql} + {$deviceScoreSql}) DESC, id ASC
         LIMIT 1"
    );
    $stmt->execute(array_merge($ids, [
        strtolower(trim($network)),
        $country,
        goSmartlinkCountryPattern($country),
        $primaryDevice,
        $secondaryDevice,
    ]));
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !is_string($row['url']) || $row['url'] === '') {
        return null;
    }

    return goAppendSmartlinkParams($row['url'], (string) ($row['params'] ?? ''));
}

// ════════════════════════════════════════════════════════════════════════
// REDIRECT FLOW — go.php
// ════════════════════════════════════════════════════════════════════════
//
//  [1] LOAD ENV        → read DB credentials from .env file
//  [2] SECURITY / WAF  → block dangerous requests before any processing
//  [3] SLUG EXTRACTION → get link identifier from PATH_INFO or ?s=
//  [4] RATE LIMIT      → limit frequency per-IP and per-slug
//  [5] LINK LOOKUP     → look up link data: negative cache → positive cache → DB
//  [6] DETECT VISITOR  → UA, country (Cloudflare header), network, device
//  [7] SMART ROUTING   → choose destination URL based on network/device/country
//                         routing result cached in APCu 120 seconds per combination
//  [8] PLACEHOLDER     → replace {subid} & {clickid} after routing (per-visitor)
//  [9] SAFETY CHECK    → block dangerous destination URLs (humans only)
// [10] HIT COUNT       → record clicks atomically via APCu batch (batch=100)
// [11] BOT → OG PAGE  → bot crawlers get an HTML page with OG meta
// [12] HUMAN → 200     → loader page with client-side redirect
//
// ════════════════════════════════════════════════════════════════════════

// [2b] Rate-limit by IP before any branch (including ?rtu= fallback).
rateLimitByIp(120);

$fallbackToken = is_string($_GET['rtu'] ?? null) ? trim($_GET['rtu']) : '';
if ($fallbackToken !== '') {
    $fallbackTargetUrl = tp_redirect_tracker_resolve_fallback_token(
        $fallbackToken,
        goTrackerFallbackSecret(),
        time()
    );
    if ($fallbackTargetUrl === '') {
        http_response_code(410);
        exit('Redirect token expired.');
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Location: ' . $fallbackTargetUrl, true, 302);
    exit;
}

// ─────────────────────────────────────────────────
// [3] SLUG EXTRACTION
// Get slug from PATH_INFO (/abc) or query string (?s=abc).
// Slug may only contain letters, digits, hyphens, underscores (max 30 chars).
// ─────────────────────────────────────────────────
$slug = '';
if (!empty($_GET['s'])) {
    $slug = $_GET['s'];
} elseif (!empty($_SERVER['PATH_INFO'])) {
    $slug = ltrim($_SERVER['PATH_INFO'], '/');
}
if (!preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $slug)) {
    http_response_code(400);
    exit('Invalid slug.');
}

// ─────────────────────────────────────────────────
// [4] RATE LIMIT (per-slug)
// Per-IP limit already applied above. Slug limit: 300 req/min.
// Counters stored in APCu with 60-second TTL.
// If APCu is unavailable, the limit is bypassed (fail-open).
// ─────────────────────────────────────────────────
rateLimitBySlug($slug, 300);

// ─────────────────────────────────────────────────
// [5] LINK LOOKUP — three-layer cache:
//   a) Negative cache (sl_404_{slug})  → slug not found, immediate 404 (TTL 60s)
//   b) Positive cache (sl_link_{slug}) → link data already stored (TTL 300s)
//   c) Database                        → query DB on cache miss, then store to cache
// ─────────────────────────────────────────────────
$cacheKey    = 'sl_link_' . $slug;
$notFoundKey = 'sl_404_'  . $slug;
$link = false;

if (function_exists('tp_apcu_fetch')) {
    // (a) Negative cache: slug was looked up before and not found
    if (tp_apcu_fetch($notFoundKey) !== false) {
        http_response_code(404);
        exit('Link not found.');
    }
    // (b) Positive cache: link data already in APCu
    $link = tp_apcu_fetch($cacheKey);
}

if ($link === false) {
    // (c) Cache miss → query DB
    $db = goDb();
    if (!$db) {
        http_response_code(503);
        exit('Service unavailable.');
    }
    try {
        $link = goFetchShortLink($db, $slug);
    } catch (Throwable $e) {
        http_response_code(503);
        exit('Service unavailable.');
    }
    if ($link !== false) {
        // Store in positive cache, 300 seconds
        if (function_exists('tp_apcu_store')) {
            tp_apcu_store($cacheKey, $link, 300);
        }
    } else {
        // Store in negative cache, 60 seconds → avoid repeated DB queries for missing slugs
        if (function_exists('tp_apcu_store')) {
            tp_apcu_store($notFoundKey, 1, 60);
        }
    }
}

if (!$link) {
    http_response_code(404);
    exit('Link not found.');
}

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$trafficProfile = goTrafficProfile($ua);
$isSocialApp = !empty($trafficProfile['is_social_app']);
$isBot = !empty($trafficProfile['is_bot']);

// ─────────────────────────────────────────────────
// [6] DETECT VISITOR
// Detect visitor characteristics for smart routing:
//   - $ua            : User-Agent string (also used for bot detection)
//   - $country       : 2-letter country code from Cloudflare header (CF-IPCountry)
//   - $visitorNetwork: Traffic source from UTM params / referrer (fb, google, direct, …)
//   - $visitorDevice : Device type — 'wap' (mobile) or 'web' (desktop)
// ─────────────────────────────────────────────────
$visitorIp = getVisitorIp();
if ($isBot) {
    $networkProfile = new \App\RedirectDecision\Value\NetworkProfile();
    $country = '';
    $visitorNetwork = 'crawler';
    $visitorDevice = 'web';
    $isVpnTraffic = false;
} else {
    $networkProfile = resolveVisitorNetworkProfile($visitorIp, $_SERVER);
    $country = normalizeCountryCode($networkProfile->countryCode());
    $visitorNetwork = detectNetworkSource();
    $visitorDevice = detectDevice($ua);
    $isVpnTraffic = $networkProfile->isVpnLike() || detectVpnTraffic();
}

// ─────────────────────────────────────────────────
// [7] SMART ROUTING — choose best destination URL
// Resolution priority:
//   A) smartlink_network → look up smartlink by affiliate network name
//      (iMonetizeit / Lospollos / Trafee) + country & device score
//   B) smartlink_ids     → look up from specific smartlink ID list,
//      match network/country/device with scoring system
//   C) country_rules     → JSON map {CC: url} for per-country redirect
//   D) default_url       → fallback if no rule matches
//
// Routing result cached in APCu per combination (link_id + network + device + country)
// for 120 seconds. The cache stores the URL with placeholders intact
// so it does not pollute the cache across visitors (replacement done at [8]).
// ─────────────────────────────────────────────────
$targetUrl = $link['default_url'];

// ── External short service (IXG / is.gd / v.gd / TinyURL) ──
// external_url is the IXG/is.gd URL that SENDS traffic to this slug (not the redirect target).
// Flow: external_url → local slug (go.php here) → default_url with placeholders replaced.
// So go.php always processes default_url — external_url is not used for redirect.

// Per-link cache version lets update_link invalidate ALL smart-routing
// variants (every network/device/country combo) in one shot by bumping
// `sl_link_ver_{id}` — otherwise we would need a wildcard delete that APCu
// does not support. Reads of a missing version key default to 0.
$linkCacheVersion = 0;
if (function_exists('tp_apcu_fetch')) {
    $verHit = false;
    $verRaw = tp_apcu_fetch('sl_link_ver_' . $link['id'], $verHit);
    if ($verHit && is_int($verRaw)) {
        $linkCacheVersion = $verRaw;
    }
}
$urlCacheKey  = 'sl_url_' . $link['id'] . '_v' . $linkCacheVersion
              . '_' . $visitorNetwork . '_' . $visitorDevice . '_' . $country;
$cachedTarget = false;
if (function_exists('tp_apcu_fetch')) {
    $cachedTarget = tp_apcu_fetch($urlCacheKey);
}

if ($isBot) {
    $cachedTarget = false;
} elseif ($cachedTarget !== false) {
    // Cache hit → use previously resolved URL
    $targetUrl = $cachedTarget;
} else {
    // Cache miss → resolve URL from DB
    try {
        if (!empty($link['smartlink_network'])) {
            // (A) Routing by affiliate network stored on the link
            $db       = goDb();
            $resolved = $db ? resolveSmartlinkByNetwork($db, $link['smartlink_network'], $visitorDevice, $country) : null;
            if ($resolved) {
                $targetUrl = $resolved;
            }
        } elseif (!empty($link['smartlink_ids'])) {
            // (B) Routing by specific smartlink ID list
            $decoded = json_decode($link['smartlink_ids'], true);
            if (is_array($decoded) && !empty($decoded)) {
                $ids      = array_slice(array_map('intval', $decoded), 0, 100);
                $db       = goDb();
                $resolved = $db ? resolveSmartlinkUrl($db, $ids, $visitorNetwork, $visitorDevice, $country) : null;
                if ($resolved) {
                    $targetUrl = $resolved;
                }
            }
        } elseif (!empty($link['country_rules'])) {
            // (C) Routing by country map → URL
            $rules = json_decode($link['country_rules'], true);
            if (is_array($rules) && $country !== '' && isset($rules[$country])) {
                $targetUrl = $rules[$country];
            }
        }
        // (D) No match → $targetUrl remains $link['default_url']
    } catch (Throwable $e) {
        // DB error during routing → keep using default_url (fail-open)
        // Increment persistent error counter so dashboard/healthz can surface this.
        if (function_exists('tp_apcu_add') && function_exists('tp_apcu_inc')) {
            tp_apcu_add('go_routing_errors', 0, 3600);
            tp_apcu_inc('go_routing_errors');
        }
    }
    // Store routing result URL in APCu for 120 seconds (placeholders intact)
    if (function_exists('tp_apcu_store')) {
        tp_apcu_store($urlCacheKey, $targetUrl, 120);
    }
}

// ─────────────────────────────────────────────────
// [7.5] UNWRAP LEGACY SHIMLINK
// Some older rows have `default_url` pre-wrapped with l.wl.co or l.facebook.com
// because a previous version of sl.php baked the wrapper at CREATE time.
// Strip it so placeholder replacement and the URL safety check always operate
// on the raw destination URL.
// The shimlink wrapper now lives in `external_url` (applied at CREATE/UPDATE time
// in sl.php) — go.php no longer re-wraps the destination.
// Idempotent — a no-op for fresh un-wrapped URLs and smart-routed URLs.
// ─────────────────────────────────────────────────
$targetUrl = unwrapShimlink($targetUrl);

// ─────────────────────────────────────────────────
// Compute effective network ONCE — used consistently in:
//   - [8]  placeholder replacement (clickid in destination URL)
//   - [10b] link_hits analytics recording
//   - [10d] clicks table recording
//   - [12]  postback URL placeholders
// Uses !empty() so that empty string '' falls through to $visitorNetwork,
// and appends 'Direct' fallback when both are empty.
// ─────────────────────────────────────────────────
$effectiveNetwork = !empty($link['smartlink_network']) && !$isBot ? $link['smartlink_network'] : $visitorNetwork;
$recordNetwork    = $effectiveNetwork ?: 'Direct';

// ─────────────────────────────────────────────────
// [8] PLACEHOLDER REPLACEMENT — per-visitor, after cache
// Aliases (case-insensitive):
//   subid   → {subid} {sid} {sub_id} {s}   = rawurlencode(owner)
//   clickid → {clickid} {cid} {click_id} {c}
//             = base64url("subid,country,device,network,ip")
//             - subid   : link owner username
//             - country : visitor country code (ID, US, SG, …)
//             - device  : 'wap' (mobile) or 'web' (desktop)
//             - network : effective network (smartlink_network → visitor network → Direct)
//             - ip      : real visitor IP (Cloudflare → X-Forwarded-For → REMOTE_ADDR)
// Replacement is done AFTER routing cache so the cache is not contaminated
// with per-visitor specific values.
// ─────────────────────────────────────────────────
if (!$isBot) {
    $targetUrl = replacePlaceholders($targetUrl, [
        'owner'   => $link['owner'] ?? '',
        'country' => $country,
        'device'  => $visitorDevice,
        'ip'      => $visitorIp,
        'network' => $recordNetwork,
    ]);
}

// Resolve the filter redirect URL:
//   1. Per-link `redirect_url` (legacy — no longer editable from the user UI)
//   2. Fall back to admin-wide `filter_redirect_url` from data/config.json
//      (cached in APCu for 120s to avoid disk hit on every click)
$filterRedirectUrl = '';
if (!$isBot) {
    $linkRedirectUrl = trim((string) ($link['redirect_url'] ?? ''));
    if ($linkRedirectUrl === '') {
        $adminFilterUrl = '';
        $adminCfgKey    = 'tp:admin_filter_redirect_url';
        $cached         = function_exists('tp_apcu_fetch') ? tp_apcu_fetch($adminCfgKey) : false;
        if ($cached !== false && is_string($cached)) {
            $adminFilterUrl = $cached;
        } else {
            $adminCfgPath = __DIR__ . '/../data/config.json';
            if (is_file($adminCfgPath)) {
                $adminCfg = json_decode((string) @file_get_contents($adminCfgPath), true);
                if (is_array($adminCfg)) {
                    $adminFilterUrl = trim((string) ($adminCfg['filter_redirect_url'] ?? ''));
                }
            }
            if (function_exists('tp_apcu_store')) {
                tp_apcu_store($adminCfgKey, $adminFilterUrl, 120);
            }
        }
        $linkRedirectUrl = $adminFilterUrl;
    }
    $filterRedirectUrl = replacePlaceholders($linkRedirectUrl, [
        'owner'   => $link['owner'] ?? '',
        'country' => $country,
        'device'  => $visitorDevice,
        'ip'      => $visitorIp,
        'network' => $recordNetwork,
    ]);
}

// ─────────────────────────────────────────────────
// [9] URL SAFETY CHECK — humans only
// Bot crawlers (Facebook, Google, Telegram, etc.) skip this check
// because they need the OG page for link preview.
// For humans: check URL via blocklist + heuristics + Google Safe Browsing (optional).
// If unsafe → show warning page (blockedPage() calls exit()).
// Check result cached in APCu: safe=3600s, unsafe=86400s.
// ─────────────────────────────────────────────────
$decisionResult = [
    'decision' => $isBot ? 'meta_tag' : 'normal',
    'window' => ['mode' => 'legacy'],
    'reasons' => [$isBot ? 'bot_meta_tag' : 'legacy_normal'],
];

if (!$isBot && class_exists('RedirectDecision')) {
    try {
        $decision = RedirectDecision::evaluate(
            RedirectDecision::loadConfig(),
            [
                'device' => $visitorDevice,
                'country' => $country,
                'is_vpn' => $isVpnTraffic,
                'is_bot' => $isBot,
                'redirect_url' => $filterRedirectUrl,
            ]
        );
        $decisionResult = $decision;

        $decisionUrl = $decision['redirect_url'] ?? null;
        if (
            ($decision['decision'] ?? '') === 'redirect_url'
            && is_string($decisionUrl)
            && trim($decisionUrl) !== ''
        ) {
            $targetUrl = $decisionUrl;
        }
    } catch (Throwable $e) {
        // Fail-open to normal routing if the redirect decision module errors.
        // Log + increment a counter so persistent breakage is visible in ops
        // dashboards instead of silently hiding behind the fallback. The
        // decisionResult is replaced with an explicit 'error' marker so the
        // audit row records which requests took the fallback path.
        error_log(sprintf(
            'RedirectDecision error: slug=%s link_id=%s ex=%s msg=%s',
            $slug,
            (string) ($link['id'] ?? ''),
            get_class($e),
            $e->getMessage()
        ));
        if (function_exists('tp_apcu_inc')) {
            if (function_exists('tp_apcu_add')) {
                tp_apcu_add('redirect_decision_errors', 0, 3600);
            }
            tp_apcu_inc('redirect_decision_errors');
        }
        $decisionResult = [
            'decision' => 'normal',
            'window' => ['mode' => 'error'],
            'reasons' => ['decision_engine_error:' . get_class($e)],
        ];
    }
}

// $effectiveNetwork and $recordNetwork already computed before [8]

if (!$isBot) {
    if (!isDestinationSafe($targetUrl)) {
        $blockReason = getUrlBlockReason($targetUrl);
        recordDecisionAudit(
            $link,
            $decisionResult,
            $networkProfile,
            $country,
            $visitorDevice,
            $effectiveNetwork,
            $visitorIp,
            $targetUrl,
            $filterRedirectUrl,
            'blocked_' . $blockReason
        );
        blockedPage($slug, $blockReason);
    }

    recordDecisionAudit(
        $link,
        $decisionResult,
        $networkProfile,
        $country,
        $visitorDevice,
        $effectiveNetwork,
        $visitorIp,
        $targetUrl,
        $filterRedirectUrl,
        'redirect'
    );
} else {
    recordDecisionAudit(
        $link,
        $decisionResult,
        $networkProfile,
        $country,
        $visitorDevice,
        $effectiveNetwork,
        $visitorIp,
        $targetUrl,
        '',
        'bot_og_page'
    );
}

// ─────────────────────────────────────────────────
// [10] HIT COUNTING — atomic batched, no race condition
// Strategy:
//   - If APCu available: increment APCu counter per request (very fast).
//     When counter reaches 100 → flush to DB at once via apcu_cas (atomic swap).
//     apcu_cas ensures only one process flushes (others continue incrementing).
//     If apcu_cas unavailable → flush at exact multiple of 100 (fallback).
//     If DB fails during flush → restore counter value to APCu.
//   - If APCu unavailable: UPDATE directly to DB per request (degraded mode).
// Bots are not counted to avoid inflating statistics.
// ─────────────────────────────────────────────────
if (!$isBot) {
    $hitKey = 'sl_hits_' . $link['id'];
    if (function_exists('tp_apcu_add')) {
        tp_apcu_add($hitKey, 0);            // initialize counter if not yet set
        $newHits = tp_apcu_inc($hitKey);    // increment by 1, get new value
        if ($newHits >= 100) {
            // Attempt atomic swap: set counter to 0, flush $newHits to DB
            if (function_exists('tp_apcu_cas') && tp_apcu_cas($hitKey, $newHits, 0)) {
                try {
                    $db = goDb();
                    if ($db) {
                        $db->prepare('UPDATE short_links SET hits = hits + ? WHERE id = ?')
                                    ->execute([$newHits, $link['id']]);
                    }
                } catch (Throwable $e) {
                    tp_apcu_inc($hitKey, $newHits); // DB failed → restore counter
                }
            } elseif (!function_exists('tp_apcu_cas')) {
                // Fallback without apcu_cas: flush accumulated hits and reset counter.
                // Store 0 first, then flush. If DB fails, counter restarts from 0
                // (acceptable trade-off vs. the old exact-multiple-of-100 approach
                // which systematically undercounted under high traffic).
                if (function_exists('tp_apcu_store')) {
                    tp_apcu_store($hitKey, 0);
                }
                try {
                    $db = goDb();
                    if ($db) {
                        $db->prepare('UPDATE short_links SET hits = hits + ? WHERE id = ?')
                                    ->execute([$newHits, $link['id']]);
                    }
                } catch (Throwable $e) {
                }
            }
        }
    } else {
        // APCu unavailable → UPDATE directly, one query per click
        try {
            $db = goDb();
            if ($db) {
                $db->prepare('UPDATE short_links SET hits = hits + 1 WHERE id = ?')
                            ->execute([$link['id']]);
            }
        } catch (Throwable $e) {
        }
    }
}

// ─────────────────────────────────────────────────
// [11] BOT → OG META PAGE
// Bot crawlers need HTML with OG meta to generate link previews
// (Facebook thumbnail, Twitter card, Telegram preview, etc.).
// This page contains all OG/Twitter card meta + meta refresh to destination URL.
// Cached by crawlers for 300 seconds (Cache-Control: public, max-age=300).
// ─────────────────────────────────────────────────

function _extractImageMime(string $contentType): string
{
    if (preg_match('#(image/[a-z0-9.+\-]+)#i', $contentType, $m) === 1) {
        return strtolower($m[1]);
    }

    return '';
}

/** @return array<string, mixed> */
function _probeOgImageUrl(string $rawUrl, bool $headOnly, int $timeout): array
{
    $empty = ['url' => '', 'mime' => '', 'w' => 0, 'h' => 0];
    $ch = curl_init($rawUrl);
    if ($ch === false) {
        return $empty;
    }

    $options = [
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT      => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        CURLOPT_HTTPHEADER     => [
            'Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Encoding: identity',
        ],
    ];

    if ($headOnly) {
        $options[CURLOPT_NOBODY] = true;
    } else {
        $options[CURLOPT_HTTPGET] = true;
        $options[CURLOPT_RANGE]   = '0-0';
    }

    curl_setopt_array($ch, $options);
    curl_exec($ch);

    $finalUrl    = (string) (curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: '');
    $httpCode    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    if ($httpCode < 200 || $httpCode >= 300) {
        return $empty;
    }

    $mime = _extractImageMime($contentType);
    if ($mime === '') {
        return $empty;
    }

    return ['url' => $finalUrl, 'mime' => $mime, 'w' => 0, 'h' => 0];
}

/**
 * Safely resolve og:image:
 * - follow redirects
 * - only accept 2xx final response
 * - only accept MIME image/*
 * - if HEAD is inconclusive, fall back to lightweight GET
 * - if still fails, omit og:image
 * @return array<string, mixed>
 */
function _resolveOgImageUrl(string $rawUrl, int $timeout = 2): array
{
    if ($rawUrl === '' || filter_var($rawUrl, FILTER_VALIDATE_URL) === false) {
        return ['url' => '', 'mime' => '', 'w' => 0, 'h' => 0];
    }

    if (!function_exists('curl_init')) {
        return ['url' => '', 'mime' => '', 'w' => 0, 'h' => 0];
    }

    $headProbe = _probeOgImageUrl($rawUrl, true, $timeout);
    if ($headProbe['url'] !== '' && $headProbe['mime'] !== '') {
        return $headProbe;
    }

    return _probeOgImageUrl($rawUrl, false, $timeout);
}

if ($isBot) {
    $fbAppId     = htmlspecialchars(trim((string) getenv('FB_APP_ID')) ?: '115190258555800', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $rawTitle       = trim((string) ($link['title'] ?? ''));
    $rawDescription = trim((string) ($link['description'] ?? ''));
    $title          = htmlspecialchars($rawTitle, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $description    = htmlspecialchars($rawDescription, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $url         = htmlspecialchars($targetUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $scheme      = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host        = preg_replace('/[^a-zA-Z0-9.\-:_]/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    $canonical   = htmlspecialchars($scheme . '://' . $host . $_SERVER['REQUEST_URI'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    // ── Resolve og:image ────────────────────────────────────────
    // We route all og:image requests through our own proxy `ogimg.php`.
    // The proxy fetches the origin image server-side with
    // `Accept-Encoding: identity` and streams raw bytes to the crawler —
    // this works around Facebook's inability to decode Brotli / zstd
    // responses that Cloudflare-fronted origins often return
    // ("crawler menerima pengkodean konten deflate and gzip" error).
    //
    // We still probe the raw URL first so we can advertise the right
    // `og:image:type` MIME — this helps Facebook pick a better preview.
    $rawImage   = (string)($link['image'] ?? '');
    $imageInfo  = $rawImage ? goCachedOgImageInfo($rawImage) : ['url' => '', 'mime' => '', 'w' => 0, 'h' => 0];
    $imageMime  = htmlspecialchars($imageInfo['mime'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $hasImage   = $rawImage !== '';

    // Build the public proxy URL (absolute — scrapers won't resolve relatives).
    $proxyImageUrl = '';
    if ($hasImage) {
        $proxyImageUrl = htmlspecialchars(
            $scheme . '://' . $host . '/ogimg.php?s=' . rawurlencode((string) $link['slug']),
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );
    }

    // ── Build og:image meta tags ────────────────────────────────
    $ogImageTags = '';
    if ($proxyImageUrl) {
        $ogImageTags .= "    <meta property=\"og:image\" content=\"{$proxyImageUrl}\">\n";
        $ogImageTags .= "    <meta property=\"og:image:secure_url\" content=\"{$proxyImageUrl}\">\n";
        if ($imageMime) {
            $ogImageTags .= "    <meta property=\"og:image:type\" content=\"{$imageMime}\">\n";
        }
        $ogImageTags .= "    <meta property=\"og:image:alt\" content=\"{$title}\">\n";
        $ogImageTags .= "    <meta name=\"twitter:image\" content=\"{$proxyImageUrl}\">\n";
    }

    $twitterCard = $proxyImageUrl ? 'summary_large_image' : 'summary';

    // Explicit 200 OK — Facebook debugger / other scrapers need a success code.
    http_response_code(200);
    header('Content-Type: text/html; charset=UTF-8');
    // no-store so intermediate caches (Cloudflare, CDN, browser) do NOT hold
    // on to an old OG page after the admin edits title/description/image.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    // Cloudflare-specific hint to skip tiered caching.
    header('CDN-Cache-Control: no-store');
    // Vary on UA so bot/human branches don't share a cache key.
    header('Vary: User-Agent');
    // Hint search engines/scrapers that this URL is crawlable.
    header('X-Robots-Tag: all');
    // Security headers — page contains no scripts, styles, or external resources.
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    echo <<<HTML
<!DOCTYPE html>
<html>
  <head prefix="og: https://ogp.me/ns#">
    <meta charset="utf-8">
    <meta name="robots" content="all">
    <title>{$title}</title>
    <meta name="description" content="{$description}">
    <meta property="og:title" content="{$title}">
    <meta property="og:type" content="website">
    <meta property="og:url" content="{$canonical}">
    <meta property="og:description" content="{$description}">
    {$ogImageTags}
    <meta name="twitter:card" content="{$twitterCard}">
    <meta name="twitter:title" content="{$title}">
    <meta name="twitter:description" content="{$description}">
    <meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="{$fbAppId}">
    <link rel="canonical" href="{$canonical}">
  </head>
</html>
HTML;
    exit;
}

// ─────────────────────────────────────────────────
// [12] HUMAN → 200 REDIRECT LOADER + POSTBACK QUEUE
// ─────────────────────────────────────────────────
if (!preg_match('/^https?:\/\//i', $targetUrl)) {
    http_response_code(400);
    exit('Invalid destination URL.');
}

// [11.5] SHIMLINK — wrapper now applied at CREATE/UPDATE time (sl.php).
// The shimlink wraps the *local shortlink URL* (e.g. l.wl.co/l?u=n1qln.../WWaSAPv)
// and is stored in `external_url`, NOT applied here.
// go.php only needs to unwrap legacy rows (step [7.5]) and serve the raw destination.

// ─────────────────────────────────────────────────
// [12a] LANDING PAGE — show intermediate click-through page
// Serve a landing page with a button instead of direct redirect.
// Hit counting ([10]/[10b]) already ran above; postbacks queued below.
// ─────────────────────────────────────────────────
if (($link['link_type'] ?? 'normal') === 'lp') {
    // Wrap destination URL in a 1-hour HMAC-signed token so the raw target
    // is not visible in the page source. Falls back to the raw URL only when
    // the signing secret (APP_TOKEN / POSTBACK_SECRET) is not configured.
    $lpWrappedUrl = goTrackerFallbackUrl($targetUrl, 3600);
    $lpHref       = htmlspecialchars(
        $lpWrappedUrl !== '' ? $lpWrappedUrl : $targetUrl,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
    $lpTitle      = htmlspecialchars((string) ($link['title'] ?: ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $scheme       = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host         = preg_replace('/[^a-zA-Z0-9.\-:_]/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    $lpBase       = $scheme . '://' . $host;

    http_response_code(200);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    ob_start();
    echo <<<HTML
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>{$lpTitle}</title>
<meta name="viewport" content="user-scalable=false, initial-scale=1.0, maximum-scale=1.0">
<link href="{$lpBase}/assets/lp.favicon.ico" rel="icon" type="image/x-icon">
<link rel="stylesheet" type="text/css" href="{$lpBase}/assets/reset.min.css">
<link rel="stylesheet" type="text/css" href="{$lpBase}/assets/lp.style.css">
<script type="text/javascript" src="{$lpBase}/assets/jquery.min.js"></script>
<script type="text/javascript" src="{$lpBase}/assets/translates.js"></script>
</head>
<body>
<div class="layout">
  <main class="main-block">
    <div class="steps-wrap">
      <div class="steps">
        <div class="steps-content">
          <div class="step-item" style="display:block;">
            <h2 class="step-title text16">Attention!</h2>
            <p class="step-subtitle text17">wants to exchange candid photos with you.</p>
            <p class="step-subtitle text18">You confirm?</p>
            <div class="btns-wrap">
              <a class="btn btn-sec text19" href="{$lpHref}">YES</a>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="bg">
      <div class="bg-stage">
        <img src="{$lpBase}/assets/bg-lg.jpg" alt="">
        <img src="{$lpBase}/assets/bg-lg.jpg" alt="">
        <img src="{$lpBase}/assets/bg-lg.jpg" alt="">
      </div>
    </div>
  </main>
</div>
<div id="wrp-id"></div>
</body>
</html>
HTML;

    goFinishClientResponse();
    goDeferredHumanWork($link, (string) $country, (string) $visitorDevice, (string) $recordNetwork, (string) $visitorIp);
    exit;
}

$fallbackUrl = goTrackerFallbackUrl($targetUrl);

http_response_code(200);
ob_start();
echo goRenderTrackerLoaderDocument($targetUrl, $fallbackUrl);

goFinishClientResponse();
goDeferredHumanWork($link, (string) $country, (string) $visitorDevice, (string) $recordNetwork, (string) $visitorIp);
exit;
