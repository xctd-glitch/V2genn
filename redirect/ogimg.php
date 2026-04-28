<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/runtime_compat.php';
require_once __DIR__ . '/../module/security.php';

/**
 * ogimg.php — Open Graph image proxy.
 *
 * Purpose
 * ───────
 * Some origin servers (or CDNs like Cloudflare) serve images with encodings
 * that Facebook's scraper cannot decode (e.g. Brotli `br`). When that
 * happens, the Facebook Sharing Debugger reports:
 *
 *     "og:image yang disediakan tidak dapat diunduh ...
 *      crawler menerima pengkodean konten deflate and gzip"
 *
 * This endpoint solves that by proxying the image through our own server:
 *   1. Look up the shortlink's `image` URL from the database.
 *   2. Fetch it via cURL (Accept-Encoding: identity so the origin
 *      returns raw bytes — no gzip / deflate / br / zstd).
 *   3. Stream the raw bytes back to the requesting scraper with a clean
 *      Content-Type header.
 *
 * Result: Facebook (and every other crawler) always sees plain bytes served
 * with a well-known MIME, regardless of how the origin stores/encodes it.
 *
 * URL format
 * ──────────
 *   /ogimg.php?s={slug}
 *
 * Response
 * ────────
 *   200 OK      + image/jpeg|png|gif|webp|avif  → image bytes (success)
 *   302 Found                                    → fallback to origin (last-resort)
 *   404 / 400   + text/plain                     → error
 *
 * Caching
 * ───────
 *   - Resolved image URL + MIME cached in APCu for 600 seconds per slug.
 *   - Response has `Cache-Control: public, max-age=86400` so FB's CDN
 *     holds on to it.
 */

// ── Load .env ──
tp_load_env_file(__DIR__ . '/../.env');

// ── DB connection ──────────────────────────────────────────────
function ogimgDb(): ?PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $host = getenv('DB_HOST') ?: 'localhost';
    $user = getenv('DB_USER') ?: '';
    $pass = getenv('DB_PASS') ?: '';
    $name = getenv('DB_NAME') ?: '';
    if (!$user || !$name) {
        return null;
    }

    try {
        $opts = tp_mysql_pdo_options();
        $connectTimeoutAttr = tp_pdo_mysql_attr('MYSQL_ATTR_CONNECT_TIMEOUT');
        if ($connectTimeoutAttr !== null) {
            $opts[$connectTimeoutAttr] = 3;
        }
        $initCommandAttr = tp_pdo_mysql_attr('MYSQL_ATTR_INIT_COMMAND');
        if ($initCommandAttr !== null) {
            $opts[$initCommandAttr] = "SET SESSION net_read_timeout=5, net_write_timeout=5";
        }
        $pdo = new PDO("mysql:host={$host};dbname={$name};charset=utf8mb4", $user, $pass, $opts);
    } catch (Throwable $e) {
        $pdo = null;
    }

    return $pdo;
}

// ── Extract MIME from "image/jpeg; charset=binary" etc. ────────
function ogimgExtractMime(string $contentType): string
{
    if (preg_match('#(image/[a-z0-9.+\-]+)#i', $contentType, $m) === 1) {
        return strtolower($m[1]);
    }

    return '';
}

// ── Very small placeholder PNG (1x1 transparent) for errors ────
function ogimgServePlaceholder(int $httpCode = 404): void
{
    http_response_code($httpCode);
    header('Content-Type: image/png');
    header('Cache-Control: public, max-age=60');
    // 1x1 transparent PNG, 67 bytes
    $png = base64_decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII='
    );
    echo $png;
    exit;
}

// ── Disk cache helpers ─────────────────────────────────────────
// APCu tops out at ~4 MB per entry and disappears on PHP-FPM restart.
// A tiny filesystem cache catches images that are too big for APCu and
// keeps them warm across deploys. Files live in data/ogimg_cache/ as
// `{slug}.bin` + `{slug}.mime`. Entries are considered fresh for 24 h.
function ogimgDiskCacheDir(): string
{
    return __DIR__ . '/../data/ogimg_cache';
}

/** @return array<string, mixed>|null */
function ogimgDiskCacheRead(string $slug): ?array
{
    if (!preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $slug)) {
        return null;
    }
    $dir = ogimgDiskCacheDir();
    $bodyFile = $dir . '/' . $slug . '.bin';
    $mimeFile = $dir . '/' . $slug . '.mime';
    if (!is_file($bodyFile) || !is_file($mimeFile)) {
        return null;
    }
    $mtime = @filemtime($bodyFile);
    if ($mtime === false || (time() - $mtime) > 86400) {
        // Stale — let the caller refresh it.
        return null;
    }
    $body = @file_get_contents($bodyFile);
    $mime = trim((string) @file_get_contents($mimeFile));
    if (!is_string($body) || $body === '' || $mime === '') {
        return null;
    }

    return ['body' => $body, 'mime' => $mime];
}

function ogimgDiskCacheWrite(string $slug, string $body, string $mime): void
{
    if (!preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $slug)) {
        return;
    }
    if ($body === '' || $mime === '') {
        return;
    }
    $dir = ogimgDiskCacheDir();
    if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
        return;
    }
    // Atomic write: temp then rename so readers never see a half-written file.
    $bodyTmp = $dir . '/.tmp_' . $slug . '_' . bin2hex(random_bytes(4)) . '.bin';
    $mimeTmp = $dir . '/.tmp_' . $slug . '_' . bin2hex(random_bytes(4)) . '.mime';
    if (@file_put_contents($bodyTmp, $body) === false) {
        return;
    }
    if (@file_put_contents($mimeTmp, $mime) === false) {
        @unlink($bodyTmp);
        return;
    }
    @rename($bodyTmp, $dir . '/' . $slug . '.bin');
    @rename($mimeTmp, $dir . '/' . $slug . '.mime');
}

// ── SSRF guard ─────────────────────────────────────────────────
// Returns true only if $url is safe to fetch from the server side:
//   - scheme must be http or https
//   - resolved IP must not be in private/reserved ranges
// This prevents fetching internal services (MySQL, metadata endpoints, etc.)
// even when the image URL is stored in the DB by an admin.
/**
 * Validate the URL and resolve the hostname to a safe public IP.
 * Returns the resolved IP string on success, or null if unsafe.
 * The caller should pass this IP to CURLOPT_RESOLVE to pin cURL to the same
 * address that was validated, preventing DNS rebinding between validation and fetch.
 */
function ogimgSafeResolve(string $url): ?string
{
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return null;
    }

    $host = (string) parse_url($url, PHP_URL_HOST);
    if ($host === '') {
        return null;
    }

    // Strip IPv6 brackets: [::1] → ::1
    if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
        $host = substr($host, 1, -1);
    }

    // Direct IP literal — validate range immediately without DNS
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
            ? $host
            : null;
    }

    // Resolve hostname and validate the resulting IP.
    $resolved = gethostbyname($host);
    if ($resolved === $host) {
        return null; // DNS resolution failed — reject to be safe
    }

    return filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        ? $resolved
        : null;
}

function ogimgIsSafeUrl(string $url): bool
{
    return ogimgSafeResolve($url) !== null;
}

// ── Fetch image via curl with identity encoding ────────────────
// Returns ['body' => string, 'mime' => string] on success, or null on failure.
/** @return array<string, string>|null */
function ogimgFetch(string $url, int $timeout = 6): ?array
{
    if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    // Resolve hostname once and pin cURL to that IP via CURLOPT_RESOLVE.
    // This closes the DNS rebinding window between validation and actual fetch.
    $resolvedIp = ogimgSafeResolve($url);
    if ($resolvedIp === null) {
        return null;
    }

    if (!function_exists('curl_init')) {
        return null;
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return null;
    }

    // Build CURLOPT_RESOLVE entry: "host:port:ip" so cURL never re-resolves.
    $host = (string) parse_url($url, PHP_URL_HOST);
    $port = (int) (parse_url($url, PHP_URL_PORT) ?: (strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'https' ? 443 : 80));
    $resolvePin = [$host . ':' . $port . ':' . $resolvedIp];

    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 5,
        CURLOPT_TIMEOUT         => $timeout,
        CURLOPT_CONNECTTIMEOUT  => 4,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        // Pin the resolved IP — prevents DNS rebinding between validation and fetch.
        CURLOPT_RESOLVE         => $resolvePin,
        // Restrict curl to HTTP/HTTPS — blocks file://, ftp://, dict://, gopher://, etc.
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        // Mimic a browser — some CDNs serve different responses to "curl".
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; OGImageProxy/1.0; +https://www.facebook.com/externalhit_uatext.php)',
        CURLOPT_HTTPHEADER     => [
            // identity → tell origin NOT to compress. We want plain bytes.
            'Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Encoding: identity',
            'Accept-Language: en-US,en;q=0.9',
            'Cache-Control: no-cache',
        ],
        // Cap download size to 10 MB to prevent abuse.
        CURLOPT_NOPROGRESS     => false,
        CURLOPT_PROGRESSFUNCTION => static function ($ch, $dlTotal, $dlNow) {
            return $dlNow > 10 * 1024 * 1024 ? 1 : 0;
        },
    ]);

    $body     = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ctype    = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    if (!is_string($body) || $body === '') {
        return null;
    }
    if ($httpCode < 200 || $httpCode >= 300) {
        return null;
    }

    $mime = ogimgExtractMime($ctype);
    if ($mime === '') {
        // Fallback: sniff MIME from magic bytes
        $mime = ogimgSniffMime($body);
    }
    if ($mime === '') {
        return null;
    }

    return ['body' => $body, 'mime' => $mime];
}

// ── MIME sniffing for common image formats ─────────────────────
function ogimgSniffMime(string $body): string
{
    $head = substr($body, 0, 16);
    if ($head === '') {
        return '';
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (str_starts_with($head, "\x89PNG\r\n\x1a\n")) {
        return 'image/png';
    }
    // JPEG: FF D8 FF
    if (str_starts_with($head, "\xFF\xD8\xFF")) {
        return 'image/jpeg';
    }
    // GIF: GIF87a / GIF89a
    if (str_starts_with($head, 'GIF87a') || str_starts_with($head, 'GIF89a')) {
        return 'image/gif';
    }
    // WebP: RIFF....WEBP
    if (str_starts_with($head, 'RIFF') && substr($body, 8, 4) === 'WEBP') {
        return 'image/webp';
    }
    // BMP
    if (str_starts_with($head, 'BM')) {
        return 'image/bmp';
    }
    // AVIF / HEIC: ....ftypavif / ....ftypheic
    if (substr($body, 4, 4) === 'ftyp') {
        $brand = substr($body, 8, 4);
        if ($brand === 'avif') {
            return 'image/avif';
        }
        if ($brand === 'heic' || $brand === 'heix' || $brand === 'mif1') {
            return 'image/heic';
        }
    }
    // SVG (XML text)
    if (stripos($head, '<svg') !== false || stripos($head, '<?xml') !== false) {
        return 'image/svg+xml';
    }

    return '';
}

// ── Main ───────────────────────────────────────────────────────
$slug = trim((string) ($_GET['s'] ?? ''));
if (!preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $slug)) {
    ogimgServePlaceholder(400);
}

// ── Rate limit ────────────────────────────────────────────────
// Each request streams up to 4 MB of cached image bytes, so unbounded hits
// can be abused as a bandwidth-amplification vector and fill APCu.
// Cap: 60 req/min per IP and 180 req/min per slug.
// APCu counters auto-expire after 60 seconds; fail-open if APCu missing.
rateLimitByIp(60);
rateLimitBySlug('ogimg_' . $slug, 180);

// Look up image URL from DB (APCu cached 10 minutes)
$cacheKey = 'og_img_url_' . $slug;
$imageUrl = '';

if (function_exists('tp_apcu_fetch')) {
    $cached = tp_apcu_fetch($cacheKey);
    if (is_string($cached)) {
        $imageUrl = $cached;
    }
}

if ($imageUrl === '') {
    $db = ogimgDb();
    if (!$db) {
        ogimgServePlaceholder(503);
    }
    try {
        $stmt = $db->prepare('SELECT image FROM short_links WHERE slug = ? AND active = 1 LIMIT 1');
        $stmt->execute([$slug]);
        $row = $stmt->fetch();
        $imageUrl = (string) ($row['image'] ?? '');
    } catch (Throwable $e) {
        ogimgServePlaceholder(503);
    }

    if (function_exists('tp_apcu_store')) {
        // Cache even empty string so repeated lookups on missing slugs are cheap.
        tp_apcu_store($cacheKey, $imageUrl, 600);
    }
}

if ($imageUrl === '' || filter_var($imageUrl, FILTER_VALIDATE_URL) === false || !ogimgIsSafeUrl($imageUrl)) {
    ogimgServePlaceholder(404);
}

// Cached image bytes? (APCu 1 hour → fallback to disk cache 24 h)
$bodyKey = 'og_img_body_' . $slug;
$mimeKey = 'og_img_mime_' . $slug;

$body = false;
$mime = '';
if (function_exists('tp_apcu_fetch')) {
    $body = tp_apcu_fetch($bodyKey);
    $mime = (string) tp_apcu_fetch($mimeKey);
}

// Disk cache as second-tier fallback — survives PHP restarts and holds
// payloads that were too big for APCu.
if (!is_string($body) || $body === '' || $mime === '') {
    $diskHit = ogimgDiskCacheRead($slug);
    if ($diskHit !== null) {
        $body = $diskHit['body'];
        $mime = $diskHit['mime'];
        // Warm APCu for the next request if the payload fits.
        if (strlen($body) <= 4 * 1024 * 1024 && function_exists('tp_apcu_store')) {
            tp_apcu_store($bodyKey, $body, 3600);
            tp_apcu_store($mimeKey, $mime, 3600);
        }
    }
}

if (!is_string($body) || $body === '' || $mime === '') {
    $result = ogimgFetch($imageUrl);
    if ($result === null) {
        // Fallback: 302 to origin — safe because $imageUrl already passed ogimgIsSafeUrl().
        // Re-check scheme defensively in case the function above is ever bypassed.
        $fallbackScheme = strtolower((string) parse_url($imageUrl, PHP_URL_SCHEME));
        if (!in_array($fallbackScheme, ['http', 'https'], true)) {
            ogimgServePlaceholder(400);
        }
        http_response_code(302);
        header('Location: ' . $imageUrl);
        header('Cache-Control: no-store');
        exit;
    }

    $body = $result['body'];
    $mime = $result['mime'];

    // Tier 1: APCu — only if payload is ≤ 4 MB to respect APCu memory.
    if (strlen($body) <= 4 * 1024 * 1024 && function_exists('tp_apcu_store')) {
        tp_apcu_store($bodyKey, $body, 3600);
        tp_apcu_store($mimeKey, $mime, 3600);
    }
    // Tier 2: disk — always cache so oversized images don't re-fetch every hit.
    ogimgDiskCacheWrite($slug, $body, $mime);
}

http_response_code(200);
header('Content-Type: ' . $mime);
header('Content-Length: ' . strlen($body));
header('Cache-Control: public, max-age=86400, immutable');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: all');
// Explicitly NO Content-Encoding header — body is raw identity bytes.
echo $body;
