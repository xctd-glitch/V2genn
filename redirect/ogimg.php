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
 *   200 OK      + image/jpeg|png|gif|webp|avif  → image bytes (success or fallback asset)
 *
 * Crawler responses always return image bytes from this endpoint —
 * we never 302 to the origin URL (that would let Facebook see and
 * cache the raw origin URL instead of /ogimg.php).
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
    static $pdo = false;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    if ($pdo === null) {
        return null;
    }

    $connection = tp_pdo_connect(true);
    if (!$connection instanceof PDO) {
        $pdo = null;
        return null;
    }

    $pdo = $connection;
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

// ── Non-empty fallback image for crawler previews ───────────────
/**
 * Always terminates the request via `exit;`. The `never` return type lets
 * static analysis (PHPStan, IDEs) know callers are unreachable past this
 * point — prevents null-deref regressions if a future refactor accidentally
 * adds an early `return;` without `exit`.
 */
function ogimgServePlaceholder(int $httpCode = 200): never
{
    $fallbackFiles = [
        __DIR__ . '/../assets/logo.png',
        __DIR__ . '/../assets/android-chrome-512x512.png',
        __DIR__ . '/../assets/bg-lg.jpg',
    ];

    foreach ($fallbackFiles as $fallbackFile) {
        if (!is_file($fallbackFile)) {
            continue;
        }

        $body = @file_get_contents($fallbackFile);
        if (!is_string($body) || $body === '') {
            continue;
        }

        $mime = ogimgSniffMime($body);
        if ($mime === '') {
            continue;
        }

        http_response_code($httpCode);
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . strlen($body));
        header('Cache-Control: public, max-age=300');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: all');
        echo $body;
        exit;
    }

    http_response_code($httpCode);
    header('Content-Type: image/png');
    header('Cache-Control: public, max-age=60');
    // 1x1 transparent PNG, 67 bytes
    $png = base64_decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=',
        true
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
    $resolvedIps = ogimgSafeResolveAll($url);

    return $resolvedIps[0] ?? null;
}

/**
 * @return list<string>
 */
function ogimgSafeResolveAll(string $url): array
{
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return [];
    }

    $host = (string) parse_url($url, PHP_URL_HOST);
    if ($host === '') {
        return [];
    }

    // Strip IPv6 brackets: [::1] → ::1
    if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
        $host = substr($host, 1, -1);
    }

    // Direct IP literal — validate range immediately without DNS
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return [];
        }

        return [$host];
    }

    $candidates = [];
    $records = @dns_get_record($host, DNS_A);
    if (is_array($records)) {
        foreach ($records as $record) {
            $ip = (string) ($record['ip'] ?? '');
            if ($ip !== '') {
                $candidates[] = $ip;
            }
        }
    }

    // Keep gethostbyname() as a fallback for hosts where dns_get_record() is disabled.
    $resolved = gethostbyname($host);
    if ($resolved !== $host) {
        $candidates[] = $resolved;
    }

    $safeIps = [];
    foreach (array_values(array_unique($candidates)) as $candidate) {
        $isPublicIp = filter_var(
            $candidate,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if (
            filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            && $isPublicIp !== false
        ) {
            $safeIps[] = $candidate;
        }
    }

    return $safeIps;
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

    // Resolve every public A record and pin cURL to each validated IP in turn.
    // This keeps the SSRF guard while avoiding false fallback when a CDN's
    // first DNS answer is temporarily unreachable from the hosting network.
    $resolvedIps = ogimgSafeResolveAll($url);
    if ($resolvedIps === []) {
        return null;
    }

    if (!function_exists('curl_init')) {
        return null;
    }

    // Build CURLOPT_RESOLVE entry: "host:port:ip" so cURL never re-resolves.
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    $host = (string) parse_url($url, PHP_URL_HOST);
    $port = (int) (parse_url($url, PHP_URL_PORT) ?: ($scheme === 'https' ? 443 : 80));

    foreach ($resolvedIps as $resolvedIp) {
        $ch = curl_init($url);
        if ($ch === false) {
            continue;
        }

        $resolveIp = str_contains($resolvedIp, ':') ? '[' . $resolvedIp . ']' : $resolvedIp;
        $resolvePin = [$host . ':' . $port . ':' . $resolveIp];

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
            CURLOPT_IPRESOLVE       => CURL_IPRESOLVE_V4,
            // Restrict curl to HTTP/HTTPS — blocks file://, ftp://, dict://, gopher://, etc.
            CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            // Use a normal browser UA; some image CDNs reject custom proxy/bot UAs.
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                . 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            // Same-origin Referer — passes anti-hotlink RewriteCond on tenant
            // domains whose .htaccess allowlists their own host. Without this,
            // cURL sends an empty Referer and Apache returns 403 for any image
            // outside /assets/.
            CURLOPT_REFERER        => $scheme . '://' . $host . '/',
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

        $body = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $ctype = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        if (!is_string($body) || $body === '') {
            continue;
        }
        if ($httpCode < 200 || $httpCode >= 300) {
            continue;
        }

        $mime = ogimgExtractMime($ctype);
        if ($mime === '') {
            // Fallback: sniff MIME from magic bytes
            $mime = ogimgSniffMime($body);
        }
        if ($mime === '') {
            continue;
        }

        return ['body' => $body, 'mime' => $mime];
    }

    return null;
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
    ogimgServePlaceholder();
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
        ogimgServePlaceholder();
    }
    try {
        $stmt = $db->prepare('SELECT image FROM short_links WHERE slug = ? AND active = 1 LIMIT 1');
        $stmt->execute([$slug]);
        $row = $stmt->fetch();
        $imageUrl = (string) ($row['image'] ?? '');
    } catch (Throwable $e) {
        ogimgServePlaceholder();
    }

    if (function_exists('tp_apcu_store')) {
        // Cache even empty string so repeated lookups on missing slugs are cheap.
        tp_apcu_store($cacheKey, $imageUrl, 600);
    }
}

if ($imageUrl === '' || filter_var($imageUrl, FILTER_VALIDATE_URL) === false || !ogimgIsSafeUrl($imageUrl)) {
    ogimgServePlaceholder();
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
        // Keep crawlers on /ogimg.php even when the origin image is unavailable.
        ogimgServePlaceholder();
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
