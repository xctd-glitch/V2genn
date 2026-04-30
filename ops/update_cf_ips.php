<?php

declare(strict_types=1);

/**
 * update_cf_ips.php — Refresh Cloudflare edge IP ranges.
 *
 * Cron usage (daily):
 *   0 3 * * * /usr/bin/php /path/to/ops/update_cf_ips.php >> /var/log/cf_ips.log 2>&1
 *
 * Behaviour:
 *   - Fetches https://www.cloudflare.com/ips-v4 and ips-v6 with a hard 10s
 *     network budget. Refuses to overwrite the existing list when either
 *     source returns no entries (avoids wiping the trust list on transient
 *     network failure).
 *   - Writes data/cf_ips.json atomically (temp file + rename).
 *   - Used by tp_request_via_cloudflare() in bootstrap/runtime_compat.php
 *     to decide whether to trust HTTP_CF_CONNECTING_IP / HTTP_X_FORWARDED_FOR.
 */

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_runtime_harden();

function cfIpsExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, '[update_cf_ips] ' . $message . PHP_EOL);
    exit($code);
}

/**
 * @return array<int, string>
 */
function cfIpsFetchList(string $url): array
{
    if (!function_exists('curl_init')) {
        throw new RuntimeException('cURL extension is required.');
    }

    $curl = curl_init($url);
    if ($curl === false) {
        throw new RuntimeException('curl_init failed for ' . $url);
    }

    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FAILONERROR => true,
        CURLOPT_USERAGENT => 'notrackng-cf-ips-updater/1.0',
    ]);

    $body = curl_exec($curl);
    $errno = curl_errno($curl);
    $error = curl_error($curl);
    curl_close($curl);

    if ($errno !== 0 || !is_string($body)) {
        throw new RuntimeException("Failed to fetch {$url}: {$error}");
    }

    $entries = [];
    foreach (preg_split('/\r\n|\n|\r/', $body) ?: [] as $line) {
        $line = trim((string) $line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        // Basic CIDR shape check; reject anything else.
        if (preg_match('#^[0-9a-fA-F:.]+/[0-9]{1,3}$#', $line) === 1) {
            $entries[] = $line;
        }
    }

    return array_values(array_unique($entries));
}

try {
    $ipv4 = cfIpsFetchList('https://www.cloudflare.com/ips-v4');
    $ipv6 = cfIpsFetchList('https://www.cloudflare.com/ips-v6');
} catch (Throwable $e) {
    cfIpsExit('fetch failed: ' . $e->getMessage(), 1);
}

if ($ipv4 === [] || $ipv6 === []) {
    cfIpsExit('refusing to write empty list (ipv4=' . count($ipv4) . ', ipv6=' . count($ipv6) . ')', 1);
}

$payload = [
    '_source' => 'https://www.cloudflare.com/ips-v4 + ips-v6',
    '_fetched_at' => date('c'),
    '_refresh_via' => 'ops/update_cf_ips.php',
    'ipv4' => $ipv4,
    'ipv6' => $ipv6,
];

$encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (!is_string($encoded)) {
    cfIpsExit('json_encode failed', 1);
}

$dataDir = dirname(__DIR__) . '/data';
if (!is_dir($dataDir) && !@mkdir($dataDir, 0775, true) && !is_dir($dataDir)) {
    cfIpsExit('data directory not writable: ' . $dataDir, 1);
}

$target = $dataDir . '/cf_ips.json';
$temp = $target . '.tmp.' . bin2hex(random_bytes(4));

if (@file_put_contents($temp, $encoded) === false) {
    cfIpsExit('failed to write temp file: ' . $temp, 1);
}
if (!@rename($temp, $target)) {
    @unlink($temp);
    cfIpsExit('failed to rename temp file into place: ' . $target, 1);
}
@chmod($target, 0644);

cfIpsExit(
    'wrote ' . $target . ' (ipv4=' . count($ipv4) . ', ipv6=' . count($ipv6) . ')',
    0
);
