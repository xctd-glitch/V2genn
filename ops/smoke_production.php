<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function smokeExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

/** @param array<int, string> $argv */
function smokeArg(array $argv, string $name, string $default = ''): string
{
    $prefix = '--' . $name . '=';
    foreach ($argv as $arg) {
        if (is_string($arg) && str_starts_with($arg, $prefix)) {
            return trim(substr($arg, strlen($prefix)));
        }
    }

    return $default;
}

/** @return array<string, mixed> */
function smokeRequest(string $url, string $userAgent): array
{
    $headers = [];
    $handle = curl_init($url);
    if ($handle === false) {
        return ['ok' => false, 'error' => 'Failed to initialize cURL.'];
    }

    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADERFUNCTION => static function ($curl, string $headerLine) use (&$headers): int {
            $trimmed = trim($headerLine);
            if ($trimmed !== '' && str_contains($trimmed, ':')) {
                [$name, $value] = explode(':', $trimmed, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }

            return strlen($headerLine);
        },
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => $userAgent,
    ]);

    $body = curl_exec($handle);
    $statusCode = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
    $errorCode = curl_errno($handle);
    $errorMessage = curl_error($handle);
    curl_close($handle);

    if ($errorCode !== 0) {
        return ['ok' => false, 'error' => $errorMessage !== '' ? $errorMessage : 'HTTP request failed.'];
    }

    return [
        'ok' => true,
        'status_code' => $statusCode,
        'headers' => $headers,
        'body' => is_string($body) ? $body : '',
    ];
}

/** @param array<int, array<string, mixed>> $checks */
function smokeCheck(array &$checks, string $name, bool $passed, string $detail): void
{
    $checks[] = [
        'name' => $name,
        'passed' => $passed,
        'detail' => $detail,
    ];
}

if (PHP_SAPI !== 'cli') {
    smokeExit('This script must be run from the command line.', 2);
}

if (!function_exists('curl_init')) {
    smokeExit('cURL extension is not available.', 2);
}

$baseUrl = rtrim(smokeArg($argv ?? [], 'base-url'), '/');
$slug = smokeArg($argv ?? [], 'slug');
$metricsPath = smokeArg($argv ?? [], 'metrics-path', '/metrics');
$metricsToken = smokeArg($argv ?? [], 'metrics-token');
$jsonOutput = in_array('--json', $argv ?? [], true);

if ($baseUrl === '' || filter_var($baseUrl, FILTER_VALIDATE_URL) === false) {
    smokeExit('Usage: php ops/smoke_production.php --base-url=https://example.com --slug=abc123 [--metrics-token=...] [--json]', 2);
}

if ($slug === '' || preg_match('/^[A-Za-z0-9_-]+$/', $slug) !== 1) {
    smokeExit('A valid --slug is required.', 2);
}

$checks = [];
$result = [
    'success' => true,
];

$goUrl = $baseUrl . '/go.php?s=' . rawurlencode($slug);
$human = smokeRequest($goUrl, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0 Safari/537.36');
if (!$human['ok']) {
    smokeCheck($checks, 'human_loader', false, (string) ($human['error'] ?? 'HTTP request failed.'));
    $result['success'] = false;
} else {
    $locationHeader = (string) ($human['headers']['location'] ?? '');
    $humanBody = (string) ($human['body'] ?? '');
    smokeCheck($checks, 'human_loader_status', (int) $human['status_code'] === 200, 'HTTP ' . (int) $human['status_code']);
    smokeCheck($checks, 'human_loader_no_location', $locationHeader === '', $locationHeader === '' ? 'No redirect header.' : 'Location=' . $locationHeader);

    $fallbackUrl = '';
    if (preg_match('/[?&]rtu=([A-Za-z0-9._-]+)/', $humanBody, $matches) === 1) {
        $fallbackUrl = $baseUrl . '/go.php?rtu=' . rawurlencode((string) $matches[1]);
    }

    smokeCheck($checks, 'human_loader_has_fallback_token', $fallbackUrl !== '', $fallbackUrl !== '' ? 'Fallback token found.' : 'Fallback token missing.');

    if ($fallbackUrl !== '') {
        $fallback = smokeRequest($fallbackUrl, 'Lynx/2.9.0 libwww-FM/2.14');
        if (!$fallback['ok']) {
            smokeCheck($checks, 'fallback_redirect', false, (string) ($fallback['error'] ?? 'Fallback request failed.'));
            $result['success'] = false;
        } else {
            $fallbackStatus = (int) ($fallback['status_code'] ?? 0);
            $hasRedirect = in_array($fallbackStatus, [301, 302, 303, 307, 308], true)
                && !empty($fallback['headers']['location']);
            smokeCheck(
                $checks,
                'fallback_redirect',
                $hasRedirect,
                'HTTP ' . $fallbackStatus . ($hasRedirect ? ' with redirect location.' : ' without expected redirect.')
            );
        }
    }
}

$bot = smokeRequest($goUrl, 'facebookexternalhit/1.1');
if (!$bot['ok']) {
    smokeCheck($checks, 'bot_preview', false, (string) ($bot['error'] ?? 'HTTP request failed.'));
    $result['success'] = false;
} else {
    $botStatus = (int) ($bot['status_code'] ?? 0);
    $botLocation = (string) ($bot['headers']['location'] ?? '');
    smokeCheck($checks, 'bot_preview_status', $botStatus === 200, 'HTTP ' . $botStatus);
    smokeCheck($checks, 'bot_preview_no_location', $botLocation === '', $botLocation === '' ? 'No redirect header.' : 'Location=' . $botLocation);
}

$metricsUrl = $baseUrl . $metricsPath;
$separator = str_contains($metricsUrl, '?') ? '&' : '?';
$metricsUrl .= $separator . 'format=json';
if ($metricsToken !== '') {
    $metricsUrl .= '&token=' . rawurlencode($metricsToken);
}

$metrics = smokeRequest($metricsUrl, 'ProductionSmoke/1.0');
if (!$metrics['ok']) {
    smokeCheck($checks, 'metrics_endpoint', false, (string) ($metrics['error'] ?? 'HTTP request failed.'));
    $result['success'] = false;
} else {
    $metricsStatus = (int) ($metrics['status_code'] ?? 0);
    $metricsBody = json_decode((string) ($metrics['body'] ?? ''), true);
    smokeCheck($checks, 'metrics_endpoint_status', $metricsStatus === 200, 'HTTP ' . $metricsStatus);
    smokeCheck($checks, 'metrics_endpoint_json', is_array($metricsBody), is_array($metricsBody) ? 'Valid JSON.' : 'Invalid JSON payload.');

    if (is_array($metricsBody)) {
        smokeCheck($checks, 'metrics_db_ok', ((int) ($metricsBody['db_ok'] ?? 0)) === 1, 'db_ok=' . (int) ($metricsBody['db_ok'] ?? 0));
        smokeCheck($checks, 'metrics_apcu_enabled', ((int) ($metricsBody['apcu_enabled'] ?? 0)) === 1, 'apcu_enabled=' . (int) ($metricsBody['apcu_enabled'] ?? 0));
        smokeCheck(
            $checks,
            'metrics_worker_not_stale',
            ((int) ($metricsBody['postback_worker_stale'] ?? 0)) === 0,
            'postback_worker_stale=' . (int) ($metricsBody['postback_worker_stale'] ?? 0)
        );
    }
}

foreach ($checks as $check) {
    if (empty($check['passed'])) {
        $result['success'] = false;
        break;
    }
}

if ($jsonOutput) {
    $result['checks'] = $checks;
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL;
    exit($result['success'] ? 0 : 1);
}

foreach ($checks as $check) {
    $prefix = !empty($check['passed']) ? '[pass] ' : '[fail] ';
    fwrite((!empty($check['passed']) ? STDOUT : STDERR), $prefix . $check['name'] . ' - ' . $check['detail'] . PHP_EOL);
}

smokeExit(
    'Smoke test ' . ($result['success'] ? 'passed' : 'failed') . '.',
    $result['success'] ? 0 : 1
);
