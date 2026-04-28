<?php

declare(strict_types=1);

// ============================================================
// notrackng.comv2 — Installation Wizard
// PHP 8.3 strict_types, single-file, no external dependencies
// ============================================================

$installerCspNonce = bin2hex(random_bytes(16));
installerSendSecurityHeaders($installerCspNonce);
installerStartSession();

if (empty($_SESSION['install_token']) || !is_string($_SESSION['install_token'])) {
    $_SESSION['install_token'] = installerGenerateRandomHex(32);
}

$installToken = (string) $_SESSION['install_token'];

// ---------------------------------------------------------------------------
// Security guard: block re-install if .env already exists and is populated
// ---------------------------------------------------------------------------
$envFile = __DIR__ . '/.env';

// Security guard: block re-install if .env already exists and is populated.
// EXCEPTION: always allow internal AJAX calls (Step 6 writes .env first and
// immediately fires write_cf / run_schema / etc. — those subsequent POST
// requests must not be blocked by this guard).
// The AJAX handlers themselves validate session data and exit safely.
$requestedStep = (int) ($_GET['step'] ?? 0);
if (
    !isset($_POST['_ajax'])
    && $requestedStep !== 7
    && is_file($envFile)
    && filesize($envFile) > 10
) {
    http_response_code(403);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>403 Forbidden</title>'
        . '<script nonce="' . h(
            $installerCspNonce
        ) . '" src="https://cdn.tailwindcss.com"></script></head>'
        . '<body class="bg-gray-100 flex items-center justify-center min-h-screen">'
        . '<div class="bg-white rounded-xl shadow p-8 max-w-md text-center">'
        . '<h1 class="text-2xl font-bold text-red-600 mb-4">403 — Already Installed</h1>'
        . '<p class="text-gray-600">File <code>.env</code> already exists. Installer is blocked.</p>'
        . '<p class="text-gray-500 text-sm mt-3">Remove or replace <code>.env</code> on the server first if you intentionally need a reinstall.</p>'
        . '</div></body></html>';
    exit(0);
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/** Get value from session installer data, step N, key, with default. */
function iv(int $step, string $key, string $default = ''): string
{
    return (string) ($_SESSION['idata'][$step][$key] ?? $default);
}

/** Escape for HTML output. */
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Return JSON AJAX response and exit. */
function ajaxJson(bool $ok, string $msg): never
{
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_UNICODE);
    exit(0);
}

function installerIsHttps(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    if (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
        return true;
    }

    return false;
}

function installerStartSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');

    if (installerIsHttps()) {
        ini_set('session.cookie_secure', '1');
    }

    $sessionSavePath = trim((string) ini_get('session.save_path'));
    $resolvedSessionPath = $sessionSavePath;
    if (str_contains($resolvedSessionPath, ';')) {
        $parts = explode(';', $resolvedSessionPath);
        $resolvedSessionPath = (string) end($parts);
    }
    $resolvedSessionPath = trim($resolvedSessionPath, " \t\n\r\0\x0B\"'");

    $hasWritableSessionPath = $resolvedSessionPath !== ''
        && is_dir($resolvedSessionPath)
        && is_writable($resolvedSessionPath);

    if (!$hasWritableSessionPath) {
        $fallbackSessionPath = __DIR__ . '/data/sessions';
        if (
            (!is_dir($fallbackSessionPath) && @mkdir($fallbackSessionPath, 0775, true))
            || is_dir($fallbackSessionPath)
        ) {
            if (is_writable($fallbackSessionPath)) {
                ini_set('session.save_path', $fallbackSessionPath);
            }
        }
    }

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => installerIsHttps(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();
}

function installerSendSecurityHeaders(string $nonce): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: accelerometer=(), ambient-light-sensor=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header(
        "Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval' https://cdn.tailwindcss.com 'nonce-{$nonce}'"
    );

    if (installerIsHttps()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function installerGenerateRandomHex(int $bytes): string
{
    return bin2hex(random_bytes($bytes));
}

function installerSafeAjaxMessage(string $message): string
{
    return preg_replace('/\s+/', ' ', trim($message)) ?? 'Operation failed.';
}

function installerFailAjax(string $message, int $statusCode = 400): never
{
    http_response_code($statusCode);
    ajaxJson(false, installerSafeAjaxMessage($message));
}

/**
 * @return array{mode: string, message: string, commands: string}
 */
function installerCronSetupSummary(): array
{
    $cron = $_SESSION['install_meta']['cron'] ?? null;
    if (!is_array($cron)) {
        return [
            'mode' => 'unknown',
            'message' => 'Cron setup status is unavailable.',
            'commands' => '',
        ];
    }

    $mode = isset($cron['mode']) && is_string($cron['mode']) ? $cron['mode'] : 'unknown';
    $message = isset($cron['message']) && is_string($cron['message']) ? $cron['message'] : 'Cron setup status is unavailable.';
    $commands = isset($cron['commands']) && is_string($cron['commands']) ? $cron['commands'] : '';

    return [
        'mode' => $mode,
        'message' => $message,
        'commands' => $commands,
    ];
}

function installerRememberCronSetup(string $mode, string $message, string $commands): void
{
    $_SESSION['install_meta']['cron'] = [
        'mode' => $mode,
        'message' => installerSafeAjaxMessage($message),
        'commands' => trim($commands),
    ];
}

function installerValidateCfToken(string $token): bool
{
    return $token !== '' && (bool) preg_match('/^[A-Za-z0-9._-]{20,255}$/', $token);
}

function installerValidateHexId(string $value): bool
{
    return (bool) preg_match('/^[a-f0-9]{32}$/i', $value);
}

function installerDetectServerIp(): string
{
    $candidates = [
        $_SERVER['SERVER_ADDR'] ?? '',
        $_SERVER['LOCAL_ADDR'] ?? '',
    ];

    foreach ($candidates as $candidate) {
        if (is_string($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if ($host !== '') {
        $stripped = preg_replace('/:\d+$/', '', $host) ?? $host;
        $resolved = @gethostbyname($stripped);
        if (is_string($resolved) && $resolved !== $stripped && filter_var($resolved, FILTER_VALIDATE_IP)) {
            return $resolved;
        }
    }

    return '';
}

function installerDetectPrimaryDomain(): string
{
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if ($host === '') {
        return '';
    }

    $host = (string) preg_replace('/:\d+$/', '', $host);
    $host = (string) preg_replace('/^www\./i', '', $host);

    return strtolower($host);
}

function installerDetectBaseDir(): string
{
    $docRoot = (string) ($_SERVER['DOCUMENT_ROOT'] ?? '');
    $dir = __DIR__;

    if ($docRoot !== '' && str_starts_with($dir, $docRoot)) {
        $relative = ltrim(substr($dir, strlen($docRoot)), '/');
        if ($relative === '') {
            $relative = basename($dir);
        }

        // Prepend public_html when document root resolves inside it
        if (str_contains($docRoot, '/public_html')) {
            return 'public_html/' . $relative;
        }

        return $relative !== '' ? $relative : basename($dir);
    }

    $base = basename($dir);
    $parent = basename(dirname($dir));

    if ($parent === 'public_html') {
        return 'public_html/' . $base;
    }

    return $base;
}

function installerDetectNameservers(string $domain): string
{
    if ($domain === '' || !function_exists('dns_get_record')) {
        return '';
    }

    $records = @dns_get_record($domain, DNS_NS);
    if (!is_array($records) || $records === []) {
        return '';
    }

    $servers = [];
    foreach ($records as $record) {
        if (isset($record['target']) && is_string($record['target']) && $record['target'] !== '') {
            $servers[] = strtolower($record['target']);
        }
    }

    $servers = array_values(array_unique($servers));
    sort($servers);

    return implode(',', $servers);
}

function installerValidateHostnameOrIp(string $value): bool
{
    if ($value === '') {
        return false;
    }

    if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    return (bool) preg_match('/^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$/', $value);
}

function installerCloudflareRequest(string $method, string $path, string $token, ?array $payload = null): array
{
    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $curl = curl_init();
    if ($curl === false) {
        throw new RuntimeException('Failed to initialize Cloudflare request.');
    }

    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
    ];

    $options = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers,
    ];

    if ($payload !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            curl_close($curl);
            throw new RuntimeException('Failed to encode Cloudflare request payload.');
        }
        $headers[] = 'Content-Type: application/json';
        $options[CURLOPT_HTTPHEADER] = $headers;
        $options[CURLOPT_POSTFIELDS] = $json;
    }

    curl_setopt_array($curl, $options);
    $response = curl_exec($curl);
    $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);

    if ($response === false) {
        $errorMessage = curl_error($curl);
        curl_close($curl);
        throw new RuntimeException('Cloudflare request failed: ' . $errorMessage);
    }

    curl_close($curl);

    $decoded = json_decode((string) $response, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Cloudflare returned invalid JSON.');
    }

    if ($httpCode >= 400 || !($decoded['success'] ?? false)) {
        $messages = [];
        if (isset($decoded['errors']) && is_array($decoded['errors'])) {
            foreach ($decoded['errors'] as $error) {
                if (is_array($error) && isset($error['message']) && is_string($error['message'])) {
                    $messages[] = $error['message'];
                }
            }
        }

        $message = $messages !== [] ? implode('; ', $messages) : 'Cloudflare API rejected the request.';
        throw new RuntimeException($message);
    }

    return $decoded;
}

function installerCloudflareResolveAccountId(string $bootstrapToken, string $providedAccountId): string
{
    if ($providedAccountId !== '') {
        if (!installerValidateHexId($providedAccountId)) {
            throw new RuntimeException('CF_ACCOUNT_ID must be a 32 character hexadecimal string.');
        }

        return strtolower($providedAccountId);
    }

    try {
        $response = installerCloudflareRequest('GET', '/accounts?per_page=1', $bootstrapToken);
        $result = $response['result'] ?? null;
        if (is_array($result) && isset($result[0]['id']) && is_string($result[0]['id']) && installerValidateHexId($result[0]['id'])) {
            return strtolower($result[0]['id']);
        }
    } catch (Throwable) {
    }

    try {
        $response = installerCloudflareRequest('GET', '/memberships?per_page=1', $bootstrapToken);
        $result = $response['result'] ?? null;
        if (is_array($result) && isset($result[0]['account']['id']) && is_string($result[0]['account']['id']) && installerValidateHexId($result[0]['account']['id'])) {
            return strtolower($result[0]['account']['id']);
        }
    } catch (Throwable) {
    }

    throw new RuntimeException('Unable to resolve account ID. Fill in CF_ACCOUNT_ID manually (Dashboard → any site → Overview sidebar → Account ID).');
}

function installerCloudflarePermissionGroupMap(string $accountId, string $bootstrapToken): array
{
    // Try user-level endpoint first (works with "Create Additional Tokens" template)
    // then fall back to account-level endpoint
    $endpoints = [
        '/user/tokens/permission_groups',
        '/accounts/' . rawurlencode($accountId) . '/tokens/permission_groups',
    ];

    $lastError = null;
    foreach ($endpoints as $endpoint) {
        try {
            $response = installerCloudflareRequest('GET', $endpoint, $bootstrapToken);
            $groups = $response['result'] ?? null;
            if (is_array($groups) && $groups !== []) {
                break;
            }
        } catch (Throwable $e) {
            $lastError = $e;
            $groups = null;
            continue;
        }
    }

    if (!is_array($groups) || $groups === []) {
        throw $lastError ?? new RuntimeException('Unable to load Cloudflare permission groups.');
    }

    $map = [];
    foreach ($groups as $group) {
        if (!is_array($group)) {
            continue;
        }
        if (!isset($group['id'], $group['name']) || !is_string($group['id']) || !is_string($group['name'])) {
            continue;
        }
        $map[strtolower(trim($group['name']))] = [
            'id' => $group['id'],
            'name' => $group['name'],
        ];
    }

    return $map;
}

function installerCloudflarePickPermission(array $map, array $candidates, bool $required): ?array
{
    foreach ($candidates as $candidate) {
        $key = strtolower($candidate);
        if (isset($map[$key]) && is_array($map[$key])) {
            return $map[$key];
        }
    }

    if ($required) {
        throw new RuntimeException('Cloudflare permission group not found: ' . implode(' / ', $candidates));
    }

    return null;
}

function installerCloudflareBuildRuntimePolicy(string $accountId, string $bootstrapToken): array
{
    $permissionMap = installerCloudflarePermissionGroupMap($accountId, $bootstrapToken);

    // Account-scoped permissions (resource = the account URN, flat)
    $accountRequired = [
        ['Account Settings Read'],
    ];
    $accountGroups = [];
    foreach ($accountRequired as $candidates) {
        $permission = installerCloudflarePickPermission($permissionMap, $candidates, true);
        if ($permission !== null) {
            $accountGroups[$permission['id']] = $permission;
        }
    }

    // Zone-scoped permissions (resource = zones within the account, nested URN)
    $zoneRequired = [
        ['Zone Read', 'Zone Write'],
        ['Zone Write'],
        ['DNS Write', 'Zone DNS Write'],
        ['Zone Settings Write'],
    ];
    $zoneOptional = [
        ['Client-Side Security Write', 'Client Side Security Write', 'Zone Client-Side Security Write', 'Page Shield Write', 'Zone Page Shield Write'],
        ['Bot Management Write', 'Zone Bot Management Write'],
        ['Zone WAF Write', 'WAF Write'],
    ];
    $zoneGroups = [];
    foreach ($zoneRequired as $candidates) {
        $permission = installerCloudflarePickPermission($permissionMap, $candidates, true);
        if ($permission !== null) {
            $zoneGroups[$permission['id']] = $permission;
        }
    }
    foreach ($zoneOptional as $candidates) {
        $permission = installerCloudflarePickPermission($permissionMap, $candidates, false);
        if ($permission !== null) {
            $zoneGroups[$permission['id']] = $permission;
        }
    }

    $policies = [];

    if ($accountGroups !== []) {
        $policies[] = [
            'effect' => 'allow',
            'resources' => [
                'com.cloudflare.api.account.' . $accountId => '*',
            ],
            'permission_groups' => array_values($accountGroups),
        ];
    }

    if ($zoneGroups !== []) {
        $policies[] = [
            'effect' => 'allow',
            'resources' => [
                'com.cloudflare.api.account.' . $accountId => [
                    'com.cloudflare.api.account.zone.*' => '*',
                ],
            ],
            'permission_groups' => array_values($zoneGroups),
        ];
    }

    return $policies;
}

function installerCloudflareCreateRuntimeToken(string $bootstrapToken, string $accountId): array
{
    $accountId = installerCloudflareResolveAccountId($bootstrapToken, $accountId);
    $payload = [
        'name' => 'notrackng runtime token',
        'policies' => installerCloudflareBuildRuntimePolicy($accountId, $bootstrapToken),
    ];

    // Try user-level endpoint first (works with "Create Additional Tokens" template),
    // then fall back to account-level endpoint
    $lastError = null;
    $result = null;
    $endpoints = [
        '/user/tokens',
        '/accounts/' . rawurlencode($accountId) . '/tokens',
    ];

    foreach ($endpoints as $endpoint) {
        try {
            $response = installerCloudflareRequest('POST', $endpoint, $bootstrapToken, $payload);
            $result = $response['result'] ?? null;
            if (is_array($result) && isset($result['value']) && is_string($result['value'])) {
                break;
            }
        } catch (Throwable $e) {
            $lastError = $e;
            $result = null;
            continue;
        }
    }

    if (!is_array($result) || !isset($result['value']) || !is_string($result['value'])) {
        throw $lastError ?? new RuntimeException('Cloudflare did not return a runtime token value.');
    }

    return [
        'token' => $result['value'],
        'account_id' => $accountId,
    ];
}

/** Shared PDO options for installer MySQL calls. */
function installerPdoOptions(array $extraOptions = []): array
{
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 10,
    ];

    if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
        $attribute = constant('PDO::MYSQL_ATTR_MULTI_STATEMENTS');
        if (is_int($attribute)) {
            $options[$attribute] = false;
        }
    }

    foreach ($extraOptions as $attribute => $value) {
        if (!is_int($attribute)) {
            continue;
        }

        $options[$attribute] = $value;
    }

    return $options;
}

function installerHasValidToken(): bool
{
    $sessionToken = $_SESSION['install_token'] ?? '';
    $requestToken = $_POST['install_token'] ?? '';

    return is_string($sessionToken)
        && $sessionToken !== ''
        && is_string($requestToken)
        && hash_equals($sessionToken, $requestToken);
}

/** Build PDO from session step-2 data. */
function buildPdo(): PDO
{
    $host = iv(2, 'DB_HOST', 'localhost');
    $user = iv(2, 'DB_USER');
    $pass = iv(2, 'DB_PASS');
    $name = iv(2, 'DB_NAME');
    $dsn  = 'mysql:host=' . $host . ';dbname=' . $name . ';charset=utf8mb4';

    return new PDO($dsn, $user, $pass, installerPdoOptions());
}

function installerApplyMysqlHotIndexes(PDO $pdo): void
{
    $driver = (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver !== 'mysql') {
        return;
    }

    $statements = [
        'ALTER TABLE `short_links` ADD INDEX `idx_active` (`active`)',
        'ALTER TABLE `short_links` ADD INDEX `idx_user_id` (`user_id`)',
        'ALTER TABLE `short_links` ADD INDEX `idx_user_active` (`user_id`, `active`)',
        'ALTER TABLE `short_links` ADD INDEX `idx_smartlink_network` (`smartlink_network`)',
        'ALTER TABLE `link_hits` ADD INDEX `idx_lh_linkid` (`link_id`)',
        'ALTER TABLE `postbacks` ADD INDEX `idx_pb_active_event` (`active`, `event`, `slug`)',
        'ALTER TABLE `clicks` ADD INDEX `idx_cl_clickid_slug` (`clickid`(100), `slug`)',
        'ALTER TABLE `clicks` ADD INDEX `idx_cl_slug_created` (`slug`, `created_at`)',
        'ALTER TABLE `clicks` ADD INDEX `idx_cl_user_created` (`user_id`, `created_at`)',
        'ALTER TABLE `conversions` ADD INDEX `idx_cv_slug` (`slug`)',
        'ALTER TABLE `conversions` ADD INDEX `idx_cv_status` (`status`)',
        'ALTER TABLE `conversions` ADD INDEX `idx_cv_slug_created` (`slug`, `created_at`)',
        'ALTER TABLE `conversions` ADD INDEX `idx_cv_user_created` (`user_id`, `created_at`)',
    ];

    foreach ($statements as $statement) {
        try {
            $pdo->exec($statement);
        } catch (Throwable $e) {
        }
    }
}

function installerCronJobs(string $phpBinary, string $appRoot): array
{
    return [
        [
            'minute' => '*',
            'hour' => '*',
            'day' => '*',
            'month' => '*',
            'weekday' => '*',
            'command' => $phpBinary . ' ' . $appRoot . '/ops/process_postback_queue.php >/dev/null 2>&1',
        ],
        [
            'minute' => '*/5',
            'hour' => '*',
            'day' => '*',
            'month' => '*',
            'weekday' => '*',
            'command' => $phpBinary . ' ' . $appRoot . '/ops/redirect_decision_alert.php >/dev/null 2>&1',
        ],
        [
            'minute' => '17',
            'hour' => '3',
            'day' => '*',
            'month' => '*',
            'weekday' => '*',
            'command' => $phpBinary . ' ' . $appRoot . '/ops/update_geolite2.php >/dev/null 2>&1',
        ],
        [
            'minute' => '7',
            'hour' => '4',
            'day' => '*',
            'month' => '*',
            'weekday' => '*',
            'command' => $phpBinary . ' ' . $appRoot . '/ops/prune_decision_audit.php >/dev/null 2>&1',
        ],
    ];
}

function installerCronCommandsText(array $cronJobs): string
{
    $lines = [];
    foreach ($cronJobs as $job) {
        $lines[] = implode(' ', [
            (string) ($job['minute'] ?? '*'),
            (string) ($job['hour'] ?? '*'),
            (string) ($job['day'] ?? '*'),
            (string) ($job['month'] ?? '*'),
            (string) ($job['weekday'] ?? '*'),
            (string) ($job['command'] ?? ''),
        ]);
    }

    return implode(' | ', $lines);
}

/** Convert a cron job array into a single crontab line. */
function installerCronJobToLine(array $job): string
{
    return implode(' ', [
        (string) ($job['minute'] ?? '*'),
        (string) ($job['hour'] ?? '*'),
        (string) ($job['day'] ?? '*'),
        (string) ($job['month'] ?? '*'),
        (string) ($job['weekday'] ?? '*'),
        (string) ($job['command'] ?? ''),
    ]);
}

/** Check whether a PHP function is callable and not in disable_functions. */
function installerFunctionAvailable(string $function): bool
{
    if (!function_exists($function)) {
        return false;
    }

    $disabled = (string) ini_get('disable_functions');
    if ($disabled === '') {
        return true;
    }

    $list = array_map('trim', explode(',', strtolower($disabled)));

    return !in_array(strtolower($function), $list, true);
}

/**
 * Install cron jobs via the local `crontab` CLI as the current PHP user.
 *
 * Idempotent: existing lines with the same command are kept as-is (counted as skipped).
 * Returns ['ok' => bool, 'added' => int, 'skipped' => int, 'total' => int, 'error' => ?string].
 *
 * @param array<int, array<string, string>> $cronJobs
 * @return array{ok: bool, added: int, skipped: int, total: int, error: ?string}
 */
function installerCronInstallViaCrontab(array $cronJobs): array
{
    $total = count($cronJobs);
    $result = ['ok' => false, 'added' => 0, 'skipped' => 0, 'total' => $total, 'error' => null];

    if (!installerFunctionAvailable('proc_open')) {
        $result['error'] = 'proc_open disabled by PHP configuration.';
        return $result;
    }

    $crontabBin = null;
    foreach (['/usr/bin/crontab', '/bin/crontab', '/usr/local/bin/crontab'] as $candidate) {
        if (is_file($candidate) && is_executable($candidate)) {
            $crontabBin = $candidate;
            break;
        }
    }
    if ($crontabBin === null) {
        $result['error'] = 'crontab binary not found on this server.';
        return $result;
    }

    // Read existing crontab (stdin=null, capture stdout/stderr).
    $existing = installerRunCommand([$crontabBin, '-l']);
    // Exit code 1 with "no crontab" message is normal for fresh users.
    $currentCrontab = $existing['stdout'] ?? '';

    $currentLines = array_values(array_filter(
        array_map('rtrim', explode("\n", $currentCrontab)),
        static fn($line) => $line !== ''
    ));

    $existingCommands = [];
    foreach ($currentLines as $line) {
        if (preg_match('/^\s*#/', $line)) {
            continue;
        }
        $existingCommands[] = $line;
    }

    $newLines = $currentLines;
    $added = 0;
    $skipped = 0;

    foreach ($cronJobs as $job) {
        $line = installerCronJobToLine($job);
        $command = (string) ($job['command'] ?? '');
        $duplicate = false;
        foreach ($existingCommands as $existingLine) {
            if ($command !== '' && strpos($existingLine, $command) !== false) {
                $duplicate = true;
                break;
            }
        }
        if ($duplicate) {
            $skipped++;
            continue;
        }
        $newLines[] = $line;
        $existingCommands[] = $line;
        $added++;
    }

    if ($added === 0) {
        $result['ok'] = true;
        $result['added'] = 0;
        $result['skipped'] = $skipped;
        return $result;
    }

    $payload = implode("\n", $newLines) . "\n";
    $write = installerRunCommand([$crontabBin, '-'], $payload);

    if ($write['exit'] !== 0) {
        $result['error'] = 'crontab write failed (exit ' . $write['exit'] . '): '
            . trim($write['stderr'] ?: $write['stdout']);
        return $result;
    }

    $result['ok'] = true;
    $result['added'] = $added;
    $result['skipped'] = $skipped;
    return $result;
}

/**
 * Run a shell command via proc_open with optional stdin.
 *
 * @param array<int, string> $argv
 * @return array{exit: int, stdout: string, stderr: string}
 */
function installerRunCommand(array $argv, ?string $stdin = null): array
{
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($argv, $descriptors, $pipes);
    if (!is_resource($process)) {
        return ['exit' => -1, 'stdout' => '', 'stderr' => 'proc_open failed'];
    }

    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]) ?: '';
    $stderr = stream_get_contents($pipes[2]) ?: '';
    fclose($pipes[1]);
    fclose($pipes[2]);

    $exit = proc_close($process);
    return ['exit' => (int) $exit, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
}

/** Recursively delete a directory. */
function rmdirRecursive(string $path): void
{
    if (!is_dir($path)) {
        return;
    }
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iter as $item) {
        if ($item->isDir()) {
            rmdir($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }
    rmdir($path);
}

/** Create a writable temporary work directory for GeoLite2 downloads. */
function installerCreateGeoLiteWorkDir(string $targetDirectory): ?string
{
    $candidates = [];
    $tempBase = trim((string) sys_get_temp_dir());
    if ($tempBase !== '') {
        $candidates[] = rtrim($tempBase, '\\/') . DIRECTORY_SEPARATOR . 'notrackng-geolite2-' . str_replace('.', '-', uniqid('', true));
    }
    $candidates[] = $targetDirectory . DIRECTORY_SEPARATOR . '.geolite2-install';

    foreach ($candidates as $candidate) {
        if (is_dir($candidate)) {
            rmdirRecursive($candidate);
        }

        if (@mkdir($candidate, 0775, true) || is_dir($candidate)) {
            return $candidate;
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// cPanel UAPI helper
// ---------------------------------------------------------------------------

/** Detect the PHP CLI binary path (EasyApache 4 / standard). */
function installerDetectPhpCliBinary(): string
{
    $candidates = [
        '/usr/local/bin/ea-php83',
        '/usr/local/bin/php83',
        '/usr/local/bin/php8.3',
        '/usr/local/bin/php',
        '/usr/bin/php',
    ];

    foreach ($candidates as $path) {
        if (is_file($path) && is_executable($path)) {
            return $path;
        }
    }

    $binDir = defined('PHP_BINDIR') ? PHP_BINDIR : '/usr/local/bin';
    $fallback = rtrim($binDir, '/') . '/php';

    return is_file($fallback) ? $fallback : '/usr/local/bin/php';
}

/**
 * Call cPanel UAPI endpoint.
 *
 * @return array<string, mixed> Decoded response
 * @throws RuntimeException on failure
 */
function installerCpanelUapi(string $host, int $port, string $user, string $token, string $module, string $function, array $params = []): array
{
    if (!installerValidateHostnameOrIp($host)) {
        throw new RuntimeException('Invalid cPanel host.');
    }

    if ($port < 1 || $port > 65535) {
        throw new RuntimeException('Invalid cPanel port.');
    }

    $url = 'https://' . $host . ':' . $port . '/execute/' . rawurlencode($module) . '/' . rawurlencode($function);

    $curl = curl_init();
    if ($curl === false) {
        throw new RuntimeException('Failed to initialize cURL for cPanel API.');
    }

    curl_setopt_array($curl, [
        CURLOPT_URL            => $url,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($params),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => [
            'Authorization: cpanel ' . $user . ':' . $token,
        ],
    ]);

    $response = curl_exec($curl);
    $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);

    if ($response === false) {
        $err = curl_error($curl);
        curl_close($curl);
        throw new RuntimeException('cPanel API failed: ' . $err);
    }

    curl_close($curl);

    if ($httpCode >= 400) {
        throw new RuntimeException('cPanel API returned HTTP ' . $httpCode);
    }

    $data = json_decode((string) $response, true);
    if (!is_array($data)) {
        throw new RuntimeException('cPanel API returned invalid JSON.');
    }

    return $data;
}

// ---------------------------------------------------------------------------
// AJAX handlers
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !installerHasValidToken()) {
    if (isset($_POST['_ajax'])) {
        http_response_code(403);
        ajaxJson(false, 'Invalid installer session. Reload the installer and try again.');
    }

    http_response_code(403);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>403 Forbidden</title>'
        . '<script nonce="' . h(
            $installerCspNonce
        ) . '" src="https://cdn.tailwindcss.com"></script></head>'
        . '<body class="bg-gray-100 flex items-center justify-center min-h-screen">'
        . '<div class="bg-white rounded-xl shadow p-8 max-w-md text-center">'
        . '<h1 class="text-2xl font-bold text-red-600 mb-4">403 — Invalid Installer Session</h1>'
        . '<p class="text-gray-600">Reload the installer and try again.</p>'
        . '</div></body></html>';
    exit(0);
}

if (isset($_POST['_ajax'])) {
    $action = (string) ($_POST['action'] ?? '');

    switch ($action) {
        // ------------------------------------------------------------------
        case 'auto_create_cf_token':
            $bootstrapToken = trim((string) ($_POST['CF_BOOTSTRAP_TOKEN'] ?? ''));
            $accountId = trim((string) ($_POST['CF_ACCOUNT_ID'] ?? ''));

            if (!installerValidateCfToken($bootstrapToken)) {
                installerFailAjax('CF bootstrap token tidak valid. Pakai token dari template "Create Additional Tokens" di Cloudflare (https://dash.cloudflare.com/profile/api-tokens), yang punya permission User → API Tokens → Edit.');
            }

            try {
                $runtimeToken = installerCloudflareCreateRuntimeToken($bootstrapToken, $accountId);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode([
                    'ok' => true,
                    'msg' => 'Cloudflare runtime token created successfully.',
                    'token' => $runtimeToken['token'],
                    'account_id' => $runtimeToken['account_id'],
                ], JSON_UNESCAPED_UNICODE);
                exit(0);
            } catch (Throwable $e) {
                $raw = $e->getMessage();
                $lower = strtolower($raw);
                $needsTokenWritePermission = str_contains($lower, 'unauthorized to access requested resource')
                    || str_contains($lower, 'authentication error')
                    || str_contains($lower, 'not entitled')
                    || str_contains($lower, 'user api tokens')
                    || str_contains($lower, 'permission denied');

                if ($needsTokenWritePermission) {
                    $hint = 'Cloudflare menolak bootstrap token: "' . $raw . '". '
                        . 'PENTING — Cloudflare pakai subset policy: bootstrap token HARUS punya SEMUA permission '
                        . 'yang akan dimiliki runtime token, bukan hanya "User → API Tokens → Edit". '
                        . 'Kalau bootstrap cuma punya satu baris (User → API Tokens → Edit), request create token akan ditolak. '
                        . 'Solusi: buat ulang di dash.cloudflare.com/profile/api-tokens → Create Custom Token → '
                        . 'tambahkan SEMUA baris permission ini (klik "+ Add more"): '
                        . '(1) User · API Tokens · Edit [wajib untuk create]; '
                        . '(2) Account · Account Settings · Read; '
                        . '(3) Zone · Zone · Read; '
                        . '(4) Zone · Zone · Edit; '
                        . '(5) Zone · DNS · Edit; '
                        . '(6) Zone · Zone Settings · Edit. '
                        . 'Opsional: Zone · Client-side Security · Edit, Zone · Bot Management · Edit, Zone · Zone WAF · Edit. '
                        . 'Account Resources: Include → akun Anda. Zone Resources: Include → All zones from an account → akun yang sama.';
                    installerFailAjax($hint, 422);
                }

                installerFailAjax('Cloudflare token creation failed: ' . $raw, 422);
            }

            // ------------------------------------------------------------------
        case 'test_db':
            $host = trim((string) ($_POST['DB_HOST'] ?? 'localhost'));
            $user = trim((string) ($_POST['DB_USER'] ?? ''));
            $pass = (string) ($_POST['DB_PASS'] ?? '');
            $name = trim((string) ($_POST['DB_NAME'] ?? ''));

            if ($host === '' || $user === '' || $name === '') {
                ajaxJson(false, 'Host, user, and database name are required.');
            }

            try {
                $dsn = 'mysql:host=' . $host . ';dbname=' . $name . ';charset=utf8mb4';
                $pdo = new PDO($dsn, $user, $pass, installerPdoOptions());
                $ver = (string) $pdo->query('SELECT VERSION()')->fetchColumn();
                ajaxJson(true, 'Connection successful! MySQL/MariaDB version: ' . $ver);
            } catch (Throwable $e) {
                installerFailAjax('Connection failed: ' . $e->getMessage(), 422);
            }

            // ------------------------------------------------------------------
        case 'run_schema':
            $sqlFile = __DIR__ . '/data/install.sql';
            if (!is_file($sqlFile)) {
                ajaxJson(false, 'File data/install.sql not found.');
            }

            try {
                $pdo = buildPdo();
                $sql = file_get_contents($sqlFile);
                if ($sql === false) {
                    ajaxJson(false, 'Failed to read data/install.sql.');
                }

                // Split on statement terminator; run each statement
                $pdo->exec('SET NAMES utf8mb4');
                $pdo->exec('SET foreign_key_checks = 0');

                // Execute multi-statement safely via splitting.
                // Strip -- comment lines from each fragment before checking
                // emptiness; CREATE TABLE blocks are preceded by comments and
                // would otherwise be filtered out entirely.
                $fragments = explode(';', $sql);
                $statements = [];
                foreach ($fragments as $fragment) {
                    $stripped = preg_replace('/--[^\n]*\n?/', '', $fragment) ?? $fragment;
                    $statement = trim($stripped);
                    if ($statement !== '') {
                        $statements[] = $statement;
                    }
                }

                foreach ($statements as $stmt) {
                    $pdo->exec($stmt);
                }

                installerApplyMysqlHotIndexes($pdo);

                $pdo->exec('SET foreign_key_checks = 1');
                ajaxJson(true, 'Schema installed to database successfully.');
            } catch (Throwable $e) {
                installerFailAjax('Failed to run schema: ' . $e->getMessage(), 422);
            }

            // ------------------------------------------------------------------
        case 'create_user':
            $adminUser = iv(4, 'ADMIN_USER');
            $adminPass = iv(4, 'ADMIN_PASS');

            if ($adminUser === '' || $adminPass === '') {
                ajaxJson(false, 'ADMIN_USER / ADMIN_PASS not in session. Please restart from step 4.');
            }

            try {
                $pdo  = buildPdo();
                $hash = password_hash($adminPass, PASSWORD_BCRYPT, ['cost' => 12]);
                $stmt = $pdo->prepare(
                    'INSERT INTO `app_users` (`username`, `password_hash`, `domain`) VALUES (?, ?, ?) '
                    . 'ON DUPLICATE KEY UPDATE `password_hash` = VALUES(`password_hash`)'
                );
                $stmt->execute([$adminUser, $hash, '']);
                ajaxJson(true, 'Admin user "' . $adminUser . '" created successfully.');
            } catch (Throwable $e) {
                installerFailAjax('Failed to create admin user: ' . $e->getMessage(), 422);
            }

            // ------------------------------------------------------------------
        case 'write_env':
            $s2 = $_SESSION['idata'][2] ?? [];
            $s3 = $_SESSION['idata'][3] ?? [];
            $s4 = $_SESSION['idata'][4] ?? [];
            $s5 = $_SESSION['idata'][5] ?? [];

            $geoPath = __DIR__ . '/data/geoip/GeoLite2-Country.mmdb';
            $cpanelUser = trim((string) ($s3['CPANEL_USER'] ?? ''));
            $baseDir = trim((string) ($s3['BASE_DIR'] ?? ''));

            $wildcardDir = (string) ($s3['WILDCARD_DIR'] ?? '');
            if ($wildcardDir === '') {
                $wildcardDir = $baseDir;
            }
            $wildcardDir = trim($wildcardDir);

            $appToken = (string) ($s4['APP_TOKEN'] ?? '');

            $postbackSecret = (string) ($s4['POSTBACK_SECRET'] ?? '');
            $metricsToken   = (string) ($s4['METRICS_TOKEN'] ?? '');

            $lines = [
                '# notrackng.comv2 — Generated by installer on ' . date('Y-m-d H:i:s'),
                '',
                '# Runtime',
                'APP_ENV=production',
                '',
                '# Database',
                'DB_HOST=' . ($s2['DB_HOST'] ?? 'localhost'),
                'DB_USER=' . ($s2['DB_USER'] ?? ''),
                'DB_PASS=' . ($s2['DB_PASS'] ?? ''),
                'DB_NAME=' . ($s2['DB_NAME'] ?? ''),
                '',
                '# cPanel',
                'CPANEL_HOST=' . ($s3['CPANEL_HOST'] ?? ''),
                'CPANEL_PORT=' . ($s3['CPANEL_PORT'] ?? '2083'),
                'CPANEL_USER=' . $cpanelUser,
                'CPANEL_TOKEN=' . ($s3['CPANEL_TOKEN'] ?? ''),
                'CPANEL_DOMAIN=' . ($s3['CPANEL_DOMAIN'] ?? ''),
                'CPANEL_NAMESERVERS=' . ($s3['CPANEL_NAMESERVERS'] ?? ''),
                '',
                '# Server',
                'SERVER_IP=' . ($s3['SERVER_IP'] ?? ''),
                'BASE_DIR=' . $baseDir,
                'WILDCARD_DIR=' . $wildcardDir,
                '',
                '# Admin',
                'ADMIN_USER=' . ($s4['ADMIN_USER'] ?? ''),
                'APP_TOKEN=' . $appToken,
                '',
                '# Cloudflare',
                'CF_TOKEN=' . ($s5['CF_TOKEN'] ?? ''),
                'CF_ACCOUNT_ID=' . ($s5['CF_ACCOUNT_ID'] ?? ''),
                'CF_ZONE_ID=' . ($s5['CF_ZONE_ID'] ?? ''),
                'CF_PROXIED=' . ($s5['CF_PROXIED'] ?? 'true'),
                '',
                '# IXG API',
                'IXG_API_URL=' . ($s5['IXG_API_URL'] ?? 'https://me.ixg.llc/api.php'),
                'IXG_API_SECRET=' . ($s5['IXG_API_SECRET'] ?? ''),
                '',
                '# TinyURL',
                'TINYURL_API_KEY=' . ($s5['TINYURL_API_KEY'] ?? ''),
                '',
                '# Google Safe Browsing (optional)',
                'GSB_API_KEY=' . ($s5['GSB_API_KEY'] ?? ''),
                '',
                '# MaxMind GeoLite2',
                'MAXMIND_ACCOUNT_ID=' . ($s5['MAXMIND_ACCOUNT_ID'] ?? ''),
                'MAXMIND_LICENSE_KEY=' . ($s5['MAXMIND_LICENSE_KEY'] ?? ''),
                'GEOLITE2_COUNTRY_DB=' . $geoPath,
                'MAXMIND_GEOLITE2_URL=',
                '',
                '# IP to ASN',
                'IPTOASN_ENDPOINT=http://127.0.0.1:53661/v1/as/ip/{ip}',
                '',
                '# Postback Security',
                'POSTBACK_SECRET=' . $postbackSecret,
                'POSTBACK_SECRET_OLD=',
                'POSTBACK_REPLAY_WINDOW=300',
                'POSTBACK_STRICT_TS=1',
                'POSTBACK_QUEUE_DIR=',
                'POSTBACK_QUEUE_SPILL_DIR=',
                'POSTBACK_QUERY_LIMIT=50',
                'POSTBACK_FAILED_RETENTION_DAYS=30',
                '',
                '# Postback Queue Worker',
                'POSTBACK_QUEUE_BATCH_SIZE=500',
                'POSTBACK_QUEUE_TIMEOUT=5',
                'POSTBACK_QUEUE_CONNECT_TIMEOUT=3',
                'POSTBACK_QUEUE_MAX_ATTEMPTS=5',
                'POSTBACK_QUEUE_RETRY_DELAY=60',
                'POSTBACK_WORKER_STALE_AFTER=900',
                '',
                '# Cache / Audit',
                'REDIRECT_PROFILE_CACHE_TTL=21600',
                'REDIRECT_PROFILE_CACHE_DB=',
                'REDIRECT_DECISION_AUDIT_SAMPLE_RATE=10',
                '',
                '# Ops / Metrics',
                'METRICS_TOKEN=' . $metricsToken,
                'DECISION_AUDIT_RETENTION_DAYS=90',
                'DECISION_METRICS_RETENTION_DAYS=180',
            ];

            $content = implode("\n", $lines) . "\n";

            if (file_put_contents(__DIR__ . '/.env', $content) === false) {
                ajaxJson(false, 'Failed to write .env file — check root directory permissions.');
            }

            ajaxJson(true, 'File .env written successfully.');

            // ------------------------------------------------------------------
            // no break
        case 'write_cf':
            $s5 = $_SESSION['idata'][5] ?? [];

            $cfData = [
                'cf_account_id'      => (string) ($s5['CF_ACCOUNT_ID'] ?? ''),
                'cf_zone_id'         => (string) ($s5['CF_ZONE_ID'] ?? ''),
                'cf_proxied'         => (string) ($s5['CF_PROXIED'] ?? 'true'),
                'filter_redirect_url' => '',
            ];

            $json = json_encode($cfData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

            if (file_put_contents(__DIR__ . '/data/config.json', $json) === false) {
                ajaxJson(false, 'Failed to write data/config.json — check data/ directory permissions.');
            }

            ajaxJson(true, 'File data/config.json written successfully.');

            // ------------------------------------------------------------------
            // no break
        case 'configure_cf_zone':
            $cfZoneId = iv(5, 'CF_ZONE_ID');
            $cfToken  = iv(5, 'CF_TOKEN');

            if ($cfZoneId === '' || $cfToken === '') {
                ajaxJson(true, 'Cloudflare not configured — skipped.');
            }

            $cfApplied = [];
            $cfFailed  = [];

            // Failure-tolerant wrapper — one permission error must not abort the rest.
            $cfApply = static function (string $label, callable $fn) use (&$cfApplied, &$cfFailed): void {
                try {
                    $fn();
                    $cfApplied[] = $label;
                } catch (Throwable $e) {
                    $cfFailed[] = $label . ' (' . $e->getMessage() . ')';
                }
            };

            // ── Zone settings (PATCH /zones/{id}/settings/{setting}) ───────
            $cfZoneSettings = [
                // Core SSL / TLS
                'ssl'                        => 'full',
                'always_use_https'           => 'on',
                'automatic_https_rewrites'   => 'on',
                'opportunistic_encryption'   => 'on',
                'opportunistic_onion'        => 'on',
                'min_tls_version'            => '1.2',
                'tls_1_3'                    => 'on',
                // Security
                'security_level'             => 'medium',
                'browser_check'              => 'on',
                'challenge_ttl'              => 1800,
                'email_obfuscation'          => 'on',
                'server_side_exclude'        => 'on',
                'hotlink_protection'         => 'on',
                'ip_geolocation'             => 'on',
                'privacy_pass'               => 'on',
                'bot_fight_mode'             => 'on',
                // Cache
                'always_online'              => 'on',
                'cache_level'                => 'aggressive',
                'browser_cache_ttl'          => 14400,
                // Performance
                'http2'                      => 'on',
                'http3'                      => 'on',
                '0rtt'                       => 'on',
                'early_hints'                => 'on',
                'brotli'                     => 'on',
                'websockets'                 => 'on',
                'prefetch_preload'           => 'on',
                'speed_brain'               => 'on',
                'fonts_loading_optimization' => 'on',
                // Rocket Loader intentionally off — rewrites <script> async, breaks tracking JS.
                'rocket_loader'              => 'off',
            ];

            foreach ($cfZoneSettings as $cfSettingId => $cfSettingValue) {
                $cfApply($cfSettingId, static function () use ($cfZoneId, $cfToken, $cfSettingId, $cfSettingValue): void {
                    installerCloudflareRequest(
                        'PATCH',
                        '/zones/' . $cfZoneId . '/settings/' . $cfSettingId,
                        $cfToken,
                        ['value' => $cfSettingValue]
                    );
                });
            }

            // minify value is an object, not a plain string.
            $cfApply('minify', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PATCH',
                    '/zones/' . $cfZoneId . '/settings/minify',
                    $cfToken,
                    ['value' => ['css' => 'on', 'html' => 'on', 'js' => 'on']]
                );
            });

            // ── HSTS ────────────────────────────────────────────────────────
            $cfApply('hsts', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PATCH',
                    '/zones/' . $cfZoneId . '/settings/security_header',
                    $cfToken,
                    ['value' => [
                        'strict_transport_security' => [
                            'enabled'            => true,
                            'max_age'            => 31536000,
                            'include_subdomains' => true,
                            'preload'            => true,
                            'nosniff'            => true,
                        ],
                    ]]
                );
            });

            // ── Page Shield (Client-side Security) ─────────────────────────
            // PUT (not PATCH) — Requires Zone → Client-side Security → Edit.
            $cfApply('page_shield', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/page_shield/settings',
                    $cfToken,
                    ['enabled' => true, 'use_cloudflare_reporting_endpoint' => true, 'use_connection_url_path' => true]
                );
            });

            // ── Leaked Credential Checks ────────────────────────────────────
            // PUT with underscore path — Business/Enterprise only.
            $cfApply('leaked_credential_checks', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/leaked_credential_checks',
                    $cfToken,
                    ['enabled' => true]
                );
            });

            // ── WAF Managed Ruleset ─────────────────────────────────────────
            // Ruleset ID efb7b8c949ac4650a09736fc376e9aee is fixed across all accounts.
            $cfApply('waf_managed_rules', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/rulesets/phases/http_request_firewall_managed/entrypoint',
                    $cfToken,
                    [
                        'description' => 'Execute Cloudflare Managed Ruleset',
                        'rules' => [[
                            'action'            => 'execute',
                            'action_parameters' => ['id' => 'efb7b8c949ac4650a09736fc376e9aee'],
                            'expression'        => 'true',
                            'description'       => 'Cloudflare Managed Ruleset',
                            'enabled'           => true,
                        ]],
                    ]
                );
            });

            // ── Response Headers Transform ──────────────────────────────────
            // Strips X-Powered-By/Server; injects security response headers.
            $cfApply('response_headers_transform', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/rulesets/phases/http_response_headers_transform/entrypoint',
                    $cfToken,
                    [
                        'description' => 'Response header hardening',
                        'rules' => [[
                            'action' => 'rewrite',
                            'action_parameters' => [
                                'headers' => [
                                    'X-Powered-By'                => ['operation' => 'remove'],
                                    'Server'                      => ['operation' => 'remove'],
                                    'X-Content-Type-Options'      => ['operation' => 'set', 'value' => 'nosniff'],
                                    'X-Frame-Options'             => ['operation' => 'set', 'value' => 'SAMEORIGIN'],
                                    'Referrer-Policy'             => ['operation' => 'set', 'value' => 'strict-origin-when-cross-origin'],
                                    'Permissions-Policy'          => ['operation' => 'set', 'value' => 'interest-cohort=()'],
                                    'X-XSS-Protection'            => ['operation' => 'set', 'value' => '1; mode=block'],
                                    'Cross-Origin-Opener-Policy'  => ['operation' => 'set', 'value' => 'same-origin'],
                                    'CF-Leaked-Credentials-Check' => [
                                        'operation'  => 'set',
                                        'expression' => 'cf.waf.credential_check.saw_results',
                                    ],
                                ],
                            ],
                            'expression'  => 'true',
                            'description' => 'Remove X-Powered-By/Server + add security headers + leaked-creds check',
                            'enabled'     => true,
                        ]],
                    ]
                );
            });

            // ── Smart Shield / Bot Management ───────────────────────────────
            // Super Bot Fight Mode + JS detection + auto-update model.
            // PUT (not PATCH) — Requires Zone → Bot Management → Edit (Pro/Business/Enterprise).
            $cfApply('smart_shield', static function () use ($cfZoneId, $cfToken): void {
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/bot_management',
                    $cfToken,
                    ['fight_mode' => true, 'enable_js' => true, 'auto_update_model' => true]
                );
            });

            // ── DMARC Management ────────────────────────────────────────────
            $cfApply('dmarc_management', static function () use ($cfZoneId, $cfToken): void {
                try {
                    installerCloudflareRequest('PUT', '/zones/' . $cfZoneId . '/dmarc_management', $cfToken, ['enabled' => true]);
                } catch (Throwable $e1) {
                    // Fallback to older email/security/settings endpoint shape.
                    installerCloudflareRequest('PATCH', '/zones/' . $cfZoneId . '/email/security/settings', $cfToken, ['dmarc_management_enabled' => true]);
                }
            });

            // ── Custom WAF skip rules ───────────────────────────────────────
            // Rule 1: Static assets + social preview bots → skip all WAF/UAM.
            //   Without this, Bot Fight Mode challenges facebookexternalhit and
            //   similar crawlers, breaking OG image fetches and link previews on
            //   Facebook, Twitter/X, Telegram, WhatsApp, Slack, Discord, LinkedIn.
            // Rule 2: Indonesia traffic → skip all WAF.
            $cfApply('custom_skip_rules', static function () use ($cfZoneId, $cfToken): void {
                $assetExt = '{"jpg" "jpeg" "png" "gif" "webp" "svg" "ico" "avif" "bmp"'
                    . ' "css" "js" "woff" "woff2" "ttf" "eot" "otf" "map" "mp4" "webm" "mp3" "ogg"}';
                $scraperUa = '(lower(http.user_agent) contains "facebookexternalhit") or '
                    . '(lower(http.user_agent) contains "facebookcatalog") or '
                    . '(lower(http.user_agent) contains "facebot") or '
                    . '(lower(http.user_agent) contains "meta-externalagent") or '
                    . '(lower(http.user_agent) contains "twitterbot") or '
                    . '(lower(http.user_agent) contains "telegrambot") or '
                    . '(lower(http.user_agent) contains "whatsapp") or '
                    . '(lower(http.user_agent) contains "slackbot") or '
                    . '(lower(http.user_agent) contains "discordbot") or '
                    . '(lower(http.user_agent) contains "linkedinbot") or '
                    . '(lower(http.user_agent) contains "applebot") or '
                    . '(lower(http.user_agent) contains "googlebot") or '
                    . '(lower(http.user_agent) contains "pinterest")';
                $skipProducts = ['bic', 'hot', 'rateLimit', 'securityLevel', 'uaBlock', 'waf', 'zoneLockdown'];
                $skipPhases   = ['http_ratelimit', 'http_request_firewall_managed'];
                installerCloudflareRequest(
                    'PUT',
                    '/zones/' . $cfZoneId . '/rulesets/phases/http_request_firewall_custom/entrypoint',
                    $cfToken,
                    [
                        'description' => 'Custom firewall rules',
                        'rules' => [
                            [
                                'action' => 'skip',
                                'action_parameters' => ['ruleset' => 'current', 'phases' => $skipPhases, 'products' => $skipProducts],
                                'expression'  => '(http.request.uri.path.extension in ' . $assetExt . ') or '
                                    . '(http.request.uri.path eq "/ogimg.php") or '
                                    . $scraperUa,
                                'description' => 'Skip WAF/UAM for static assets + social scrapers',
                                'enabled'     => true,
                            ],
                            [
                                'action' => 'skip',
                                'action_parameters' => ['ruleset' => 'current', 'phases' => $skipPhases, 'products' => $skipProducts],
                                'expression'  => '(ip.src.country eq "ID")',
                                'description' => 'Skip all WAF components for ID traffic',
                                'enabled'     => true,
                            ],
                        ],
                    ]
                );
            });

            $cfMsg = count($cfApplied) . ' settings applied: ' . implode(', ', $cfApplied);
            if ($cfFailed !== []) {
                $cfMsg .= '. Skipped (plan/permission): ' . implode('; ', $cfFailed);
            }

            ajaxJson(true, $cfMsg);

            // ------------------------------------------------------------------
            // no break
        case 'download_geolite2':
            $s5 = $_SESSION['idata'][5] ?? [];

            $licenseKey = trim((string) ($s5['MAXMIND_LICENSE_KEY'] ?? ''));
            $targetPath = __DIR__ . '/data/geoip/GeoLite2-Country.mmdb';

            if ($licenseKey === '') {
                ajaxJson(false, 'MAXMIND_LICENSE_KEY is not set. Go back to step 5 and configure it.');
            }

            $downloadUrl = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key='
                . rawurlencode($licenseKey)
                . '&suffix=tar.gz';

            $targetDirectory = dirname($targetPath);
            if (!is_dir($targetDirectory) && !mkdir($targetDirectory, 0775, true) && !is_dir($targetDirectory)) {
                ajaxJson(false, 'Failed to create target directory: ' . $targetDirectory);
            }

            $workDir = installerCreateGeoLiteWorkDir($targetDirectory);
            if ($workDir === null) {
                ajaxJson(false, 'Failed to create GeoLite2 working directory. Check temp directory and target directory permissions.');
            }
            $archivePath = $workDir . DIRECTORY_SEPARATOR . 'GeoLite2-Country.tar.gz';

            try {
                // --- Download ---
                $handle = fopen($archivePath, 'wb');
                if ($handle === false) {
                    throw new RuntimeException('Failed to open temporary file for download.');
                }

                $curl = curl_init($downloadUrl);
                if ($curl === false) {
                    fclose($handle);
                    throw new RuntimeException('Failed to initialize cURL.');
                }

                curl_setopt_array($curl, [
                    CURLOPT_FILE            => $handle,
                    CURLOPT_FOLLOWLOCATION  => true,
                    CURLOPT_TIMEOUT         => 180,
                    CURLOPT_CONNECTTIMEOUT  => 15,
                    CURLOPT_SSL_VERIFYPEER  => true,
                    CURLOPT_SSL_VERIFYHOST  => 2,
                    CURLOPT_FAILONERROR     => true,
                    CURLOPT_USERAGENT       => 'notrackng-installer/1.0',
                ]);

                if (curl_exec($curl) === false) {
                    $err = curl_error($curl);
                    fclose($handle);
                    throw new RuntimeException('Download failed: ' . $err);
                }

                $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
                curl_close($curl);
                fclose($handle);

                if ($httpCode >= 400) {
                    throw new RuntimeException('Download failed with HTTP ' . $httpCode . '. Check MaxMind license key.');
                }

                // --- Extract ---
                $tarPath = preg_replace('/\.gz$/', '', $archivePath);
                if (!is_string($tarPath) || $tarPath === '') {
                    throw new RuntimeException('Invalid tar path.');
                }

                if (is_file($tarPath) && !unlink($tarPath)) {
                    throw new RuntimeException('Failed to clean up old tar file.');
                }

                $archive = new PharData($archivePath);
                $archive->decompress();
                $tar = new PharData($tarPath);
                $tar->extractTo($workDir, null, true);

                // --- Find .mmdb ---
                $mmdbPath = null;
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($workDir, FilesystemIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if (!$file instanceof SplFileInfo) {
                        continue;
                    }
                    if (strtolower($file->getFilename()) === 'geolite2-country.mmdb') {
                        $mmdbPath = $file->getPathname();
                        break;
                    }
                }

                if ($mmdbPath === null) {
                    throw new RuntimeException('GeoLite2-Country.mmdb not found in archive.');
                }

                if (!copy($mmdbPath, $targetPath)) {
                    throw new RuntimeException('Failed to copy .mmdb to ' . $targetPath);
                }

                chmod($targetPath, 0640);
                rmdirRecursive($workDir);

                ajaxJson(true, 'GeoLite2-Country.mmdb downloaded successfully to ' . $targetPath);
            } catch (Throwable $e) {
                rmdirRecursive($workDir);
                installerFailAjax('GeoLite2 download failed: ' . $e->getMessage(), 422);
            }

            // ------------------------------------------------------------------
        case 'setup_cron':
            $s3 = $_SESSION['idata'][3] ?? [];
            $cpanelHost  = trim((string) ($s3['CPANEL_HOST'] ?? ''));
            $cpanelPort  = (int) (trim((string) ($s3['CPANEL_PORT'] ?? '2083')) ?: 2083);
            $cpanelUser  = trim((string) ($s3['CPANEL_USER'] ?? ''));
            $cpanelToken = trim((string) ($s3['CPANEL_TOKEN'] ?? ''));
            $baseDir     = trim((string) ($s3['BASE_DIR'] ?? ''));

            if ($cpanelUser === '' || $baseDir === '') {
                ajaxJson(false, 'CPANEL_USER / BASE_DIR missing. Go back to step 3.');
            }

            $appRoot = '/home/' . $cpanelUser . '/' . $baseDir;
            $phpBin  = installerDetectPhpCliBinary();
            $cronJobs = installerCronJobs($phpBin, $appRoot);
            $cronCommandsText = installerCronCommandsText($cronJobs);

            $tryCrontabFallback = static function (array $cronJobs, string $phpBin, string $cronCommandsText, string $uapiError = ''): void {
                $cli = installerCronInstallViaCrontab($cronJobs);
                if ($cli['ok']) {
                    $msg = 'Cron jobs installed via local crontab CLI. Added: ' . $cli['added']
                        . ', already present: ' . $cli['skipped']
                        . '. PHP binary: ' . $phpBin;
                    if ($uapiError !== '') {
                        $msg .= ' (UAPI fallback reason: ' . $uapiError . ')';
                    }
                    installerRememberCronSetup('crontab', $msg, $cronCommandsText);
                    ajaxJson(true, $msg);
                }

                $manualMessage = 'Automatic cron setup failed. Add these cron lines manually: '
                    . $cronCommandsText
                    . '. Reason: ' . ($cli['error'] ?? 'unknown crontab error')
                    . ($uapiError !== '' ? '; UAPI error: ' . $uapiError : '');
                installerRememberCronSetup('manual', $manualMessage, $cronCommandsText);
                ajaxJson(true, $manualMessage);
            };

            if ($cpanelHost === '' || $cpanelToken === '') {
                $tryCrontabFallback($cronJobs, $phpBin, $cronCommandsText, 'UAPI credentials empty');
            }

            $added  = 0;
            $errors = [];

            foreach ($cronJobs as $job) {
                try {
                    $result = installerCpanelUapi($cpanelHost, $cpanelPort, $cpanelUser, $cpanelToken, 'Cron', 'add_line', $job);
                    if (($result['status'] ?? 0) == 1) {
                        $added++;
                    } else {
                        $errMsg = '';
                        if (isset($result['errors']) && is_array($result['errors'])) {
                            $errMsg = implode('; ', $result['errors']);
                        }
                        if (stripos($errMsg, 'Failed to load module') !== false) {
                            $tryCrontabFallback($cronJobs, $phpBin, $cronCommandsText, 'Cron UAPI module unavailable');
                        }
                        $errors[] = basename(explode('/ops/', $job['command'])[1] ?? $job['command'], '.php') . ': ' . ($errMsg ?: 'unknown error');
                    }
                } catch (Throwable $e) {
                    $msg = $e->getMessage();
                    if (stripos($msg, 'Failed to load module') !== false) {
                        $tryCrontabFallback($cronJobs, $phpBin, $cronCommandsText, 'Cron UAPI module unavailable');
                    }
                    $errors[] = $msg;
                    break;
                }
            }

            if ($added === count($cronJobs)) {
                installerRememberCronSetup('cpanel', $added . ' cron jobs installed via cPanel UAPI. PHP binary: ' . $phpBin, $cronCommandsText);
                ajaxJson(true, $added . ' cron jobs installed via cPanel UAPI. PHP binary: ' . $phpBin);
            } elseif ($added > 0) {
                $partialMessage = $added . '/' . count($cronJobs) . ' cron jobs added via UAPI. Complete the rest manually if needed: '
                    . $cronCommandsText
                    . '. Errors: ' . implode('; ', $errors);
                installerRememberCronSetup('partial', $partialMessage, $cronCommandsText);
                ajaxJson(
                    true,
                    $partialMessage
                );
            } else {
                $tryCrontabFallback($cronJobs, $phpBin, $cronCommandsText, $errors ? implode('; ', $errors) : 'unknown UAPI failure');
            }

            // ------------------------------------------------------------------
            // no break
        case 'self_destruct':
            $self = __FILE__;
            if (@unlink($self)) {
                ajaxJson(true, 'install.php deleted successfully.');
            }
            ajaxJson(false, 'Failed to delete install.php — remove manually via FTP/SSH.');

            // ------------------------------------------------------------------
            // no break
        default:
            ajaxJson(false, 'Unknown action: ' . $action);
    }
}

// ---------------------------------------------------------------------------
// Form POST handler — save step data to session, then redirect
// ---------------------------------------------------------------------------
if (isset($_POST['_step'])) {
    $step = (int) $_POST['_step'];

    if ($step >= 2 && $step <= 5) {
        $data = $_POST;
        unset($data['_step'], $data['_ajax'], $data['install_token']);
        $noTrimKeys = ['DB_PASS', 'ADMIN_PASS', 'CPANEL_TOKEN', 'CF_TOKEN',
                       'MAXMIND_LICENSE_KEY', 'IXG_API_SECRET', 'TINYURL_API_KEY',
                       'GSB_API_KEY', 'APP_TOKEN', 'POSTBACK_SECRET', 'METRICS_TOKEN'];
        foreach ($data as $k => $v) {
            if (is_string($v) && !in_array($k, $noTrimKeys, true)) {
                $data[$k] = trim($v);
            }
        }
        $_SESSION['idata'][$step] = $data;
    }

    // Redirect to next step
    $nextStep = $step + 1;
    header('Location: install.php?step=' . $nextStep);
    exit(0);
}

// ---------------------------------------------------------------------------
// Determine current step
// ---------------------------------------------------------------------------
$currentStep = max(1, min(7, (int) ($_GET['step'] ?? 1)));

if ($currentStep === 7) {
    // Session data kept so Step 7 can display config summary
}

// ---------------------------------------------------------------------------
// Step 1 — Requirements check
// ---------------------------------------------------------------------------
$reqs = [];
if ($currentStep === 1) {
    $reqs = [
        'php_version' => [
            'label'  => 'PHP >= 8.3',
            'pass'   => PHP_VERSION_ID >= 80300,
            'detail' => PHP_VERSION,
        ],
        'ext_pdo' => [
            'label'  => 'Extension: pdo',
            'pass'   => extension_loaded('pdo'),
            'detail' => '',
        ],
        'ext_pdo_mysql' => [
            'label'  => 'Extension: pdo_mysql',
            'pass'   => extension_loaded('pdo_mysql'),
            'detail' => '',
        ],
        'ext_curl' => [
            'label'  => 'Extension: curl',
            'pass'   => extension_loaded('curl'),
            'detail' => '',
        ],
        'ext_json' => [
            'label'  => 'Extension: json',
            'pass'   => extension_loaded('json'),
            'detail' => '',
        ],
        'ext_phar' => [
            'label'  => 'Extension: phar',
            'pass'   => extension_loaded('phar'),
            'detail' => '',
        ],
        'ext_openssl' => [
            'label'  => 'Extension: openssl',
            'pass'   => extension_loaded('openssl'),
            'detail' => '',
        ],
        'ext_apcu' => [
            'label'  => 'Extension: apcu (recommended)',
            'pass'   => extension_loaded('apcu'),
            'warn'   => true,
            'detail' => extension_loaded('apcu') ? (ini_get('apc.enabled') ? 'enabled' : 'loaded but disabled') : 'not loaded — app works without it but slower',
        ],
        'ext_mbstring' => [
            'label'  => 'Extension: mbstring',
            'pass'   => extension_loaded('mbstring'),
            'detail' => '',
        ],
        'writable_root' => [
            'label'  => 'Writable: . (root)',
            'pass'   => is_writable(__DIR__),
            'detail' => __DIR__,
        ],
        'writable_data' => [
            'label'  => 'Writable: data/',
            'pass'   => is_dir(__DIR__ . '/data') && is_writable(__DIR__ . '/data'),
            'detail' => __DIR__ . '/data',
        ],
        'writable_geoip' => [
            'label'  => 'Writable: data/geoip/',
            'pass'   => (is_dir(__DIR__ . '/data/geoip') || mkdir(__DIR__ . '/data/geoip', 0775, true))
                        && is_writable(__DIR__ . '/data/geoip'),
            'detail' => __DIR__ . '/data/geoip',
        ],
    ];
}

$allPass = true;
if ($currentStep === 1) {
    foreach ($reqs as $req) {
        if (empty($req['pass']) && empty($req['warn'])) {
            $allPass = false;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// HTML output
// ---------------------------------------------------------------------------
$stepTitles = [
    1 => 'Requirements',
    2 => 'Database',
    3 => 'Server & cPanel',
    4 => 'Admin & Security',
    5 => 'APIs & Cloudflare',
    6 => 'Install',
    7 => 'Done',
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installer</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="assets/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="assets/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="assets/apple-touch-icon.png">
    <script nonce="<?= h($installerCspNonce) ?>" src="https://cdn.tailwindcss.com"></script>
    <script nonce="<?= h($installerCspNonce) ?>" defer src="assets/vendor/alpine-3.15.11.min.js"></script>
    <script nonce="<?= h($installerCspNonce) ?>">
        const INSTALL_TOKEN = <?= json_encode($installToken, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
    </script>
    <style nonce="<?= h($installerCspNonce) ?>">
        .step-active  { background:#3b82f6; color:#fff; }
        .step-done    { background:#22c55e; color:#fff; }
        .step-pending { background:#e5e7eb; color:#6b7280; }
        .spinner {
            display:inline-block; width:1rem; height:1rem;
            border:2px solid currentColor; border-top-color:transparent;
            border-radius:50%; animation:spin .7s linear infinite;
        }
        @keyframes spin { to { transform:rotate(360deg); } }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">

    <!-- Header -->
    <div class="bg-white border-b shadow-sm">
        <div class="max-w-3xl mx-auto px-4 py-4 flex items-center gap-3">
            <span class="text-xl font-bold text-blue-600">Installer</span>
            <span class="text-gray-400">/</span>
            <span class="text-gray-600 font-medium">Installer Wizard</span>
        </div>
    </div>

    <!-- Step indicator -->
    <div class="max-w-3xl mx-auto px-4 pt-6">
        <div class="flex items-center gap-1 overflow-x-auto pb-2">
            <?php foreach ($stepTitles as $n => $title) : ?>
                <?php
                $cls = 'step-pending';
                if ($n < $currentStep) {
                    $cls = 'step-done';
                } elseif ($n === $currentStep) {
                    $cls = 'step-active';
                }
                ?>
                <div class="flex items-center gap-1 flex-shrink-0">
                    <div class="<?= $cls ?> w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold"><?= $n ?></div>
                    <span class="text-xs text-gray-500 hidden sm:inline whitespace-nowrap"><?= h($title) ?></span>
                    <?php if ($n < 7) : ?>
                        <span class="text-gray-300 mx-1">›</span>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Main card -->
    <div class="max-w-3xl mx-auto px-4 py-6">
        <div class="bg-white rounded-xl shadow-md p-6 sm:p-8">

            <h2 class="text-xl font-bold text-gray-800 mb-6 pb-3 border-b">
                Step <?= $currentStep ?> — <?= h($stepTitles[$currentStep] ?? '') ?>
            </h2>

            <?php
            // ================================================================
            // STEP 1 — Requirements
            // ================================================================
            if ($currentStep === 1) :
                ?>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b">
                            <th class="text-left py-2 font-semibold text-gray-600">Requirement</th>
                            <th class="text-left py-2 font-semibold text-gray-600">Status</th>
                            <th class="text-left py-2 font-semibold text-gray-600">Detail</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($reqs as $req) : ?>
                        <tr class="border-b border-gray-50">
                            <td class="py-2 text-gray-700"><?= h($req['label']) ?></td>
                            <td class="py-2">
                                <?php if ($req['pass']) : ?>
                                    <span class="inline-flex items-center gap-1 text-green-600 font-medium">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                        </svg>
                                        Pass
                                    </span>
                                <?php else : ?>
                                    <span class="inline-flex items-center gap-1 text-red-600 font-medium">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                        </svg>
                                        Fail
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td class="py-2 text-gray-400 text-xs font-mono"><?= h($req['detail']) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="mt-6 flex justify-end">
                <a href="install.php?step=2"
                   class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm transition
                          <?= $allPass ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-gray-200 text-gray-400 pointer-events-none cursor-not-allowed' ?>"
                   <?= $allPass ? '' : 'tabindex="-1" aria-disabled="true"' ?>>
                    Continue to Database
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                    </svg>
                </a>
            </div>

                <?php
                // ================================================================
                // STEP 2 — Database
                // ================================================================
            elseif ($currentStep === 2) :
                ?>
            <script nonce="<?= h($installerCspNonce) ?>">
            document.addEventListener('alpine:init', function () {
                Alpine.data('installStep2', function () {
                    return {
                    submitting: false,
                    dbHost: <?= json_encode(iv(2, 'DB_HOST', 'localhost')) ?>,
                    dbUser: <?= json_encode(iv(2, 'DB_USER')) ?>,
                    dbPass: <?= json_encode(iv(2, 'DB_PASS')) ?>,
                    dbName: <?= json_encode(iv(2, 'DB_NAME')) ?>,
                    testing: false,
                    testOk: null,
                    testMsg: '',
                    async testConn() {
                        this.testing = true;
                        this.testOk = null;
                        this.testMsg = '';
                        try {
                            const fd = new FormData();
                            fd.append('_ajax', '1');
                            fd.append('install_token', INSTALL_TOKEN);
                            fd.append('action', 'test_db');
                            fd.append('DB_HOST', this.dbHost);
                            fd.append('DB_USER', this.dbUser);
                            fd.append('DB_PASS', this.dbPass);
                            fd.append('DB_NAME', this.dbName);
                            const r = await fetch('install.php', { method: 'POST', body: fd });
                            const j = await r.json();
                            this.testOk = j.ok;
                            this.testMsg = j.msg;
                        } catch(e) {
                            this.testOk = false;
                            this.testMsg = 'Request failed: ' + e.message;
                        } finally {
                            this.testing = false;
                        }
                    }
                };
                });
            });
            </script>
            <div x-data="installStep2">
                <form method="POST" action="install.php" @submit="submitting = true">
                    <input type="hidden" name="_step" value="2">
                    <input type="hidden" name="install_token" value="<?= h($installToken) ?>">

                    <div class="grid gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">DB_HOST</label>
                            <input type="text" name="DB_HOST" x-model="dbHost"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                   placeholder="localhost">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">DB_USER</label>
                            <input type="text" name="DB_USER" x-model="dbUser"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                   placeholder="db_username" autocomplete="username">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">DB_PASS</label>
                            <input type="password" name="DB_PASS" x-model="dbPass"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                   placeholder="••••••••" autocomplete="current-password">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">DB_NAME</label>
                            <input type="text" name="DB_NAME" x-model="dbName"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                   placeholder="database_name">
                        </div>
                    </div>

                    <!-- Test result banner -->
                    <div class="mt-4" x-show="testMsg !== ''" x-cloak>
                        <div :class="testOk ? 'bg-green-50 border-green-300 text-green-800' : 'bg-red-50 border-red-300 text-red-800'"
                             class="border rounded-lg px-4 py-3 text-sm" x-text="testMsg"></div>
                    </div>

                    <div class="mt-6 flex items-center justify-between gap-3">
                        <button type="button" @click="testConn()"
                                :disabled="testing"
                                class="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 transition">
                            <span x-show="testing" class="spinner text-blue-500"></span>
                            <span x-text="testing ? 'Checking...' : 'Test Connection'"></span>
                        </button>

                        <button type="submit" :disabled="submitting"
                                class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition disabled:opacity-60 disabled:cursor-not-allowed">
                            <span x-show="submitting" class="spinner" style="border-color:rgba(255,255,255,.5);border-top-color:#fff;"></span>
                            <span x-text="submitting ? 'Saving...' : 'Continue'"></span>
                            <svg x-show="!submitting" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                            </svg>
                        </button>
                    </div>
                </form>
            </div>

                    <?php
                // ================================================================
                // STEP 3 — Server & cPanel
                // ================================================================
            elseif ($currentStep === 3) :
                ?>
            <?php
                $autoServerIp = installerDetectServerIp();
                $autoPrimaryDomain = installerDetectPrimaryDomain();
                $autoBaseDir = installerDetectBaseDir();
                $autoNameservers = installerDetectNameservers($autoPrimaryDomain);
            ?>
            <script nonce="<?= h($installerCspNonce) ?>">
            document.addEventListener('alpine:init', function () {
                Alpine.data('installStep3', function () {
                    return {
                    submitting: false,
                    baseDir: <?= json_encode(iv(3, 'BASE_DIR', $autoBaseDir)) ?>,
                    wildcardDir: <?= json_encode(iv(3, 'WILDCARD_DIR', $autoBaseDir)) ?>,
                    syncWildcard() {
                        if (this.wildcardDir === '') {
                            this.wildcardDir = this.baseDir;
                        }
                    }
                };
                });
            });
            </script>
            <form method="POST" action="install.php" x-data="installStep3" @submit="submitting = true">
                <input type="hidden" name="_step" value="3">
                <input type="hidden" name="install_token" value="<?= h($installToken) ?>">

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">Server</h3>
                <div class="grid gap-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            SERVER_IP
                            <?php if ($autoServerIp !== '' && iv(3, 'SERVER_IP') === '') : ?>
                                <span class="text-green-600 font-normal text-xs">(auto-detected)</span>
                            <?php endif; ?>
                        </label>
                        <input type="text" name="SERVER_IP" value="<?= h(iv(3, 'SERVER_IP', $autoServerIp)) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="123.456.789.0">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            BASE_DIR
                            <?php if ($autoBaseDir !== '' && iv(3, 'BASE_DIR') === '') : ?>
                                <span class="text-green-600 font-normal text-xs">(auto-detected)</span>
                            <?php endif; ?>
                        </label>
                        <input type="text" name="BASE_DIR" x-model="baseDir" @input="syncWildcard()"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="public_html/notrackng">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            WILDCARD_DIR
                            <span class="text-gray-400 font-normal">(empty = auto from BASE_DIR)</span>
                        </label>
                        <input type="text" name="WILDCARD_DIR" x-model="wildcardDir"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="(same as BASE_DIR)">
                    </div>
                </div>

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">cPanel</h3>
                <div class="grid gap-4">
                    <div class="grid grid-cols-3 gap-4">
                        <div class="col-span-2">
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                CPANEL_HOST
                                <?php if ($autoPrimaryDomain !== '' && iv(3, 'CPANEL_HOST') === '') : ?>
                                    <span class="text-green-600 font-normal text-xs">(auto-detected)</span>
                                <?php endif; ?>
                            </label>
                            <input type="text" name="CPANEL_HOST" value="<?= h(iv(3, 'CPANEL_HOST', $autoPrimaryDomain)) ?>"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                                   placeholder="yourdomain.com">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">CPANEL_PORT</label>
                            <input type="number" name="CPANEL_PORT" value="<?= h(iv(3, 'CPANEL_PORT', '2083')) ?>"
                                   class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none">
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CPANEL_USER</label>
                        <input type="text" name="CPANEL_USER" value="<?= h(iv(3, 'CPANEL_USER')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="cpanel_username">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CPANEL_TOKEN</label>
                        <input type="password" name="CPANEL_TOKEN" value="<?= h(iv(3, 'CPANEL_TOKEN')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="cPanel API Token">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            CPANEL_DOMAIN
                            <span class="text-gray-400 font-normal">(optional)</span>
                            <?php if ($autoPrimaryDomain !== '' && iv(3, 'CPANEL_DOMAIN') === '') : ?>
                                <span class="text-green-600 font-normal text-xs">(auto-detected)</span>
                            <?php endif; ?>
                        </label>
                        <input type="text" name="CPANEL_DOMAIN" value="<?= h(iv(3, 'CPANEL_DOMAIN', $autoPrimaryDomain)) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="yourdomain.com">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            CPANEL_NAMESERVERS
                            <span class="text-gray-400 font-normal">(optional, comma-separated)</span>
                            <?php if ($autoNameservers !== '' && iv(3, 'CPANEL_NAMESERVERS') === '') : ?>
                                <span class="text-green-600 font-normal text-xs">(auto-detected)</span>
                            <?php endif; ?>
                        </label>
                        <input type="text" name="CPANEL_NAMESERVERS" value="<?= h(iv(3, 'CPANEL_NAMESERVERS', $autoNameservers)) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="ns1.example.com,ns2.example.com">
                        <p class="text-xs text-gray-400 mt-1">Override nameservers for DNS validation. Empty = auto-detect via DNS lookup.</p>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <button type="submit" :disabled="submitting"
                            class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition disabled:opacity-60 disabled:cursor-not-allowed">
                        <span x-show="submitting" class="spinner" style="border-color:rgba(255,255,255,.5);border-top-color:#fff;"></span>
                        <span x-text="submitting ? 'Saving...' : 'Continue'"></span>
                        <svg x-show="!submitting" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                        </svg>
                    </button>
                </div>
            </form>

                    <?php
                // ================================================================
                // STEP 4 — Admin & Security
                // ================================================================
            elseif ($currentStep === 4) :
                ?>
            <script nonce="<?= h($installerCspNonce) ?>">
            document.addEventListener('alpine:init', function () {
                Alpine.data('installStep4', function () {
                    return {
                    submitting: false,
                    pass: '',
                    confirm: '',
                    token: <?= json_encode(iv(4, 'APP_TOKEN')) ?>,
                    postbackSecret: <?= json_encode(iv(4, 'POSTBACK_SECRET')) ?>,
                    metricsToken: <?= json_encode(iv(4, 'METRICS_TOKEN')) ?>,
                    get mismatch() { return this.confirm !== '' && this.pass !== this.confirm; },
                    generateRandom(len) {
                        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                        let t = '';
                        for (let i = 0; i < len; i++) t += chars.charAt(Math.floor(Math.random() * chars.length));
                        return t;
                    },
                    generateToken() { this.token = this.generateRandom(48); },
                    generatePostbackSecret() { this.postbackSecret = this.generateRandom(64); },
                    generateMetricsToken() { this.metricsToken = this.generateRandom(32); }
                };
                });
            });
            </script>
            <form method="POST" action="install.php" x-data="installStep4" @submit="submitting = true">
                <input type="hidden" name="_step" value="4">
                <input type="hidden" name="install_token" value="<?= h($installToken) ?>">

                <div class="grid gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">ADMIN_USER</label>
                        <input type="text" name="ADMIN_USER" value="<?= h(iv(4, 'ADMIN_USER', 'admin')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               required autocomplete="username">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">ADMIN_PASS</label>
                        <input type="password" name="ADMIN_PASS" x-model="pass"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               required autocomplete="new-password" minlength="8">
                        <p class="text-xs text-gray-400 mt-1">Minimum 8 characters</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
                        <input type="password" x-model="confirm"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 outline-none"
                               :class="mismatch ? 'border-red-400 focus:ring-red-500' : 'border-gray-300 focus:ring-blue-500'"
                               autocomplete="new-password">
                        <p x-show="mismatch" class="text-xs text-red-500 mt-1" x-cloak>Passwords do not match.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            APP_TOKEN
                            <span class="text-gray-400 font-normal">(optional)</span>
                        </label>
                        <div class="flex gap-2">
                            <input type="text" name="APP_TOKEN" x-model="token"
                                   class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                                   placeholder="Token (optional)">
                            <button type="button" @click="generateToken()"
                                    class="px-3 py-2 rounded-lg border border-gray-300 text-sm text-gray-600 hover:bg-gray-50 transition whitespace-nowrap">
                                Generate
                            </button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            POSTBACK_SECRET
                            <span class="text-gray-400 font-normal">(HMAC signature for postbacks)</span>
                        </label>
                        <div class="flex gap-2">
                            <input type="text" name="POSTBACK_SECRET" x-model="postbackSecret"
                                   class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                                   placeholder="Leave empty to disable HMAC verification">
                            <button type="button" @click="generatePostbackSecret()"
                                    class="px-3 py-2 rounded-lg border border-gray-300 text-sm text-gray-600 hover:bg-gray-50 transition whitespace-nowrap">
                                Generate
                            </button>
                        </div>
                        <p class="text-xs text-gray-400 mt-1">Used by /postback endpoint (recv.php) to verify postback signatures. Empty = fail-open.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            METRICS_TOKEN
                            <span class="text-gray-400 font-normal">(optional)</span>
                        </label>
                        <div class="flex gap-2">
                            <input type="text" name="METRICS_TOKEN" x-model="metricsToken"
                                   class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                                   placeholder="Token for /metrics HTTP access">
                            <button type="button" @click="generateMetricsToken()"
                                    class="px-3 py-2 rounded-lg border border-gray-300 text-sm text-gray-600 hover:bg-gray-50 transition whitespace-nowrap">
                                Generate
                            </button>
                        </div>
                        <p class="text-xs text-gray-400 mt-1">Auth token for Prometheus-style metrics endpoint. Empty = no HTTP auth.</p>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <button type="submit" :disabled="submitting || mismatch || pass.length < 8"
                            class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed">
                        <span x-show="submitting" class="spinner" style="border-color:rgba(255,255,255,.5);border-top-color:#fff;"></span>
                        <span x-text="submitting ? 'Saving...' : 'Continue'"></span>
                        <svg x-show="!submitting" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                        </svg>
                    </button>
                </div>
            </form>

                    <?php
                // ================================================================
                // STEP 5 — APIs & Cloudflare
                // ================================================================
            elseif ($currentStep === 5) :
                ?>
            <script nonce="<?= h($installerCspNonce) ?>">
            document.addEventListener('alpine:init', function () {
                Alpine.data('installStep5', function () {
                    return {
                    submitting: false,
                    cfProxied: <?= iv(5, 'CF_PROXIED', 'true') === 'true' ? 'true' : 'false' ?>,
                    cfBootstrapToken: '',
                    cfToken: <?= json_encode(iv(5, 'CF_TOKEN')) ?>,
                    cfAccountId: <?= json_encode(iv(5, 'CF_ACCOUNT_ID')) ?>,
                    cfLoading: false,
                    cfStatusOk: null,
                    cfStatusMsg: '',
                    async autoCreateToken() {
                        this.cfLoading = true;
                        this.cfStatusOk = null;
                        this.cfStatusMsg = '';
                        try {
                            const fd = new FormData();
                            fd.append('_ajax', '1');
                            fd.append('install_token', INSTALL_TOKEN);
                            fd.append('action', 'auto_create_cf_token');
                            fd.append('CF_BOOTSTRAP_TOKEN', this.cfBootstrapToken);
                            fd.append('CF_ACCOUNT_ID', this.cfAccountId);
                            const response = await fetch('install.php', { method: 'POST', body: fd });
                            const payload = await response.json();
                            if (!payload.ok) {
                                this.cfStatusOk = false;
                                this.cfStatusMsg = payload.msg;
                                return;
                            }
                            this.cfStatusOk = true;
                            this.cfStatusMsg = 'Runtime token created. Submit this step to persist CF_TOKEN into .env.';
                            this.cfToken = payload.token ?? '';
                            this.cfAccountId = payload.account_id ?? this.cfAccountId;
                        } catch (error) {
                            this.cfStatusOk = false;
                            this.cfStatusMsg = 'Request failed: ' + error.message;
                        } finally {
                            this.cfLoading = false;
                        }
                    }
                };
                });
            });
            </script>
            <form method="POST" action="install.php" x-data="installStep5" @submit="submitting = true">
                <input type="hidden" name="_step" value="5">
                <input type="hidden" name="install_token" value="<?= h($installToken) ?>">

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">MaxMind GeoLite2</h3>
                <div class="grid gap-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">MAXMIND_ACCOUNT_ID</label>
                        <input type="text" name="MAXMIND_ACCOUNT_ID" value="<?= h(iv(5, 'MAXMIND_ACCOUNT_ID', '***REDACTED-MAXMIND-ACCT***')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">MAXMIND_LICENSE_KEY</label>
                        <input type="password" name="MAXMIND_LICENSE_KEY" value="<?= h(iv(5, 'MAXMIND_LICENSE_KEY', '***REDACTED-MAXMIND***')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none">
                    </div>
                </div>

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">IXG API</h3>
                <div class="grid gap-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">IXG_API_URL</label>
                        <input type="url" name="IXG_API_URL" value="<?= h(iv(5, 'IXG_API_URL', 'https://me.ixg.llc/api.php')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">IXG_API_SECRET</label>
                        <input type="text" name="IXG_API_SECRET" value="<?= h(iv(5, 'IXG_API_SECRET', '***REDACTED-IXG***')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500 outline-none">
                    </div>
                </div>

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">TinyURL</h3>
                <div class="grid gap-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">TINYURL_API_KEY</label>
                        <input type="text" name="TINYURL_API_KEY" value="<?= h(iv(5, 'TINYURL_API_KEY', '***REDACTED-TINYURL***')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500 outline-none">
                    </div>
                </div>

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">
                    Google Safe Browsing
                    <span class="text-gray-400 font-normal normal-case">(optional)</span>
                </h3>
                <div class="grid gap-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">GSB_API_KEY</label>
                        <input type="text" name="GSB_API_KEY" value="<?= h(iv(5, 'GSB_API_KEY', '***REDACTED-GSB***')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="(optional)">
                    </div>
                </div>

                <h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">Cloudflare</h3>

                <!-- CF Token permission info -->
                <div class="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 mb-4">
                    <div class="flex gap-2">
                        <svg class="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div class="text-xs text-amber-900">
                            <p class="font-semibold text-sm mb-1.5">CF Token Permissions</p>
                            <p class="mb-2"><strong class="text-red-700 bg-red-100 px-1 rounded">PENTING — Subset Policy:</strong> Cloudflare hanya mengijinkan bootstrap token membuat runtime token dengan permission <u>sama atau subset</u> dari milik bootstrap. Jadi bootstrap token <strong>wajib punya SEMUA baris permission di tabel di bawah</strong>, bukan hanya <code class="font-mono bg-amber-100 px-1 rounded">User &rarr; API Tokens &rarr; Edit</code>. Kalau cuma satu baris itu saja, Cloudflare tolak dengan error <em>"Unauthorized to access requested resource"</em>.</p>
                            <p class="mb-2">Cara buat: <strong>Cloudflare &rarr; My Profile &rarr; API Tokens &rarr; Create Token &rarr; "Create Custom Token" &rarr; Get started</strong>, tambahkan tiap baris permission lewat tombol <strong>+ Add more</strong>.</p>

                            <p class="font-semibold mb-1">Required (core):</p>
                            <table class="w-full text-left mb-3">
                                <thead><tr class="border-b border-amber-200">
                                    <th class="py-1 pr-3 font-semibold">Scope</th>
                                    <th class="py-1 pr-3 font-semibold">Permission</th>
                                    <th class="py-1 font-semibold">Used For</th>
                                </tr></thead>
                                <tbody class="font-mono text-[11px]">
                                    <tr class="border-b border-amber-100 bg-amber-100/40"><td class="py-1 pr-3"><strong>User &rarr; API Tokens</strong></td><td class="pr-3"><strong>Edit</strong></td><td class="text-amber-700 font-sans"><strong>WAJIB untuk auto-create</strong> — ijinkan bootstrap token menerbitkan runtime token baru</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Account &rarr; Account Settings</td><td class="pr-3">Read</td><td class="text-amber-700 font-sans">Resolve Account ID when CF_ACCOUNT_ID is left blank</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Zone</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">List, create &amp; delete zones</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; DNS</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">Create, update &amp; delete DNS records (A, CNAME, MX, TXT)</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Zone Settings</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">SSL, HTTP/2, HTTP/3, 0-RTT, Early Hints, Brotli, Minify, Rocket Loader</td></tr>
                                </tbody>
                            </table>

                            <p class="font-semibold mb-1">Optional (enhanced security &mdash; skipped gracefully if missing):</p>
                            <table class="w-full text-left mb-3">
                                <tbody class="font-mono text-[11px]">
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Client-side Security</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">Client-side security monitoring (Page Shield)</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Bot Management</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">Bot Fight Mode</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Zone WAF</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">Cloudflare Managed WAF Ruleset</td></tr>
                                    <tr class="border-b border-amber-100"><td class="py-1 pr-3">Zone &rarr; Leaked Credential Checks</td><td class="pr-3">Edit</td><td class="text-amber-700 font-sans">Detect compromised credentials <span class="font-sans text-[10px] bg-gray-200 text-gray-600 px-1 rounded ml-1">Business/Enterprise only — skip if not visible</span></td></tr>
                                </tbody>
                            </table>

                            <p class="text-amber-600"><strong>Zone Resources:</strong> set to <em>All zones from an account</em> &rarr; select your account. This allows the token to manage both existing and future zones.</p>
                        </div>
                    </div>
                </div>

                <div class="grid gap-4">
                    <div class="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3">
                        <p class="text-sm font-semibold text-blue-900 mb-1">Auto-create runtime token</p>
                        <p class="text-xs text-blue-800 mb-3">Paste <strong>Custom Token</strong> Cloudflare yang punya <strong>SEMUA permission</strong> yang akan dipakai runtime (subset policy). Lihat panel kuning di atas untuk daftar permission lengkap. Token ini hanya dipakai sekali untuk memanggil API dan <strong>tidak</strong> disimpan ke <code class="font-mono">.env</code>.</p>
                        <div class="grid gap-3">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">CF_BOOTSTRAP_TOKEN</label>
                                <input type="password" x-model="cfBootstrapToken"
                                       class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                                       placeholder="Bootstrap token from Create Additional Tokens template">
                            </div>
                            <div class="flex items-center gap-3 flex-wrap">
                                <button type="button" @click="autoCreateToken()" :disabled="cfLoading"
                                        class="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-blue-300 bg-white text-sm font-medium text-blue-700 hover:bg-blue-100 disabled:opacity-50 disabled:cursor-not-allowed transition">
                                    <span x-show="cfLoading" class="spinner text-blue-500"></span>
                                    <span x-text="cfLoading ? 'Creating...' : 'Create CF_TOKEN automatically'"></span>
                                </button>
                                <p class="text-xs text-gray-500">If CF_ACCOUNT_ID is empty, installer tries <code class="font-mono">GET /accounts?per_page=1</code>.</p>
                            </div>
                            <div x-show="cfStatusMsg !== ''" x-cloak>
                                <div :class="cfStatusOk ? 'bg-green-50 border-green-300 text-green-800' : 'bg-red-50 border-red-300 text-red-800'"
                                     class="border rounded-lg px-4 py-3 text-sm" x-text="cfStatusMsg"></div>
                            </div>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CF_TOKEN</label>
                        <input type="password" name="CF_TOKEN" x-model="cfToken"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="Cloudflare runtime API token (Bearer)">
                        <p class="text-xs text-gray-400 mt-1">Filled automatically when bootstrap creation succeeds, or paste an existing runtime token manually.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CF_ACCOUNT_ID</label>
                        <input type="text" name="CF_ACCOUNT_ID" x-model="cfAccountId"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="32-char hex string">
                        <p class="text-xs text-gray-400 mt-1">Found at Cloudflare dashboard &rarr; any site &rarr; Overview sidebar &rarr; Account ID, or auto-resolved from the bootstrap token.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CF_ZONE_ID</label>
                        <input type="text" name="CF_ZONE_ID" value="<?= h(iv(5, 'CF_ZONE_ID')) ?>"
                               class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                               placeholder="32-char hex string (reference zone)">
                        <p class="text-xs text-gray-400 mt-1">Zone ID of your main domain. Found at dashboard &rarr; site &rarr; Overview sidebar &rarr; Zone ID</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">CF_PROXIED</label>
                        <div class="flex items-center gap-3">
                            <button type="button"
                                    @click="cfProxied = !cfProxied"
                                    :class="cfProxied ? 'bg-blue-600' : 'bg-gray-300'"
                                    class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <span :class="cfProxied ? 'translate-x-6' : 'translate-x-1'"
                                      class="inline-block h-4 w-4 transform bg-white rounded-full transition-transform"></span>
                            </button>
                            <span class="text-sm text-gray-600" x-text="cfProxied ? 'Proxied (true)' : 'Direct (false)'"></span>
                            <input type="hidden" name="CF_PROXIED" :value="cfProxied ? 'true' : 'false'">
                        </div>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <button type="submit" :disabled="submitting"
                            class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition disabled:opacity-60 disabled:cursor-not-allowed">
                        <span x-show="submitting" class="spinner" style="border-color:rgba(255,255,255,.5);border-top-color:#fff;"></span>
                        <span x-text="submitting ? 'Saving...' : 'Continue to Install'"></span>
                        <svg x-show="!submitting" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                        </svg>
                    </button>
                </div>
            </form>

                    <?php
                // ================================================================
                // STEP 6 — Install
                // ================================================================
            elseif ($currentStep === 6) :
                ?>
            <div x-data="{
                tasks: [
                    { id: 'write_env',          label: 'Write .env file',                     status: 'pending', msg: '' },
                    { id: 'write_cf',           label: 'Write data/config.json',              status: 'pending', msg: '' },
                    { id: 'configure_cf_zone',  label: 'Apply Cloudflare security & performance settings', status: 'pending', msg: '' },
                    { id: 'run_schema',         label: 'Run SQL schema',                      status: 'pending', msg: '' },
                    { id: 'create_user',      label: 'Create admin user in database',status: 'pending', msg: '' },
                    { id: 'download_geolite2',label: 'Download GeoLite2 Country DB', status: 'pending', msg: '' },
                    { id: 'setup_cron',       label: 'Setup cron jobs via cPanel', status: 'pending', msg: '' }
                ],
                installing: false,
                done: false,

                statusClass(status) {
                    return {
                        pending: 'text-gray-400',
                        running: 'text-blue-500',
                        success: 'text-green-600',
                        error:   'text-red-600'
                    }[status] ?? 'text-gray-400';
                },

                bgClass(status) {
                    return {
                        pending: 'bg-gray-50 border-gray-100',
                        running: 'bg-blue-50 border-blue-200',
                        success: 'bg-green-50 border-green-200',
                        error:   'bg-red-50 border-red-200'
                    }[status] ?? 'bg-gray-50';
                },

                async runTask(task) {
                    task.status = 'running';
                    task.msg = '';
                    try {
                        const fd = new FormData();
                        fd.append('_ajax', '1');
                        fd.append('install_token', INSTALL_TOKEN);
                        fd.append('action', task.id);
                        const r = await fetch('install.php', { method: 'POST', body: fd });
                        const j = await r.json();
                        task.status = j.ok ? 'success' : 'error';
                        task.msg = j.msg;
                        return j.ok;
                    } catch(e) {
                        task.status = 'error';
                        task.msg = 'Request failed: ' + e.message;
                        return false;
                    }
                },

                async startInstall() {
                    this.installing = true;
                    let allOk = true;
                    for (const task of this.tasks) {
                        if (task.status === 'success') continue;
                        const ok = await this.runTask(task);
                        if (!ok) {
                            allOk = false;
                            break;
                        }
                    }
                    this.installing = false;
                    if (allOk) {
                        this.done = true;
                    }
                }
            }">
                <div class="space-y-3 mb-6">
                    <template x-for="task in tasks" :key="task.id">
                        <div class="border rounded-lg px-4 py-3 transition-colors" :class="bgClass(task.status)">
                            <div class="flex items-center gap-3">
                                <!-- Status icon -->
                                <div class="flex-shrink-0">
                                    <!-- Pending -->
                                    <svg x-show="task.status === 'pending'" class="w-5 h-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <circle cx="12" cy="12" r="10" stroke-width="2"/>
                                    </svg>
                                    <!-- Running -->
                                    <span x-show="task.status === 'running'" class="spinner text-blue-500 w-5 h-5" style="width:1.25rem;height:1.25rem;border-width:2px;"></span>
                                    <!-- Success -->
                                    <svg x-show="task.status === 'success'" class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                    </svg>
                                    <!-- Error -->
                                    <svg x-show="task.status === 'error'" class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                    </svg>
                                </div>
                                <div class="flex-1 min-w-0">
                                    <p class="text-sm font-medium text-gray-800" x-text="task.label"></p>
                                    <p x-show="task.msg !== ''" class="text-xs mt-0.5 truncate" :class="statusClass(task.status)" x-text="task.msg"></p>
                                </div>
                                <div class="text-xs font-medium flex-shrink-0" :class="statusClass(task.status)" x-text="task.status.charAt(0).toUpperCase() + task.status.slice(1)"></div>
                            </div>
                        </div>
                    </template>
                </div>

                <p class="text-xs text-gray-400 mb-4">
                    GeoLite2 download may take a few minutes depending on server speed.
                </p>

                <!-- Start button -->
                <div x-show="!done">
                    <button @click="startInstall()" :disabled="installing"
                            class="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium transition disabled:opacity-60 disabled:cursor-not-allowed">
                        <span x-show="installing" class="spinner" style="border-color:rgba(255,255,255,.5);border-top-color:#fff;"></span>
                        <span x-text="installing ? 'Installing...' : 'Start Install'"></span>
                    </button>
                </div>

                <!-- Done button -->
                <div x-show="done" x-cloak>
                    <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm font-medium">
                        All tasks completed! Installation done.
                    </div>
                    <a href="install.php?step=7"
                       class="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-green-600 hover:bg-green-700 text-white font-medium transition">
                        Done
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                        </svg>
                    </a>
                </div>
            </div>

                    <?php
                // ================================================================
                // STEP 7 — Done
                // ================================================================
            elseif ($currentStep === 7) :
                $cronSetupSummary = installerCronSetupSummary();
                $cronMode = $cronSetupSummary['mode'];
                $cronCommands = $cronSetupSummary['commands'];
                $cronMessage = $cronSetupSummary['message'];
                $cronSummaryBoxClass = 'bg-green-50 border-green-200 text-green-800';
                $cronSummaryIconClass = 'text-green-500';
                $cronSummaryLabel = 'Cron jobs installed via cPanel UAPI';
                if ($cronMode === 'crontab') {
                    $cronSummaryLabel = 'Cron jobs installed via local crontab CLI';
                } elseif ($cronMode === 'manual') {
                    $cronSummaryBoxClass = 'bg-amber-50 border-amber-200 text-amber-800';
                    $cronSummaryIconClass = 'text-amber-500';
                    $cronSummaryLabel = 'Cron jobs require manual setup in cPanel';
                } elseif ($cronMode === 'partial') {
                    $cronSummaryBoxClass = 'bg-amber-50 border-amber-200 text-amber-800';
                    $cronSummaryIconClass = 'text-amber-500';
                    $cronSummaryLabel = 'Cron jobs partially installed; finish the rest manually';
                }
?>
            <div x-data="{
                destroying: false,
                destroyed: false,
                destroyMsg: '',

                async selfDestruct() {
                    if (!confirm('Are you sure you want to delete install.php? This action cannot be undone.')) return;
                    this.destroying = true;
                    try {
                        const fd = new FormData();
                        fd.append('_ajax', '1');
                        fd.append('install_token', INSTALL_TOKEN);
                        fd.append('action', 'self_destruct');
                        const r = await fetch('install.php', { method: 'POST', body: fd });
                        const j = await r.json();
                        this.destroyMsg = j.msg;
                        this.destroyed = j.ok;
                    } catch(e) {
                        this.destroyMsg = 'Error: ' + e.message;
                    } finally {
                        this.destroying = false;
                    }
                }
            }">
                <!-- Summary -->
                <div class="space-y-3 mb-8">
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">File <code class="font-mono">.env</code> created successfully</span>
                    </div>
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">File <code class="font-mono">data/config.json</code> created successfully</span>
                    </div>
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">Database schema installed successfully</span>
                    </div>
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">
                            Admin user <code class="font-mono"><?= h(iv(4, 'ADMIN_USER', 'admin')) ?></code> created successfully
                        </span>
                    </div>
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">GeoLite2-Country.mmdb downloaded successfully</span>
                    </div>
                    <div class="flex items-center gap-3 p-3 border rounded-lg <?= h($cronSummaryBoxClass) ?>">
                        <svg class="w-5 h-5 flex-shrink-0 <?= h($cronSummaryIconClass) ?>" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm"><?= h($cronSummaryLabel) ?></span>
                    </div>
                    <div class="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                        <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span class="text-sm text-green-800">Health endpoint ready at <code class="font-mono">/metrics</code> and <code class="font-mono">/healthz</code></span>
                    </div>
                </div>

                <!-- Config recap -->
                <div class="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-6 text-sm">
                    <h3 class="font-semibold text-gray-700 mb-3">Configuration Summary</h3>
                    <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                        <dt class="text-gray-500">DB_HOST</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(2, 'DB_HOST', 'localhost')) ?></dd>
                        <dt class="text-gray-500">DB_NAME</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(2, 'DB_NAME')) ?></dd>
                        <dt class="text-gray-500">SERVER_IP</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(3, 'SERVER_IP')) ?></dd>
                        <dt class="text-gray-500">BASE_DIR</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(3, 'BASE_DIR')) ?></dd>
                        <dt class="text-gray-500">CPANEL_HOST</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(3, 'CPANEL_HOST')) ?></dd>
                        <dt class="text-gray-500">ADMIN_USER</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(4, 'ADMIN_USER', 'admin')) ?></dd>
                        <dt class="text-gray-500">POSTBACK_SECRET</dt>
                        <dd class="font-mono text-gray-800"><?= iv(4, 'POSTBACK_SECRET') !== '' ? '••••••••' : '(disabled)' ?></dd>
                        <dt class="text-gray-500">METRICS_TOKEN</dt>
                        <dd class="font-mono text-gray-800"><?= iv(4, 'METRICS_TOKEN') !== '' ? '••••••••' : '(disabled)' ?></dd>
                        <dt class="text-gray-500">METRICS_URL</dt>
                        <dd class="font-mono text-gray-800">/metrics</dd>
                        <dt class="text-gray-500">CF_ACCOUNT_ID</dt>
                        <dd class="font-mono text-gray-800"><?= h(iv(5, 'CF_ACCOUNT_ID')) ?: '(not set)' ?></dd>
                    </dl>
                </div>

                <!-- Security warning -->
                <div class="bg-yellow-50 border border-yellow-300 rounded-lg px-4 py-3 mb-6">
                    <div class="flex gap-2">
                        <svg class="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <div class="text-sm text-yellow-800">
                            <p class="font-semibold">Security Notice</p>
                            <p class="mt-1">Delete <code class="font-mono">install.php</code> after installation is complete to prevent unauthorized access.</p>
                        </div>
                    </div>
                </div>

                <div class="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 mb-6">
                    <div class="flex gap-2">
                        <svg class="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div class="text-sm text-blue-900">
                            <p class="font-semibold">Cron Jobs</p>
                            <p class="mt-1"><?= h($cronMessage) ?></p>
                            <?php if ($cronCommands !== '') : ?>
                                <pre class="mt-3 bg-white/70 border border-blue-200 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all text-xs font-mono"><?= h($cronCommands) ?></pre>
                            <?php endif; ?>
                            <p class="mt-3">Verify them at <strong>cPanel &rarr; Cron Jobs</strong>. Existing MySQL installs can be normalized with <code class="font-mono">php ops/ensure_mysql_hot_indexes.php --json</code>. Health checks are available at <code class="font-mono">/metrics</code> and <code class="font-mono">/healthz</code>.</p>
                        </div>
                    </div>
                </div>

                <div class="bg-gray-50 border border-gray-200 rounded-lg px-4 py-3 mb-6">
                    <div class="flex gap-2">
                        <svg class="w-5 h-5 text-gray-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div class="text-sm text-gray-700">
                            <p class="font-semibold">Smoke Verification</p>
                            <p class="mt-1">After DNS and database are live, run <code class="font-mono">php ops/smoke_production.php --base-url=https://your-domain.tld --slug=your-slug --metrics-token=&lt;token&gt; --json</code> from the deployed app root.</p>
                        </div>
                    </div>
                </div>

                <!-- Destruct message -->
                <div x-show="destroyMsg !== ''" class="mb-4 px-4 py-3 rounded-lg border text-sm"
                     :class="destroyed ? 'bg-green-50 border-green-300 text-green-800' : 'bg-red-50 border-red-300 text-red-800'"
                     x-text="destroyMsg" x-cloak></div>

                <div class="flex items-center gap-3 flex-wrap">
                    <!-- Self-destruct -->
                    <button x-show="!destroyed" @click="selfDestruct()" :disabled="destroying"
                            class="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-sm font-medium transition disabled:opacity-50">
                        <span x-show="destroying" class="spinner" style="border-color:rgba(255,255,255,.4);border-top-color:#fff;"></span>
                        <svg x-show="!destroying" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                        </svg>
                        <span x-text="destroying ? 'Deleting...' : 'Delete install.php'"></span>
                    </button>

                    <!-- Go to dashboard -->
                    <a href="/"
                       class="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
                        </svg>
                        Open Dashboard
                    </a>
                </div>
            </div>

            <?php endif; ?>

        </div><!-- /card -->
    </div><!-- /container -->

    <div class="max-w-3xl mx-auto px-4 py-4 text-center text-xs text-gray-400">
        Installer &mdash; PHP <?= h(PHP_VERSION) ?>
    </div>

</body>
</html>
