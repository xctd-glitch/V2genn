<?php

declare(strict_types=1);

/**
 * handler.php - Backend API Handler
 * cPanel UAPI + Cloudflare DNS Manager
 */

require_once __DIR__ . '/../bootstrap/security_bootstrap.php';
require_once __DIR__ . '/../bootstrap/host_utils.php';

tp_secure_session_bootstrap();
session_start();
tp_send_security_headers();

header('Content-Type: application/json');

// Accept POST only
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['success' => false, 'message' => 'Method not allowed']));
}

// Limit input size (max 256 KB)
// Read 1 byte beyond the limit to detect payloads exceeding the limit
$rawInput = file_get_contents('php://input', false, null, 0, 262145);
if ($rawInput === false || strlen($rawInput) > 262144) {
    http_response_code(413);
    exit(json_encode(['success' => false, 'message' => 'Request too large']));
}

// Parse JSON input
$input = json_decode($rawInput, true);
if (!is_array($input)) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Invalid request']));
}

$action = is_string($input['action'] ?? null) ? trim($input['action']) : '';
$config = is_array($input['config'] ?? null) ? $input['config'] : [];
$data   = is_array($input['data'] ?? null) ? $input['data'] : [];

// Preserve a verbatim copy of the submitted config BEFORE any env/admin
// merge or '****' conversion. save_config uses this to write exactly
// what the UI sent, without stale env values silently clobbering the
// new input.
$rawRequestConfig = $config;

foreach (['cpanel_token', 'cf_token'] as $secretKey) {
    if (($config[$secretKey] ?? null) === '****') {
        $config[$secretKey] = '';
    }
}

$userAllowedActions = ['add_domain', 'delete_domain', 'sync_cloudflare'];
$hasAdminSession = !empty($_SESSION['dashboard_auth']);
$hasUserSession = !empty($_SESSION['sl_uid']);
$isUserAction = in_array($action, $userAllowedActions, true);
$hasSessionAuth = $hasAdminSession || ($hasUserSession && $isUserAction);

$appToken = getenv('APP_TOKEN') ?: '';
$reqToken = is_string($input['token'] ?? null)
    ? trim($input['token'])
    : (is_string($input['app_token'] ?? null) ? trim($input['app_token']) : '');
$hasValidAppToken = $appToken !== '' && $reqToken !== '' && hash_equals($appToken, $reqToken);

if ($hasSessionAuth) {
    if (!tp_is_valid_csrf_token(is_string($input['csrf_token'] ?? null) ? $input['csrf_token'] : null)) {
        http_response_code(403);
        exit(json_encode(['success' => false, 'message' => 'Invalid CSRF token']));
    }
} elseif ($appToken !== '') {
    if (!$hasValidAppToken) {
        http_response_code(403);
        exit(json_encode(['success' => false, 'message' => 'Access denied']));
    }
} else {
    http_response_code(401);
    exit(json_encode(['success' => false, 'message' => 'Unauthorized']));
}

// ── Load .env file into getenv() ──
tp_load_env_file(__DIR__ . '/../.env');

// ── cPanel config from environment variables (override UI config) ──
/** @return array<string, string|int> */
function getCpanelEnvConfig(): array
{
    $env = [];
    if ($v = getenv('CPANEL_HOST')) {
        $env['cpanel_host']   = trim($v);
    }
    if ($v = getenv('CPANEL_PORT')) {
        $env['cpanel_port']   = intval($v);
    }
    if ($v = getenv('CPANEL_USER')) {
        $env['cpanel_user']   = trim($v);
    }
    if ($v = getenv('CPANEL_TOKEN')) {
        $env['cpanel_token']  = trim($v);
    }
    if ($v = getenv('CPANEL_DOMAIN')) {
        $normalizedDomain = tp_normalize_host_value((string) $v);
        if ($normalizedDomain !== '') {
            $env['cpanel_domain'] = $normalizedDomain;
        }
    }
    if ($v = getenv('SERVER_IP')) {
        $env['server_ip']    = trim($v);
    }
    if ($v = getenv('BASE_DIR')) {
        $env['base_dir']     = trim($v);
    }
    if ($v = getenv('WILDCARD_DIR')) {
        $env['wildcard_dir'] = trim($v);
    }
    return $env;
}
/** @return array<string, string> */
function getCloudflareEnvConfig(): array
{
    $env = [];
    if ($v = getenv('CF_TOKEN')) {
        $env['cf_token'] = trim($v);
    }
    if ($v = getenv('CF_ACCOUNT_ID')) {
        $env['cf_account_id'] = trim($v);
    }
    if ($v = getenv('CF_ZONE_ID')) {
        $env['cf_zone_id'] = trim($v);
    }
    if (($v = getenv('CF_PROXIED')) !== false) {
        $value = trim((string) $v);
        if ($value !== '') {
            $env['cf_proxied'] = $value === 'false' ? 'false' : 'true';
        }
    }
    return $env;
}

// Back-compat wrapper — delegates to the shared helper in runtime_compat.php.
/** @param array<string, string> $newValues */
function updateEnvConfigValues(string $envFile, array $newValues): bool
{
    return tp_env_file_set($envFile, $newValues);
}

function loadRedirectDecisionBootstrap(): void
{
    require_once __DIR__ . '/../src/RedirectDecision/bootstrap.php';
}

/**
 * @return array{
 *     geolite2: array{active: bool},
 *     iptoasn: array{configured: bool, active: bool},
 *     persistent_cache: array{backend: string}
 * }
 */
function redirectDecisionProviderState(): array
{
    $geoLitePath = trim((string) getenv('GEOLITE2_COUNTRY_DB'));
    if ($geoLitePath === '') {
        $geoLitePath = __DIR__ . '/../data/geoip/GeoLite2-Country.mmdb';
    }

    $iptoAsnEndpoint = trim((string) getenv('IPTOASN_ENDPOINT'));
    $conn = dbConnect();
    $cacheBackend = 'sqlite_local';
    if ($conn instanceof PDO) {
        try {
            $driver = strtolower((string) $conn->getAttribute(PDO::ATTR_DRIVER_NAME));
            $cacheBackend = $driver === 'mysql' ? 'shared_db' : 'sqlite_local';
        } catch (Throwable $e) {
            $cacheBackend = 'sqlite_local';
        }
    }

    return [
        'geolite2' => [
            'active' => is_file($geoLitePath) && class_exists('MaxMind\\Db\\Reader'),
        ],
        'iptoasn' => [
            'configured' => $iptoAsnEndpoint !== '',
            'active' => $iptoAsnEndpoint !== '' && function_exists('curl_init'),
        ],
        'persistent_cache' => [
            'backend' => $cacheBackend,
        ],
    ];
}

/**
 * @return array{
 *     current_hour_count: int,
 *     previous_hour_count: int,
 *     healthy: bool,
 *     alerts: list<array{severity: string, code: string, message: string}>,
 *     redirect_decision_errors: int
 * }
 */
function redirectDecisionHealthSummary(): array
{
    loadRedirectDecisionBootstrap();

    $currentHourCount = 0;
    $previousHourCount = 0;
    $conn = dbConnect();
    if ($conn instanceof PDO) {
        try {
            $repository = new App\RedirectDecision\Audit\PdoDecisionAuditRepository($conn);
            $currentHourStart = (int) floor(time() / 3600) * 3600;
            $previousHourStart = $currentHourStart - 3600;
            $currentHourCount = $repository->fetchTotalCountBetween($currentHourStart, $currentHourStart + 3600);
            $previousHourCount = $repository->fetchTotalCountBetween($previousHourStart, $currentHourStart);
        } catch (Throwable $e) {
            $currentHourCount = 0;
            $previousHourCount = 0;
        }
    }

    $health = App\RedirectDecision\Health\RedirectDecisionHealthEvaluator::evaluate(
        redirectDecisionProviderState(),
        $currentHourCount,
        $previousHourCount
    );

    $redirectDecisionErrors = 0;
    if (function_exists('tp_apcu_fetch')) {
        $raw = tp_apcu_fetch('redirect_decision_errors');
        if (is_int($raw)) {
            $redirectDecisionErrors = $raw;
        }
    }

    return [
        'current_hour_count' => (int) ($health['current_hour_count'] ?? $currentHourCount),
        'previous_hour_count' => (int) ($health['previous_hour_count'] ?? $previousHourCount),
        'healthy' => !empty($health['healthy']),
        'alerts' => is_array($health['alerts'] ?? null) ? $health['alerts'] : [],
        'redirect_decision_errors' => $redirectDecisionErrors,
    ];
}

/**
 * @param array<string, mixed> $config
 * @return array{
 *     config: array<string, mixed>,
 *     window: array<string, mixed>,
 *     health: array{
 *         current_hour_count: int,
 *         previous_hour_count: int,
 *         healthy: bool,
 *         alerts: list<array{severity: string, code: string, message: string}>,
 *         redirect_decision_errors: int
 *     }
 * }
 */
function redirectDecisionPayload(array $config): array
{
    loadRedirectDecisionBootstrap();

    // Expose the admin-wide filter_redirect_url from data/config.json.
    // This takes priority over config['redirect_url'] in go.php, so the UI
    // must show it to avoid the operator being confused why the engine's
    // redirect_url field appears to have no effect.
    $adminCfgPath = __DIR__ . '/../data/config.json';
    $globalFilterUrl = '';
    if (is_file($adminCfgPath)) {
        $adminCfg = json_decode((string) @file_get_contents($adminCfgPath), true);
        if (is_array($adminCfg)) {
            $globalFilterUrl = trim((string) ($adminCfg['filter_redirect_url'] ?? ''));
        }
    }

    return [
        'config' => $config,
        'window' => RedirectDecision::currentWindow($config),
        'health' => redirectDecisionHealthSummary(),
        'global_filter_redirect_url' => $globalFilterUrl,
    ];
}

function touchDashboardVersion(): void
{
    if (function_exists('tp_apcu_store')) {
        tp_apcu_store('tp_dashboard_version', time());
    }
}

$adminConfigFile = __DIR__ . '/../data/config.json';
$adminStoredConfig = [];
if (file_exists($adminConfigFile)) {
    $adminStoredConfig = json_decode(file_get_contents($adminConfigFile), true) ?? [];
}

$config = array_merge($config, getCpanelEnvConfig());
$config = array_merge($config, getCloudflareEnvConfig());
if (isset($config['cpanel_domain'])) {
    $config['cpanel_domain'] = tp_normalize_host_value((string) $config['cpanel_domain']);
}

if (empty(trim((string) ($config['cpanel_token'] ?? ''))) && !empty($adminStoredConfig['cpanel_token'])) {
    $config['cpanel_token'] = trim((string) $adminStoredConfig['cpanel_token']);
}

// ── CF config fallback: if request does not include cf_token, use
//    (1) admin config.json, then (2) the admin user's DB row. ──
if (empty(trim($config['cf_token'] ?? ''))) {
    foreach (['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'] as $k) {
        if (!empty($adminStoredConfig[$k]) && empty($config[$k])) {
            $config[$k] = $adminStoredConfig[$k];
        }
    }
    // DB fallback — pulls cf_* from the admin's app_users row.
    if (empty(trim($config['cf_token'] ?? ''))) {
        $adminDbCf = fetchAdminCfConfig();
        foreach (['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'] as $k) {
            if (!empty($adminDbCf[$k]) && empty($config[$k])) {
                $config[$k] = $adminDbCf[$k];
            }
        }
    }
}

// ── Database helper ──────────────────────────────────────────
function dbConnect(): ?PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $pdo = tp_pdo_connect(false);
    return $pdo;
}

// ── Ensure addondomain table + domain_id column ──────────────
function ensureAddondomainTable(PDO $conn): void
{
    $isSqlite = $conn->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    if ($isSqlite) {
        $conn->exec("CREATE TABLE IF NOT EXISTS addondomain (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sub_domain TEXT DEFAULT '',
            domain_id  TEXT DEFAULT '',
            domain    TEXT NOT NULL UNIQUE,
            created_at TEXT DEFAULT (datetime('now'))
        )");
        try {
            $conn->exec("ALTER TABLE addondomain ADD COLUMN domain_id TEXT DEFAULT ''");
        } catch (PDOException $e) {
        }
    } else {
        $conn->exec("CREATE TABLE IF NOT EXISTS addondomain (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            sub_domain VARCHAR(50)  DEFAULT '',
            domain_id  VARCHAR(100) DEFAULT '',
            domain    VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try {
            $conn->exec("ALTER TABLE addondomain ADD COLUMN domain_id VARCHAR(100) DEFAULT '' AFTER sub_domain");
        } catch (PDOException $e) {
        }
    }
}

// ── Shared users table (also used by sl.php) ─────────────────
function ensureAppUsersTable(PDO $conn): void
{
    $conn->exec("CREATE TABLE IF NOT EXISTS app_users (
        id            INT              NOT NULL AUTO_INCREMENT,
        username      VARCHAR(50)      NOT NULL,
        password_hash VARCHAR(255)     NOT NULL,
        domain        VARCHAR(255)     NOT NULL DEFAULT '',
        cf_token      VARCHAR(255)     NOT NULL DEFAULT '',
        cf_account_id VARCHAR(100)     NOT NULL DEFAULT '',
        cf_zone_id    VARCHAR(100)     NOT NULL DEFAULT '',
        cf_proxied    VARCHAR(10)      NOT NULL DEFAULT 'true',
        created_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function syncAppUser(string $username, string $password): void
{
    $conn = dbConnect();
    if (!$conn) {
        return;
    }
    ensureAppUsersTable($conn);
    $hash = password_hash($password, PASSWORD_BCRYPT);
    try {
        $conn->prepare('INSERT INTO app_users (username, password_hash) VALUES (?,?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)')
             ->execute([$username, $hash]);
    } catch (PDOException $e) {
    }
}

function removeAppUser(string $username): void
{
    $conn = dbConnect();
    if (!$conn) {
        return;
    }
    try {
        $conn->prepare('DELETE FROM app_users WHERE username = ?')->execute([$username]);
    } catch (PDOException $e) {
    }
}

// ── Admin ↔ DB CF config sync ────────────────────────────────
// The admin is identified by the ADMIN_USER env var and is just a
// regular row in app_users. Keep its cf_* columns in sync with
// whatever the admin UI saves, so that when the admin logs into
// sl.php as a normal user they see the same CF config.

function adminDbUsername(): string
{
    $fromEnv = trim((string) getenv('ADMIN_USER'));
    return $fromEnv !== '' ? $fromEnv : '';
}

/** @return array<string, string> */
function fetchAdminCfConfig(): array
{
    $username = adminDbUsername();
    if ($username === '') {
        return [];
    }
    $conn = dbConnect();
    if (!$conn) {
        return [];
    }
    try {
        $stmt = $conn->prepare('SELECT cf_token, cf_account_id, cf_zone_id, cf_proxied FROM app_users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $row = $stmt->fetch();
    } catch (PDOException $e) {
        return [];
    }
    if (!is_array($row)) {
        return [];
    }
    $out = [];
    foreach (['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'] as $k) {
        $v = trim((string) ($row[$k] ?? ''));
        if ($v !== '') {
            $out[$k] = $v;
        }
    }
    return $out;
}

/** @param array<string, string> $cfFields */
function syncAdminCfToAppUsers(array $cfFields): bool
{
    $username = adminDbUsername();
    if ($username === '') {
        return false; // no ADMIN_USER env → skip silently
    }
    $conn = dbConnect();
    if (!$conn) {
        return false;
    }

    // Make sure the table has the cf_* columns. Production DB already
    // has them (see data/install.sql). Dev/local SQLite may be on the
    // older minimal schema from ensureAppUsersTable() — best-effort
    // ALTER so the UPDATE below doesn't blow up.
    try {
        ensureAppUsersTable($conn);
        $isSqlite = $conn->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
        foreach (['cf_token' => 'TEXT', 'cf_account_id' => 'TEXT', 'cf_zone_id' => 'TEXT', 'cf_proxied' => 'TEXT'] as $col => $sqliteType) {
            try {
                if ($isSqlite) {
                    $conn->exec("ALTER TABLE app_users ADD COLUMN {$col} {$sqliteType} DEFAULT ''");
                } else {
                    $conn->exec("ALTER TABLE app_users ADD COLUMN {$col} VARCHAR(255) NOT NULL DEFAULT ''");
                }
            } catch (PDOException $e) {
                // Column already exists — ignore.
            }
        }
    } catch (PDOException $e) {
        return false;
    }

    try {
        // Fetch the current row so we can preserve the stored cf_token
        // when the incoming value is the '****' placeholder or empty.
        $existingStmt = $conn->prepare(
            'SELECT cf_token FROM app_users WHERE username = ? LIMIT 1'
        );
        $existingStmt->execute([$username]);
        $existingRow = $existingStmt->fetch();
        if (!$existingRow) {
            return false; // admin row not set up yet — nothing to sync
        }
        $existingToken = trim((string) ($existingRow['cf_token'] ?? ''));

        // Normalize incoming values.
        $incomingToken     = trim((string) ($cfFields['cf_token']      ?? ''));
        $incomingAccountId = trim((string) ($cfFields['cf_account_id'] ?? ''));
        $incomingZoneId    = trim((string) ($cfFields['cf_zone_id']    ?? ''));
        $incomingProxied   = trim((string) ($cfFields['cf_proxied']    ?? 'true'));

        // '****' is the legacy masked placeholder — never overwrite
        // the real token with it. Empty string also means "unchanged".
        $finalToken = ($incomingToken === '' || $incomingToken === '****')
            ? $existingToken
            : $incomingToken;

        $stmt = $conn->prepare(
            'UPDATE app_users
                SET cf_token      = ?,
                    cf_account_id = ?,
                    cf_zone_id    = ?,
                    cf_proxied    = ?
              WHERE username = ?'
        );
        $stmt->execute([
            $finalToken,
            $incomingAccountId,
            $incomingZoneId,
            $incomingProxied !== '' ? $incomingProxied : 'true',
            $username,
        ]);
        // rowCount() can be 0 when values didn't change — treat a
        // clean execute() with no exception as success.
        return true;
    } catch (PDOException $e) {
        return false;
    }
}

// ── Get registrable domain (last 2 labels: example.com from sub.example.com) ──
function getRegistrableDomain(string $domain): string
{
    $parts = explode('.', strtolower($domain));
    return implode('.', array_slice($parts, -2));
}

// ── Fetch all CF zones → map zone_name to status ('active'|'pending'|...) ──
/**
 * @param array<string, mixed> $cfg
 * @return array<string, string>
 */
function buildCfZoneMap(array $cfg): array
{
    $res = cfRequest($cfg, 'zones?per_page=1000');
    if (empty($res['body']['success'])) {
        return [];
    }
    $map = [];
    foreach ($res['body']['result'] ?? [] as $z) {
        $map[strtolower($z['name'])] = $z['status'] ?? 'unknown';
    }
    return $map;
}

// ── Convert CF zone status to cf_status value ──
function cfZoneToStatus(string $zoneStatus): string
{
    return $zoneStatus === 'active' ? 'active' : 'pending';
}

// ── Resolve the cPanel server's nameservers. ───────────────────
//
// Returns a structured result:
//   ['nameservers' => string[], 'source' => string, 'method' => string]
//
// source values:
//   'config'    — admin config override
//   'env'       — CPANEL_NAMESERVERS env var
//   'dns-main'  — public NS lookup of cPanel main domain
//   'dns-host'  — public NS lookup of cpanel_host's registrable root
//   'guess'     — heuristic ns1/ns2.<main> verified via A-record
//   'none'      — nothing detected
//
// Priority:
//   1. $config['cpanel_nameservers']   (manual override, comma-separated)
//   2. getenv('CPANEL_NAMESERVERS')
//   3. dns_get_record($cpanelMainDomain, DNS_NS)
//   4. dns_get_record(parent of cpanel_host, DNS_NS)
//   5. Heuristic: ns1.<main>, ns2.<main> verified via DNS A-record
//
// All returned hostnames are lowercased with no trailing dot.
/**
 * @param array<string, mixed> $config
 * @return array<string, mixed>
 */
function resolveCpanelNameservers(array $config, string $cpanelMainDomain = ''): array
{
    $normalize = static function ($list): array {
        if (!is_array($list)) {
            $list = preg_split('/[\s,;]+/', (string) $list) ?: [];
        }
        $out = [];
        foreach ($list as $ns) {
            $ns = strtolower(trim((string) $ns, " \t\n\r\0\x0B."));
            if ($ns !== '' && preg_match('/^[a-z0-9.\-]+$/', $ns)) {
                $out[$ns] = true;
            }
        }
        return array_keys($out);
    };

    $lookupNs = static function (string $domain) use ($normalize): array {
        if ($domain === '' || !function_exists('dns_get_record')) {
            return [];
        }
        try {
            $records = @dns_get_record($domain, DNS_NS);
            if (is_array($records) && !empty($records)) {
                $targets = [];
                foreach ($records as $rec) {
                    if (isset($rec['target']) && $rec['target'] !== '') {
                        $targets[] = $rec['target'];
                    }
                }
                return $normalize($targets);
            }
        } catch (Throwable $e) {
            // Silent — fall through.
        }
        return [];
    };

    $result = static function (array $ns, string $source, string $method): array {
        return ['nameservers' => $ns, 'source' => $source, 'method' => $method];
    };

    // 1. Admin config override
    if (!empty($config['cpanel_nameservers'])) {
        $manual = $normalize($config['cpanel_nameservers']);
        if (!empty($manual)) {
            return $result($manual, 'config', 'Admin config override');
        }
    }

    // 2. Environment variable override
    $envNs = trim((string) getenv('CPANEL_NAMESERVERS'));
    if ($envNs !== '') {
        $fromEnv = $normalize($envNs);
        if (!empty($fromEnv)) {
            return $result($fromEnv, 'env', 'Env CPANEL_NAMESERVERS');
        }
    }

    // 3. Public DNS NS lookup of cPanel main domain.
    //    Catches whatever NS records the server's own zone publishes.
    $cpanelMainDomain = strtolower(trim($cpanelMainDomain, " \t\n\r\0\x0B."));
    if ($cpanelMainDomain !== '') {
        $fromMain = $lookupNs($cpanelMainDomain);
        if (!empty($fromMain)) {
            return $result($fromMain, 'dns-main', "DNS NS lookup of {$cpanelMainDomain}");
        }
    }

    // 4. Public DNS NS lookup of cpanel_host's registrable parent.
    //    (e.g. server23.provider.com → provider.com)
    $cpHost = strtolower(trim((string) ($config['cpanel_host'] ?? '')));
    if ($cpHost !== '') {
        $cpHostRoot = getRegistrableDomain($cpHost);
        if ($cpHostRoot !== '' && $cpHostRoot !== $cpanelMainDomain) {
            $fromHost = $lookupNs($cpHostRoot);
            if (!empty($fromHost)) {
                return $result($fromHost, 'dns-host', "DNS NS lookup of {$cpHostRoot}");
            }
        }
    }

    // 5. Heuristic: ns1.<main>, ns2.<main> verified via A-record lookup.
    //    Many shared-hosting setups follow this convention. The A-record
    //    check prevents returning bogus values on servers that don't.
    if ($cpanelMainDomain !== '' && function_exists('dns_get_record')) {
        $guesses  = ["ns1.{$cpanelMainDomain}", "ns2.{$cpanelMainDomain}"];
        $verified = [];
        foreach ($guesses as $ns) {
            try {
                $aRecs = @dns_get_record($ns, DNS_A);
                if (is_array($aRecs) && !empty($aRecs)) {
                    $verified[] = $ns;
                }
            } catch (Throwable $e) {
                // Silent
            }
        }
        $verified = $normalize($verified);
        if (count($verified) >= 1) {
            return $result($verified, 'guess', "Heuristic ns1/ns2.{$cpanelMainDomain} (A-record verified)");
        }
    }

    return $result([], 'none', '');
}

// ── Extract error message from CF API response ──
/** @param array<string, mixed> $res */
function cfErrMsg(array $res, string $fallback = 'Unknown error'): string
{
    return ($res['body']['errors'][0]['message'] ?? null)
        ?? ($res['body']['errors'][0]['code']    ?? null)
        ?? ($res['error']                        ?? ('HTTP ' . ($res['code'] ?? '?')))
        ?: $fallback;
}

// ── Classify a CF API response as permission-denied / plan-limited ──
// Used so applyCfSecuritySpeed() can downgrade such results to a clean
// "Skipped" info line instead of noisy "Authentication error" warnings.
/** @param array<string, mixed> $res */
function cfIsPermissionDenied(array $res): bool
{
    $httpCode = (int) ($res['code'] ?? 0);
    if ($httpCode === 401 || $httpCode === 403) {
        return true;
    }
    // 404 on a CF zone sub-resource means the endpoint is not available for this plan
    // (e.g. page_shield/settings on free/pro, bot_management on free).
    if ($httpCode === 404) {
        return true;
    }

    $cfCode = (int) ($res['body']['errors'][0]['code'] ?? 0);
    // Well-known CF error codes that indicate missing scope / plan / entitlement.
    $deniedCodes = [
        10000, // Authentication error
        10001, // Method not allowed for this token
        9103,  // Unknown X-Auth-Key or X-Auth-Email
        9106,  // Missing X-Auth-* / insufficient auth
        9109,  // Unauthorized to access requested resource
        6003,  // Invalid request headers
        7003,  // Could not route to /zones/.../xxx, invalid identifier (endpoint disabled for plan)
        7000,  // No route for that URI
        1200,  // feature not enabled / not entitled
        1015,  // You are being rate limited / forbidden
    ];
    if ($cfCode !== 0 && in_array($cfCode, $deniedCodes, true)) {
        return true;
    }

    $msg = strtolower((string) cfErrMsg($res, ''));
    if ($msg === '') {
        return false;
    }
    $needles = [
        'authentication error',
        'unauthorized',
        'not authorized',
        'permission',
        'forbidden',
        'not entitled',
        'not available on your plan',
        'upgrade required',
        'not enabled',
        'not allowed',
        'perhaps your object identifier is invalid',
        'could not route',
        'unrecognized zone setting name',
        'unknown setting',
    ];
    foreach ($needles as $needle) {
        if (strpos($msg, $needle) !== false) {
            return true;
        }
    }
    return false;
}

// ── Extract error message from cPanel API response ──
/** @param array<string, mixed> $res */
function cpanelErrStr(array $res): string
{
    if (!empty($res['body']['errors'])) {
        return implode('; ', (array)$res['body']['errors']);
    }
    return $res['body']['error'] ?? $res['error'] ?? 'Unknown';
}

// ── Is Cloudflare configured? ──
// Returns true only when cf_token is present and non-empty.
// All other CF fields (account_id, zone_id, proxied) are optional.
/** @param array<string, mixed> $config */
function isCloudflareConfigured(array $config): bool
{
    return trim((string) ($config['cf_token'] ?? '')) !== '';
}

// Look up a UserManager sub-account by username and return its
// real domain + guid as cPanel reports them.
// Returns ['ok'=>true,'domain'=>..,'guid'=>..,'full_username'=>..] on hit,
// or ['ok'=>false,'message'=>..] on miss / API error.
/**
 * @param array<string, mixed> $config
 * @return array<string, mixed>
 */
function lookupCpanelSubaccount(array $config, string $username): array
{
    $username = trim($username);
    if ($username === '') {
        return ['ok' => false, 'message' => 'Username is required'];
    }

    $res = cpanelRequest($config, 'UserManager', 'list_users');
    if (!$res['ok']) {
        return ['ok' => false, 'message' => 'cPanel connection failed: ' . ($res['error'] ?? 'Unknown')];
    }
    if (!($res['body']['status'] ?? false)) {
        return ['ok' => false, 'message' => cpanelErrStr($res) ?: 'Failed to fetch user list'];
    }

    foreach (($res['body']['data'] ?? []) as $u) {
        if (($u['username'] ?? '') !== $username) {
            continue;
        }
        $type = strtolower((string) ($u['type'] ?? 'sub'));
        if (in_array($type, ['cpanel'], true)) {
            continue; // never touch the main cPanel account
        }
        return [
            'ok'            => true,
            'domain'        => (string) ($u['domain']        ?? ''),
            'guid'          => (string) ($u['guid']          ?? ''),
            'full_username' => (string) ($u['full_username'] ?? ($username . '@' . ($u['domain'] ?? ''))),
            'type'          => $type,
        ];
    }

    return ['ok' => false, 'message' => "User '{$username}' not found in cPanel"];
}

/**
 * @param array<string, mixed> $config
 * @return array<string, mixed>
 */
function resolveCpanelUserDomain(array $config): array
{
    $configuredDomain = tp_normalize_host_value((string) ($config['cpanel_domain'] ?? ''));
    if ($configuredDomain !== '') {
        return ['ok' => true, 'domain' => $configuredDomain];
    }

    $mainDomainRes = cpanelRequest($config, 'DomainInfo', 'list_domains');
    if (!$mainDomainRes['ok']) {
        return ['ok' => false, 'message' => 'cPanel connection failed: ' . ($mainDomainRes['error'] ?? 'Unknown')];
    }
    if (($mainDomainRes['code'] ?? 0) === 401) {
        return ['ok' => false, 'message' => 'cPanel authentication failed'];
    }

    $mainDomain = tp_normalize_host_value((string) ($mainDomainRes['body']['data']['main_domain'] ?? ''));
    if ($mainDomain === '') {
        return ['ok' => false, 'message' => 'Failed to determine the cPanel account domain'];
    }

    return ['ok' => true, 'domain' => $mainDomain];
}

// ── Log addDnsRecord result to logs array ──
/**
 * @param array<string, mixed> $r
 * @param array<int, array<string, string>> $logs
 */
function logDnsResult(array $r, string $label, array &$logs, bool &$overallSuccess): void
{
    if (!$r['ok']) {
        $logs[]        = ['type' => 'error',   'message' => "{$label}: " . ($r['error'] ?? 'Unknown error')];
        $overallSuccess = false;
    } elseif ($r['skipped'] ?? false) {
        $logs[] = ['type' => 'warning', 'message' => "{$label}: " . $r['message']];
    } else {
        $logs[] = ['type' => 'success', 'message' => "{$label}: " . $r['message']];
    }
}

// ── Add wildcard record, keeping it proxied to avoid exposing origin IP ──
// Strategy:
//   1. Try proxied A *. → server_ip (works on Pro/Business/Enterprise)
//   2. If proxied A rejected (Free plan), fallback to CNAME *. → apex (still proxied)
//   3. Only as last resort create DNS-only A (this is what triggers CF's
//      "DNS-only records exposing IP addresses that are proxied" warning).
/**
 * @param array<string, mixed> $cfg
 * @param array<int, array<string, string>> $logs
 */
function addWildcardDnsRecord(array $cfg, string $zoneId, string $domain, string $serverIp, bool $proxied, bool $skipExisting, array &$logs, bool &$overallSuccess): void
{
    $r = addDnsRecord($cfg, $zoneId, 'A', '*.' . $domain, $serverIp, $proxied, $skipExisting);
    if ($r['ok']) {
        logDnsResult($r, 'A * (wildcard)', $logs, $overallSuccess);
        return;
    }

    if ($proxied) {
        $logs[] = ['type' => 'warning', 'message' => 'A *: proxied A rejected, fallback to proxied CNAME → ' . $domain];
        $r = addDnsRecord($cfg, $zoneId, 'CNAME', '*.' . $domain, $domain, true, $skipExisting);
        if ($r['ok']) {
            logDnsResult($r, 'CNAME * (wildcard, proxied)', $logs, $overallSuccess);
            return;
        }

        $logs[] = ['type' => 'warning', 'message' => 'CNAME * also rejected, last-resort DNS-only A (may expose origin IP — consider upgrading CF plan)'];
        $r = addDnsRecord($cfg, $zoneId, 'A', '*.' . $domain, $serverIp, false, $skipExisting);
    }

    logDnsResult($r, 'A * (wildcard)', $logs, $overallSuccess);
}

// ── Scan and auto-fix DNS-only A/AAAA/CNAME records that share origin with proxied ones ──
// Returns: ['fixed' => [...], 'unfixable' => [...], 'checked' => N]
/**
 * @param array<string, mixed> $cfg
 * @param array<int, array<string, string>> $logs
 * @return array<string, mixed>
 */
function auditAndFixProxyLeaks(array $cfg, string $zoneId, array &$logs): array
{
    $result = ['fixed' => [], 'unfixable' => [], 'checked' => 0];

    $listRes = cfRequest($cfg, "zones/{$zoneId}/dns_records?per_page=1000");
    if (!$listRes['ok'] || ($listRes['code'] ?? 0) !== 200) {
        $logs[] = ['type' => 'warning', 'message' => 'Proxy-leak audit skipped: could not list zone records'];
        return $result;
    }

    $records = $listRes['body']['result'] ?? [];
    if (!is_array($records)) {
        return $result;
    }

    // Build a set of origins (IPs / CNAME targets) that at least one proxied record uses
    $proxiedOrigins = [];
    foreach ($records as $rec) {
        if (!is_array($rec)) continue;
        if (!empty($rec['proxied']) && in_array($rec['type'] ?? '', ['A', 'AAAA', 'CNAME'], true)) {
            $proxiedOrigins[strtolower((string) ($rec['content'] ?? ''))] = true;
        }
    }

    if ($proxiedOrigins === []) {
        return $result;
    }

    foreach ($records as $rec) {
        if (!is_array($rec)) continue;
        $type = $rec['type'] ?? '';
        $content = strtolower((string) ($rec['content'] ?? ''));
        $name = (string) ($rec['name'] ?? '');
        $id = (string) ($rec['id'] ?? '');

        if ($id === '' || !in_array($type, ['A', 'AAAA', 'CNAME'], true)) continue;
        if (!empty($rec['proxied'])) continue;
        if (!isset($proxiedOrigins[$content])) continue;

        $result['checked']++;

        // Known cPanel records that MUST stay DNS-only for service login
        // (cpanel.*, webmail.*, mail.*, ftp.*, autodiscover.*, autoconfig.*)
        $leaf = strtolower(explode('.', $name)[0] ?? '');
        if (in_array($leaf, ['cpanel', 'webmail', 'whm', 'ftp', 'autodiscover', 'autoconfig'], true)) {
            $result['unfixable'][] = "{$type} {$name} (cPanel service record — kept DNS-only by design)";
            continue;
        }

        // Flip to proxied
        $patch = cfRequest($cfg, "zones/{$zoneId}/dns_records/{$id}", 'PATCH', ['proxied' => true]);
        if ($patch['ok'] && ($patch['code'] ?? 0) === 200 && ($patch['body']['success'] ?? false)) {
            $result['fixed'][] = "{$type} {$name} → proxied";
            $logs[] = ['type' => 'success', 'message' => "Audit: flipped {$type} {$name} to proxied (was exposing origin {$content})"];
        } else {
            $result['unfixable'][] = "{$type} {$name} (patch failed: " . cfErrMsg($patch, 'unknown') . ')';
        }
    }

    return $result;
}

// Validate action
$allowedActions = [
    'test_cpanel', 'test_cloudflare', 'save_config',
    'add_domain', 'list_domains', 'delete_domain', 'sync_cloudflare', 'refresh_cf_status',
    'create_cpanel_user', 'list_cpanel_users', 'reset_cpanel_password', 'delete_cpanel_user',
    'list_smartlinks', 'create_smartlink', 'update_smartlink', 'delete_smartlink',
    'list_global_domains', 'add_global_domain', 'delete_global_domain',
    'list_decision_audit', 'reset_decision_audit_errors', 'get_dashboard_version',
    'get_redirect_engine_config', 'save_redirect_engine_config', 'reset_redirect_engine_cycle',
    'preview_redirect_engine',
];
if (!in_array($action, $allowedActions, true)) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Unknown action']));
}

// ── APP_TOKEN is for non-session access only (automation/API) ──

// ── ACTION: Refresh CF Status (lightweight — only check CF zones, no cPanel hit) ──
if ($action === 'refresh_cf_status') {
    if (!isCloudflareConfigured($config)) {
        exit(json_encode(['success' => true, 'statuses' => [], 'unconfigured' => true]));
    }

    // Get domain IDs from request (only domains that need checking)
    $domains = $data['domains'] ?? [];  // array of {id, domain}
    if (empty($domains)) {
        exit(json_encode(['success' => true, 'statuses' => []]));
    }

    $cfZoneMap  = buildCfZoneMap($config);
    $statuses   = [];
    $dbConn     = dbConnect();
    foreach ($domains as $d) {
        $id         = intval($d['id'] ?? 0);
        $domainName = trim($d['domain'] ?? '');
        if (!$id || !$domainName) {
            continue;
        }
        $registrable   = getRegistrableDomain($domainName);
        $status        = isset($cfZoneMap[$registrable])
            ? cfZoneToStatus($cfZoneMap[$registrable])
            : 'not_found';
        $statuses[$id] = $status;
        if ($status === 'active' && ($d['sub_domain'] ?? '') !== 'GLOBAL') {
            // Newly active zone — apply Security & Speed settings
            $zoneRes = getZoneId($config, $domainName);
            if ($zoneRes['ok']) {
                $dummy = [];
                applyCfSecuritySpeed($config, $zoneRes['zone_id'], $dummy);
            }
            if ($dbConn) {
                try {
                    $dbConn->prepare("UPDATE addondomain SET sub_domain = 'GLOBAL' WHERE id = ? AND sub_domain != 'GLOBAL'")
                        ->execute([$id]);
                } catch (PDOException $e) { /* silent */
                }
            }
        }
    }

    exit(json_encode(['success' => true, 'statuses' => $statuses]));
}

// ── ACTION: List Domains ──────────────────────────────────────
if ($action === 'list_domains') {
    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'domains' => [], 'message' => 'DB not connected']));
    }
    ensureAddondomainTable($conn);
    try {
        $rows = $conn->query('SELECT id, sub_domain, domain_id, domain FROM addondomain ORDER BY id DESC')->fetchAll();
    } catch (PDOException $e) {
        exit(json_encode(['success' => false, 'domains' => [], 'message' => 'Query failed: ' . $e->getMessage()]));
    }

    // ── Cloudflare status per domain ──
    $cfEnabled = isCloudflareConfigured($config);
    if ($cfEnabled) {
        $cfZoneMap = buildCfZoneMap($config);
        foreach ($rows as &$row) {
            $registrable      = getRegistrableDomain($row['domain']);
            $cfStatus         = isset($cfZoneMap[$registrable])
                ? cfZoneToStatus($cfZoneMap[$registrable])
                : 'not_found';
            $row['cf_status'] = $cfStatus;
            if ($cfStatus === 'active' && $row['sub_domain'] !== 'GLOBAL') {
                try {
                    $conn->prepare("UPDATE addondomain SET sub_domain = 'GLOBAL' WHERE id = ?")
                        ->execute([$row['id']]);
                    $row['sub_domain'] = 'GLOBAL';
                } catch (PDOException $e) { /* silent */
                }
            }
        }
        unset($row);
    } else {
        foreach ($rows as &$row) {
            $row['cf_status'] = 'unconfigured';
        }
        unset($row);
    }

    exit(json_encode(['success' => true, 'domains' => $rows, 'cf_configured' => $cfEnabled]));
}

// ── ACTION: Delete Domain ─────────────────────────────────────
if ($action === 'delete_domain') {
    $id     = intval($data['id'] ?? 0);
    $domain = trim($data['domain'] ?? '');
    $logs   = [];

    if ($id > 0 && $domain === '') {
        $conn = dbConnect();
        if ($conn) {
            ensureAddondomainTable($conn);
            try {
                $stmt = $conn->prepare('SELECT domain FROM addondomain WHERE id = ? LIMIT 1');
                $stmt->execute([$id]);
                $row = $stmt->fetch();
                if (is_array($row) && is_string($row['domain'] ?? null)) {
                    $domain = trim((string) $row['domain']);
                }
            } catch (PDOException $e) {
            }
        }
    }

    if (!$id || !$domain) {
        exit(json_encode(['success' => false, 'message' => 'Incomplete data']));
    }

    $hasError   = false;
    $isNotFound = function (string $err): bool {
        return stripos($err, 'does not exist') !== false
            || stripos($err, 'not found')      !== false
            || stripos($err, 'invalid')        !== false
            || stripos($err, 'does not belong') !== false;
    };

    $deleteWildcardSubdomain = function () use ($config, $domain): array {
        return cpanelApi2Request($config, 'SubDomain', 'delsubdomain', ['domain' => "*.{$domain}"]);
    };

    // ---- Step 1a: Delete wildcard *.domain.com first (required before unpark) ----
    // This shared-host cPanel supports API2 delsubdomain here; the UAPI delete_subdomain
    // call is not available and causes the wildcard delete step to be skipped.
    $delWcRes = $deleteWildcardSubdomain();
    if (($delWcRes['body']['status'] ?? 0) == 1) {
        $logs[] = ['type' => 'success', 'message' => "cPanel: Wildcard *.{$domain} deleted"];
    } else {
        $delWcErr = cpanelErrStr($delWcRes);
        if ($isNotFound($delWcErr)) {
            $logs[] = ['type' => 'info', 'message' => "cPanel: Wildcard *.{$domain} not found, skipped"];
        } else {
            $logs[]   = ['type' => 'warning', 'message' => "cPanel Wildcard: {$delWcErr} — continuing unpark..."];
            // Do not set $hasError so unpark is still attempted
        }
    }

    // ---- Step 1b: Unpark domain.com (after wildcard deleted) ----
    $unparkRes = cpanelApi2Request($config, 'Park', 'unpark', ['domain' => $domain]);
    if (($unparkRes['body']['status'] ?? 0) == 1) {
        $logs[] = ['type' => 'success', 'message' => "cPanel: {$domain} removed (Parked Domain)"];
    } else {
        $unparkErr = cpanelErrStr($unparkRes);
        if ($isNotFound($unparkErr)) {
            $logs[] = ['type' => 'info', 'message' => "cPanel: {$domain} not found as parked domain, skipped"];
        } elseif (stripos($unparkErr, 'Before the system') !== false || stripos($unparkErr, 'subdomain') !== false) {
            // Subdomain still present — retry the supported wildcard delete API once.
            $logs[] = ['type' => 'warning', 'message' => "cPanel Park: Remaining subdomain found, retrying wildcard delete..."];
            $delWc2 = $deleteWildcardSubdomain();
            if (($delWc2['body']['status'] ?? 0) == 1) {
                $logs[] = ['type' => 'success', 'message' => "cPanel: Wildcard *.{$domain} deleted"];
                // Retry unpark
                $unparkRes2 = cpanelApi2Request($config, 'Park', 'unpark', ['domain' => $domain]);
                if (($unparkRes2['body']['status'] ?? 0) == 1) {
                    $logs[] = ['type' => 'success', 'message' => "cPanel: {$domain} removed (retry)"];
                } else {
                    $logs[]   = ['type' => 'error', 'message' => "cPanel Park (retry): " . cpanelErrStr($unparkRes2)];
                    $hasError = true;
                }
            } else {
                $logs[]   = ['type' => 'error', 'message' => "cPanel Park: {$unparkErr}"];
                $hasError = true;
            }
        } else {
            $logs[]   = ['type' => 'error', 'message' => "cPanel Park: {$unparkErr}"];
            $hasError = true;
        }
    }

    // ---- Step 2: Delete zone from Cloudflare ----
    if (isCloudflareConfigured($config)) {
        $zoneRes = getZoneId($config, $domain);
        if (!$zoneRes['ok']) {
            $logs[] = ['type' => 'info', 'message' => "CF: Zone {$domain} not found in Cloudflare, skipped"];
        } else {
            $delZoneRes = cfRequest($config, 'zones/' . $zoneRes['zone_id'], 'DELETE');
            if ($delZoneRes['ok'] && ($delZoneRes['code'] ?? 0) === 200 && !empty($delZoneRes['body']['success'])) {
                $logs[] = ['type' => 'success', 'message' => "CF: Zone {$domain} deleted from Cloudflare"];
            } else {
                $logs[]   = ['type' => 'error', 'message' => 'CF: Failed to delete zone — ' . cfErrMsg($delZoneRes)];
                $hasError = true;
            }
        }
    } else {
        $logs[] = ['type' => 'info', 'message' => 'CF: Token not configured, skipped'];
    }

    // ---- Step 3: Delete from DB ----
    $conn = dbConnect();
    if ($conn) {
        try {
            $stmt = $conn->prepare('DELETE FROM addondomain WHERE id = ?');
            $stmt->execute([$id]);
            $logs[] = ['type' => 'success', 'message' => "DB: Record {$domain} deleted"];
        } catch (PDOException $e) {
            $logs[]   = ['type' => 'error', 'message' => 'DB: ' . $e->getMessage()];
            $hasError = true;
        }
    } else {
        $logs[] = ['type' => 'info', 'message' => 'DB: Not configured, skipped'];
    }

    $msg = $hasError
        ? "Deletion of {$domain} completed with some errors"
        : "Domain {$domain} successfully removed from cPanel, Cloudflare, and database";

    if (!$hasError && function_exists('tp_apcu_store')) {
        tp_apcu_store('tp_dashboard_version', time());
    }
    exit(json_encode(['success' => !$hasError, 'message' => $msg, 'logs' => $logs]));
}

// ============================================================
// Helper: cURL request
// ============================================================
/**
 * @param array<int, string> $headers
 * @param array<string, mixed>|string|null $body
 * @return array<string, mixed>
 */
function curlRequest(string $url, string $method = 'GET', array $headers = [], $body = null, bool $sslVerify = false, int $timeout = 15): array
{
    $attempts = 3;
    $lastErr  = '';
    for ($i = 0; $i < $attempts; $i++) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_SSL_VERIFYPEER => $sslVerify,
            CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
            CURLOPT_HTTPHEADER     => $headers,
        ]);

        if ($body !== null) {
            if (is_array($body)) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($body));
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
        }

        $response  = curl_exec($ch);
        $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!$curlError) {
            $decoded = json_decode($response, true);
            return ['ok' => true, 'code' => $httpCode, 'body' => $decoded];
        }

        $lastErr = $curlError;
        // Retry only on transient DNS thread exhaustion
        if (stripos($curlError, 'getaddrinfo') === false || $i === $attempts - 1) {
            break;
        }
        sleep(3);
    }

    return ['ok' => false, 'code' => 0, 'body' => null, 'error' => $lastErr];
}

// ============================================================
// cPanel API2 helper (for modules not available in UAPI)
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @param array<string, mixed> $params
 * @return array<string, mixed>
 */
function cpanelApi2Request(array $cfg, string $module, string $func, array $params = []): array
{
    $host  = trim($cfg['cpanel_host'] ?? '');
    $port  = intval($cfg['cpanel_port'] ?? 2083);
    $user  = trim($cfg['cpanel_user'] ?? '');
    $token = trim($cfg['cpanel_token'] ?? '');

    if (!$host || !$user || !$token) {
        return ['ok' => false, 'error' => 'Incomplete cPanel credentials'];
    }

    $params = array_merge($params, [
        'cpanel_jsonapi_module'     => $module,
        'cpanel_jsonapi_func'       => $func,
        'cpanel_jsonapi_apiversion' => '2',
    ]);

    $url     = "https://{$host}:{$port}/json-api/cpanel?" . http_build_query($params);
    $headers = [
        "Authorization: cpanel {$user}:{$token}",
        'Content-Type: application/x-www-form-urlencoded',
    ];

    $res = ['ok' => false, 'error' => 'Not attempted'];
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $res = curlRequest($url, 'GET', $headers, null, false, 45);
        if (!$res['ok']) break; // cURL errors already retried inside curlRequest

        // Normalize to the same format as the UAPI response
        $rawBody = $res['body'] ?? [];
        $cpanel  = $rawBody['cpanelresult'] ?? [];
        $data    = $cpanel['data']  ?? null;
        $errMsg  = $cpanel['error'] ?? null;
        $status  = empty($errMsg) && !empty($data) ? 1 : 0;

        $res['body'] = [
            'status'   => $status,
            'data'     => $data,
            'errors'   => $errMsg ? [$errMsg] : [],
            'messages' => [],
        ];

        // Retry on transient cPanel DNS thread exhaustion (error is in body)
        if ($attempt < 2 && $status != 1 && stripos(cpanelErrStr($res), 'getaddrinfo') !== false) {
            sleep(3);
            continue;
        }
        break;
    }
    return $res;
}

// ============================================================
// cPanel UAPI helper
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @param array<string, mixed> $params
 * @return array<string, mixed>
 */
function cpanelRequest(array $cfg, string $module, string $func, array $params = []): array
{
    $host  = trim($cfg['cpanel_host'] ?? '');
    $port  = intval($cfg['cpanel_port'] ?? 2083);
    $user  = trim($cfg['cpanel_user'] ?? '');
    $token = trim($cfg['cpanel_token'] ?? '');

    if (!$host || !$user || !$token) {
        return ['ok' => false, 'error' => 'Incomplete cPanel credentials'];
    }

    // UAPI supports GET + query string for all functions — and some
    // endpoints (e.g. UserManager::delete_user) silently drop POST body
    // params, so use GET everywhere for consistency.
    $url = "https://{$host}:{$port}/execute/{$module}/{$func}";
    if (!empty($params)) {
        $url .= '?' . http_build_query($params);
    }

    $headers = [
        "Authorization: cpanel {$user}:{$token}",
    ];

    $res = ['ok' => false, 'error' => 'Not attempted'];
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $res = curlRequest($url, 'GET', $headers, null, false, 45);
        if (!$res['ok']) break; // cURL errors already retried inside curlRequest

        // Retry on transient cPanel DNS thread exhaustion (error is in body)
        if ($attempt < 2 && ($res['body']['status'] ?? 1) != 1
            && stripos(cpanelErrStr($res), 'getaddrinfo') !== false) {
            sleep(3);
            continue;
        }
        break;
    }
    return $res;
}

// ============================================================
// Cloudflare API helper
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @param array<string, mixed> $body
 * @return array<string, mixed>
 */
function cfRequest(array $cfg, string $path, string $method = 'GET', array $body = []): array
{
    $token = trim($cfg['cf_token'] ?? '');
    if (!$token) {
        return ['ok' => false, 'error' => 'Cloudflare token not set'];
    }

    $url     = 'https://api.cloudflare.com/client/v4/' . ltrim($path, '/');
    $headers = [
        "Authorization: Bearer {$token}",
        'Content-Type: application/json',
    ];

    $bodyStr = !empty($body) ? json_encode($body) : null;
    return curlRequest($url, $method, $headers, $bodyStr, true);
}

// ============================================================
// Get Cloudflare Zone ID (used for non-add operations, e.g. delete)
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function getZoneId(array $cfg, string $domain): array
{
    $registrable = getRegistrableDomain($domain);

    $res = cfRequest($cfg, 'zones?name=' . urlencode($registrable) . '&per_page=1');
    if (!$res['ok']) {
        return ['ok' => false, 'error' => $res['error'] ?? 'Failed to fetch zone'];
    }
    if (($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => 'HTTP ' . ($res['code'] ?? '?') . ' from Cloudflare'];
    }

    $zones = $res['body']['result'] ?? [];
    if (empty($zones)) {
        return ['ok' => false, 'error' => "Zone {$registrable} not found in Cloudflare"];
    }
    return ['ok' => true, 'zone_id' => $zones[0]['id']];
}

// ============================================================
// Get Cloudflare Account ID
// Priority: (1) explicit cf_account_id field → (2) from cf_zone_id → (3) GET /accounts
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function getCfAccountId(array $cfg): array
{
    // ── Method 1: from cf_account_id field set by user ──
    $explicit = trim($cfg['cf_account_id'] ?? '');
    if ($explicit) {
        return ['ok' => true, 'account_id' => $explicit];
    }

    // ── Method 2: get account.id from configured reference zone ──
    $existingZoneId = trim($cfg['cf_zone_id'] ?? '');
    if ($existingZoneId) {
        $res = cfRequest($cfg, "zones/{$existingZoneId}");
        if ($res['ok'] && ($res['code'] ?? 0) === 200) {
            $accountId = $res['body']['result']['account']['id'] ?? '';
            if ($accountId) {
                return ['ok' => true, 'account_id' => $accountId];
            }
        }
    }

    // ── Method 3: fallback to GET /accounts ──
    $res = cfRequest($cfg, 'accounts?per_page=1');
    if ($res['ok'] && ($res['code'] ?? 0) === 200) {
        $accounts = $res['body']['result'] ?? [];
        if (!empty($accounts)) {
            return ['ok' => true, 'account_id' => $accounts[0]['id']];
        }
    }

    return ['ok' => false, 'error' => 'Failed to get Account ID. Set the "Account ID" field in Cloudflare settings.'];
}

// ============================================================
// Find CF zone, create new if not found (full setup)
// Return: ['ok', 'zone_id', 'created' (bool), 'nameservers' (array)]
// ============================================================
// ── Read-only CF zone lookup (never creates). ───────────────
// Returns ['ok'=>true, 'zone_id','status','nameservers'] on hit,
// ['ok'=>false, 'error', 'not_found'=>true] when the zone doesn't
// exist on the account, or ['ok'=>false,'error'] on API/permission
// errors. Used by sync_cloudflare (no Zone:Edit required).
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function findCfZone(array $cfg, string $domain): array
{
    $registrable = getRegistrableDomain($domain);

    $searchRes = cfRequest($cfg, 'zones?name=' . urlencode($registrable) . '&per_page=1');
    if (!$searchRes['ok']) {
        return ['ok' => false, 'error' => $searchRes['error'] ?? 'Cloudflare API unreachable'];
    }
    $code = $searchRes['code'] ?? 0;
    if ($code === 401 || $code === 403) {
        return ['ok' => false, 'error' => 'CF Token rejected (' . $code . ') — needs at least "Zone → Zone → Read" and "Zone → DNS → Edit"'];
    }
    if ($code !== 200) {
        return ['ok' => false, 'error' => 'HTTP ' . $code . ' from Cloudflare: ' . cfErrMsg($searchRes)];
    }

    $zones = $searchRes['body']['result'] ?? [];
    if (empty($zones)) {
        return [
            'ok'        => false,
            'not_found' => true,
            'error'     => "Zone {$registrable} not found on the Cloudflare account — create it first (add_domain) or add it manually at dash.cloudflare.com, then retry Sync.",
        ];
    }

    return [
        'ok'          => true,
        'zone_id'     => $zones[0]['id'],
        'created'     => false,
        'status'      => $zones[0]['status']       ?? 'unknown',
        'nameservers' => $zones[0]['name_servers'] ?? [],
    ];
}

/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function findOrCreateCfZone(array $cfg, string $domain): array
{
    $registrable = getRegistrableDomain($domain);

    // ── Look for existing zone ──
    $searchRes = cfRequest($cfg, 'zones?name=' . urlencode($registrable) . '&per_page=1');
    if ($searchRes['ok'] && ($searchRes['code'] ?? 0) === 200) {
        $zones = $searchRes['body']['result'] ?? [];
        if (!empty($zones)) {
            return [
                'ok'          => true,
                'zone_id'     => $zones[0]['id'],
                'created'     => false,
                'status'      => $zones[0]['status'] ?? 'unknown',
                'nameservers' => $zones[0]['name_servers'] ?? [],
            ];
        }
    }

    // ── Zone does not exist → create new ──
    $accRes = getCfAccountId($cfg);
    if (!$accRes['ok']) {
        return ['ok' => false, 'error' => $accRes['error']];
    }

    $createRes = cfRequest($cfg, 'zones', 'POST', [
        'name'        => $registrable,
        'account'     => ['id' => $accRes['account_id']],
        'jump_start'  => false,
        'type'        => 'full',
    ]);

    $createCode = $createRes['code'] ?? 0;
    $createBody = $createRes['body'] ?? [];

    // Handle "already exists" (race condition / zone pending)
    if (!$createRes['ok'] || ($createCode !== 200 && $createCode !== 201)) {
        $errMsg = cfErrMsg($createRes);

        if (stripos($errMsg, 'already exists') !== false || stripos($errMsg, 'already been taken') !== false) {
            // Zone exists but may be in pending/moved status — search without status filter
            $retryRes = cfRequest($cfg, 'zones?name=' . urlencode($registrable) . '&per_page=1');
            if ($retryRes['ok'] && !empty($retryRes['body']['result'])) {
                $z = $retryRes['body']['result'][0];
                return [
                    'ok'          => true,
                    'zone_id'     => $z['id'],
                    'created'     => false,
                    'status'      => $z['status'] ?? 'unknown',
                    'nameservers' => $z['name_servers'] ?? [],
                ];
            }
        }

        // Permission error → specific message
        if (stripos($errMsg, 'zone.create') !== false || stripos($errMsg, 'permission') !== false) {
            return ['ok' => false, 'error' => "CF Token does not have permission to create zone. Ensure \"Zone → Zone → Edit\" permission is set with Zone Resources = \"All zones from an account\" in Cloudflare → My Profile → API Tokens."];
        }

        return ['ok' => false, 'error' => "Failed to create CF zone for {$registrable}: {$errMsg}"];
    }

    $zone = $createBody['result'] ?? [];
    return [
        'ok'          => true,
        'zone_id'     => $zone['id'],
        'created'     => true,
        'status'      => $zone['status'] ?? 'pending',
        'nameservers' => $zone['name_servers'] ?? [],
    ];
}

// ============================================================
// Add Cloudflare DNS record
// Supports: A, CNAME, AAAA, MX, TXT, NS
// $proxied   — only valid for A/CNAME/AAAA; automatically false for MX/TXT/NS
// $priority  — required for MX records
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function addDnsRecord(
    array $cfg,
    string $zoneId,
    string $type,
    string $name,
    string $content,
    bool $proxied = true,
    bool $skipExisting = true,
    ?int $priority = null
): array {
    // Types that cannot be proxied
    $noProxyTypes = ['MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'CERT', 'SSHFP', 'TLSA', 'DNSKEY', 'DS'];
    if (in_array(strtoupper($type), $noProxyTypes)) {
        $proxied = false;
    }

    // Check if record already exists
    $checkRes = cfRequest($cfg, "zones/{$zoneId}/dns_records?type={$type}&name={$name}");
    if ($checkRes['ok'] && ($checkRes['code'] ?? 0) === 200) {
        $existing = $checkRes['body']['result'] ?? [];
        if (!empty($existing)) {
            if ($skipExisting) {
                return ['ok' => true, 'skipped' => true, 'message' => "Record {$type} {$name} already exists, skipped"];
            }
            // Delete old record, create new
            foreach ($existing as $rec) {
                cfRequest($cfg, "zones/{$zoneId}/dns_records/{$rec['id']}", 'DELETE');
            }
        }
    }

    $body = [
        'type'    => $type,
        'name'    => $name,
        'content' => $content,
        'ttl'     => 1,       // auto
        'proxied' => $proxied,
    ];

    // MX: add priority
    if (strtoupper($type) === 'MX' && $priority !== null) {
        $body['priority'] = $priority;
    }

    $res = cfRequest($cfg, "zones/{$zoneId}/dns_records", 'POST', $body);

    $code = $res['code'] ?? 0;
    if (!$res['ok'] || ($code !== 200 && $code !== 201) || !($res['body']['success'] ?? false)) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to create record')];
    }

    $proxiedLabel = $proxied ? ' [Proxied]' : ' [DNS-only]';
    return ['ok' => true, 'skipped' => false, 'message' => "Record {$type} {$name} → {$content}{$proxiedLabel} successfully created"];
}

// ============================================================
// Helper: Patch single zone setting
// PATCH /zones/{id}/settings/{setting}  body: {"value": ...}
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @param mixed $value
 * @return array<string, mixed>
 */
function setCfZoneSetting(array $cfg, string $zoneId, string $setting, $value): array
{
    $res = cfRequest($cfg, "zones/{$zoneId}/settings/{$setting}", 'PATCH', ['value' => $value]);

    if (!$res['ok']) {
        return ['ok' => false, 'error' => $res['error'] ?? 'cURL error', 'res' => $res];
    }
    $code = $res['code'] ?? 0;
    if ($code !== 200 || !($res['body']['success'] ?? false)) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to activate setting'), 'res' => $res];
    }
    return ['ok' => true, 'message' => "Setting [{$setting}] successfully activated"];
}

// ============================================================
// Helper: Enable Page Shield (Client-side Security)
// PUT /zones/{id}/page_shield/settings
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfPageShield(array $cfg, string $zoneId, bool $enabled): array
{
    $body = [
        'enabled'                            => $enabled,
        'use_cloudflare_reporting_endpoint'  => true,
        'use_connection_url_path'            => true,
    ];
    $res = cfRequest($cfg, "zones/{$zoneId}/page_shield/settings", 'PUT', $body);

    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'Page Shield (Client-side Security) active'];
}

// ============================================================
// Helper: Enable Leaked Credentials Detection
// PUT /zones/{id}/leaked_credential_checks
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfLeakedCredentials(array $cfg, string $zoneId, bool $enabled): array
{
    $res = cfRequest($cfg, "zones/{$zoneId}/leaked_credential_checks", 'PUT', ['enabled' => $enabled]);

    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'Leaked Credentials Detection active'];
}

// ============================================================
// Helper: Enable WAF Managed Ruleset
// PUT /zones/{id}/rulesets/phases/http_request_firewall_managed/entrypoint
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfWaf(array $cfg, string $zoneId): array
{
    $body = [
        'description' => 'Execute Cloudflare Managed Ruleset',
        'rules' => [[
            'action'            => 'execute',
            'action_parameters' => ['id' => 'efb7b8c949ac4650a09736fc376e9aee'],
            'expression'        => 'true',
            'description'       => 'Cloudflare Managed Ruleset',
            'enabled'           => true,
        ]],
    ];
    $res = cfRequest($cfg, "zones/{$zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint", 'PUT', $body);
    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'WAF Managed Rules active'];
}

// ============================================================
// HSTS — PATCH /zones/{id}/settings/security_header
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfHsts(array $cfg, string $zoneId, bool $enabled): array
{
    $body = [
        'value' => [
            'strict_transport_security' => [
                'enabled'            => $enabled,
                'max_age'            => $enabled ? 31536000 : 0, // 12 months
                'include_subdomains' => $enabled,
                'preload'            => $enabled,
                'nosniff'            => $enabled,
            ],
        ],
    ];
    $res = cfRequest($cfg, "zones/{$zoneId}/settings/security_header", 'PATCH', $body);
    if (!$res['ok'] || ($res['code'] ?? 0) !== 200 || !($res['body']['success'] ?? false)) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to activate HSTS'), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'HSTS active (max-age 12 months, includeSubdomains, preload)'];
}

// ============================================================
// Transform rules: remove X-Powered-By, add security headers
// PUT /zones/{id}/rulesets/phases/http_response_headers_transform/entrypoint
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfResponseHeadersTransform(array $cfg, string $zoneId): array
{
    $body = [
        'description' => 'Response header hardening',
        'rules' => [[
            'action' => 'rewrite',
            'action_parameters' => [
                'headers' => [
                    'X-Powered-By'               => ['operation' => 'remove'],
                    'Server'                     => ['operation' => 'remove'],
                    'X-Content-Type-Options'     => ['operation' => 'set', 'value' => 'nosniff'],
                    'X-Frame-Options'            => ['operation' => 'set', 'value' => 'SAMEORIGIN'],
                    'Referrer-Policy'            => ['operation' => 'set', 'value' => 'strict-origin-when-cross-origin'],
                    'Permissions-Policy'         => ['operation' => 'set', 'value' => 'interest-cohort=()'],
                    'X-XSS-Protection'           => ['operation' => 'set', 'value' => '1; mode=block'],
                    'Cross-Origin-Opener-Policy' => ['operation' => 'set', 'value' => 'same-origin'],
                    'CF-Leaked-Credentials-Check' => [
                        'operation' => 'set',
                        'expression' => 'cf.waf.credential_check.saw_results',
                    ],
                ],
            ],
            'expression'  => 'true',
            'description' => 'Remove X-Powered-By / Server + add security headers + leaked-credentials check',
            'enabled'     => true,
        ]],
    ];
    $res = cfRequest($cfg, "zones/{$zoneId}/rulesets/phases/http_response_headers_transform/entrypoint", 'PUT', $body);
    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to apply response headers transform'), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'Response headers hardened (X-Powered-By/Server removed, security headers added)'];
}

// ============================================================
// Custom WAF rule: skip all WAF components for social scrapers + static assets.
// $includeIdSkip = true also adds a second rule that skips WAF for ID traffic.
// PUT /zones/{id}/rulesets/phases/http_request_firewall_custom/entrypoint
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfCustomSkipIdWaf(array $cfg, string $zoneId, bool $includeIdSkip = true): array
{
    // Rule 1 (always): Static assets + social preview bots → skip all WAF/UAM.
    //   Without this, Under Attack Mode (security_level=under_attack) and
    //   Bot Fight Mode challenge facebookexternalhit and similar crawlers,
    //   causing og:image fetches to fail and link previews to break on every
    //   social platform (Facebook, Twitter/X, Telegram, WhatsApp, Slack,
    //   Discord, LinkedIn, Pinterest, Apple iMessage, Google).
    //
    // Rule 2 (optional, $includeIdSkip): Indonesia traffic → skip all WAF.
    $assetExt = '{"jpg" "jpeg" "png" "gif" "webp" "svg" "ico" "avif" "bmp" "css" "js" "woff" "woff2" "ttf" "eot" "otf" "map" "mp4" "webm" "mp3" "ogg"}';
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

    $rules = [
        [
            'action' => 'skip',
            'action_parameters' => [
                'ruleset'  => 'current',
                'phases'   => $skipPhases,
                'products' => $skipProducts,
            ],
            'expression'  => '(http.request.uri.path.extension in ' . $assetExt . ') or '
                . '(http.request.uri.path eq "/ogimg.php") or '
                . $scraperUa,
            'description' => 'Skip WAF/UAM for static assets + social scrapers (images & link previews must load)',
            'enabled'     => true,
        ],
    ];

    if ($includeIdSkip) {
        $rules[] = [
            'action' => 'skip',
            'action_parameters' => [
                'ruleset'  => 'current',
                'phases'   => $skipPhases,
                'products' => $skipProducts,
            ],
            'expression'  => '(ip.src.country eq "ID")',
            'description' => 'Skip all WAF components for ID traffic',
            'enabled'     => true,
        ];
    }

    $body = ['description' => 'Custom firewall rules', 'rules' => $rules];
    $res = cfRequest($cfg, "zones/{$zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint", 'PUT', $body);
    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to create custom skip rules'), 'res' => $res];
    }
    $label = $includeIdSkip
        ? 'Custom skip rules active (static assets + social scrapers + ID traffic)'
        : 'Custom skip rules active (static assets + social scrapers)';
    return ['ok' => true, 'message' => $label];
}

// ============================================================
// Smart Shield / Bot Management (available tier depends on plan)
// PUT /zones/{id}/bot_management
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfSmartShield(array $cfg, string $zoneId, bool $enabled): array
{
    $body = [
        'fight_mode'          => $enabled, // Super Bot Fight Mode
        'enable_js'           => $enabled,
        'auto_update_model'   => $enabled,
        // Always allow verified bots (Googlebot, facebookexternalhit, etc.)
        // so OG/social previews and SEO crawlers are never blocked by SBFM.
        'sbfm_verified_bots'  => 'allow',
    ];
    $res = cfRequest($cfg, "zones/{$zoneId}/bot_management", 'PUT', $body);
    if (!$res['ok'] || ($res['code'] ?? 0) !== 200) {
        return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to enable Smart Shield'), 'res' => $res];
    }
    return ['ok' => true, 'message' => 'Smart Shield / Bot Management active'];
}

// ============================================================
// DMARC Management — enables aggregate report ingestion
// POST /zones/{id}/dmarc_management (newer) or /email/security/settings
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @return array<string, mixed>
 */
function setCfDmarcManagement(array $cfg, string $zoneId, bool $enabled): array
{
    $res = cfRequest($cfg, "zones/{$zoneId}/dmarc_management", 'PUT', ['enabled' => $enabled]);
    if ($res['ok'] && ($res['code'] ?? 0) === 200) {
        return ['ok' => true, 'message' => 'DMARC Management active'];
    }

    // Fallback to email security settings endpoint (older CF API shape)
    $res2 = cfRequest($cfg, "zones/{$zoneId}/email/security/settings", 'PATCH', [
        'dmarc_management_enabled' => $enabled,
    ]);
    if ($res2['ok'] && ($res2['code'] ?? 0) === 200) {
        return ['ok' => true, 'message' => 'DMARC Management active (email/security)'];
    }

    return ['ok' => false, 'error' => cfErrMsg($res, 'Failed to enable DMARC Management'), 'res' => $res];
}

// ============================================================
// Apply all CF Security & Speed settings to a zone.
// $opts keys:
//   under_attack (default false), page_shield, bot_fight, leaked_creds,
//   waf, always_online, cache_aggressive, browser_cache_ttl, minify,
//   rocket, early_hints, http2, brotli
// ============================================================
/**
 * @param array<string, mixed> $cfg
 * @param array<int, array<string, string>> $logs
 * @param array<string, mixed> $opts
 */
function applyCfSecuritySpeed(array $cfg, string $zoneId, array &$logs, array $opts = []): void
{
    $o = array_merge([
        // ── Core SSL / TLS ────────────────────────────────────
        'ssl'                      => true,
        'always_use_https'         => true,
        'automatic_https_rewrites' => true,
        'opportunistic_encryption' => true,
        'opportunistic_onion'      => true,
        'min_tls_version'          => true,
        'tls_1_3'                  => true,
        // ── Security settings ─────────────────────────────────
        'under_attack'             => false,
        'security_level_medium'    => true,
        'browser_check'            => true,
        'challenge_ttl'            => true,
        'email_obfuscation'        => true,
        'server_side_exclude'      => true,
        'hotlink_protection'       => true,
        'ip_geolocation'           => true,
        'privacy_pass'             => true,
        // ── Advanced security ─────────────────────────────────
        'page_shield'              => true,
        'bot_fight'                => true,
        'leaked_creds'             => true,
        'waf'                      => true,
        'hsts'                     => true,
        'response_headers'         => true,
        'smart_shield'             => true,
        'dmarc_mgmt'               => true,
        'custom_skip_id'           => true,
        // ── Cache ─────────────────────────────────────────────
        'always_online'            => true,
        'cache_aggressive'         => true,
        'browser_cache_ttl'        => true,
        // ── Performance ───────────────────────────────────────
        'http2'                    => true,
        'brotli'                   => true,
        'early_hints'              => true,
        'minify'                   => true,
        'websockets'               => true,
        'prefetch_preload'         => true,
        'speed_brain'              => true,
        'fonts'                    => true,
        // Rocket Loader intentionally off — rewrites <script> tags
        // asynchronously, which breaks click-tracking and postback JS.
        'rocket'                   => false,
    ], $opts);

    // Track denied features so we can emit a single actionable hint
    // at the end instead of repeating the same permission warning.
    $deniedFeatures = [];

    $logCf = function (array $r, string $label) use (&$logs, &$deniedFeatures) {
        if ($r['ok']) {
            $logs[] = ['type' => 'success', 'message' => "CF: " . $r['message']];
            return;
        }

        $res = is_array($r['res'] ?? null) ? $r['res'] : [];
        $isDenied = $res ? cfIsPermissionDenied($res) : false;

        if ($isDenied) {
            $deniedFeatures[] = $label;
            $logs[] = [
                'type'    => 'info',
                'message' => "CF [{$label}]: skipped — token lacks permission or feature not on current plan",
            ];
            return;
        }

        $logs[] = [
            'type'    => 'warning',
            'message' => "CF [{$label}]: " . ($r['error'] ?? 'Not supported / plan limitation'),
        ];
    };

    // ── Core SSL / TLS ────────────────────────────────────────────────
    if ($o['ssl']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'ssl',                      'full'), 'SSL (Full)');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'always_use_https',         'on'),   'Always Use HTTPS');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'automatic_https_rewrites', 'on'),   'Automatic HTTPS Rewrites');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'opportunistic_encryption', 'on'),   'Opportunistic Encryption');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'opportunistic_onion',      'on'),   'Opportunistic Onion');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'min_tls_version',          '1.2'),  'Min TLS 1.2');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'tls_1_3',                  'on'),   'TLS 1.3');
    }
    // ── Security settings ──────────────────────────────────────────────
    if ($o['security_level_medium'] && !$o['under_attack']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'security_level', 'medium'), 'Security Level (Medium)');
    }
    if ($o['browser_check']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'browser_check',       'on'), 'Browser Integrity Check');
    }
    if ($o['challenge_ttl']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'challenge_ttl',        1800), 'Challenge TTL (30 min)');
    }
    if ($o['email_obfuscation']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'email_obfuscation',   'on'), 'Email Obfuscation');
    }
    if ($o['server_side_exclude']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'server_side_exclude', 'on'), 'Server-Side Excludes');
    }
    if ($o['hotlink_protection']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'hotlink_protection',  'on'), 'Hotlink Protection');
    }
    if ($o['ip_geolocation']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'ip_geolocation',      'on'), 'IP Geolocation');
    }
    if ($o['privacy_pass']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'privacy_pass',        'on'), 'Privacy Pass');
    }
    if ($o['under_attack']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'security_level', 'under_attack'), 'Under Attack Mode');
    }
    if ($o['page_shield']) {
        $logCf(setCfPageShield($cfg, $zoneId, true), 'Page Shield');
    }
    if ($o['bot_fight']) {
        // Explicitly set zone setting to 'off' so Basic Bot Fight Mode is never
        // active on free-plan zones (basic BFM blocks ALL bots including verified
        // ones like facebookexternalhit, breaking social link previews).
        // setCfSmartShield() below calls PUT /bot_management with fight_mode:true +
        // sbfm_verified_bots:'allow', which re-enables SBFM on Pro/Business plans
        // with verified-bot pass-through — so the net result is correct on all plans.
        $logCf(setCfZoneSetting($cfg, $zoneId, 'bot_fight_mode', 'off'), 'Bot Fight Mode zone setting (reset to off; SBFM via API below)');
    }
    if ($o['leaked_creds']) {
        $logCf(setCfLeakedCredentials($cfg, $zoneId, true), 'Leaked Credentials');
    }
    if ($o['waf']) {
        $logCf(setCfWaf($cfg, $zoneId), 'WAF Managed Rules');
    }
    if ($o['always_online']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'always_online', 'on'), 'Always Online');
    }
    if ($o['cache_aggressive']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'cache_level', 'aggressive'), 'Cache Level (Aggressive)');
    }
    if ($o['browser_cache_ttl']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'browser_cache_ttl', 14400), 'Browser Cache TTL (4h)');
    }
    if ($o['minify']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'minify', ['css' => 'on', 'js' => 'on', 'html' => 'on']), 'Auto Minify');
    }
    if ($o['rocket']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'rocket_loader', 'on'), 'Rocket Loader');
    }
    if ($o['early_hints']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'early_hints', 'on'), 'Early Hints');
    }
    if ($o['http2']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'http2', 'on'), 'HTTP/2');
        $logCf(setCfZoneSetting($cfg, $zoneId, 'http3', 'on'), 'HTTP/3 (QUIC)');
        $logCf(setCfZoneSetting($cfg, $zoneId, '0rtt', 'on'), '0-RTT');
    }
    if ($o['brotli']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'brotli', 'on'), 'Brotli Compression');
    }
    if ($o['websockets']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'websockets',               'on'), 'WebSockets');
    }
    if ($o['prefetch_preload']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'prefetch_preload',         'on'), 'Prefetch/Preload');
    }
    if ($o['speed_brain']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'speed_brain',              'on'), 'Speed Brain');
    }
    if ($o['fonts']) {
        $logCf(setCfZoneSetting($cfg, $zoneId, 'fonts_loading_optimization', 'on'), 'Fonts Loading Optimization');
    }
    if ($o['hsts']) {
        $logCf(setCfHsts($cfg, $zoneId, true), 'HSTS (12 months, includeSubdomains, preload)');
    }
    if ($o['response_headers']) {
        $logCf(setCfResponseHeadersTransform($cfg, $zoneId), 'Response Headers (hardening + leaked creds)');
    }
    if ($o['smart_shield']) {
        $logCf(setCfSmartShield($cfg, $zoneId, true), 'Smart Shield / Bot Management');
    }
    if ($o['dmarc_mgmt']) {
        $logCf(setCfDmarcManagement($cfg, $zoneId, true), 'DMARC Management');
    }
    // Social bot bypass is unconditional — link previews on Facebook, Twitter,
    // Telegram etc. require facebookexternalhit and similar UAs to bypass WAF.
    // $o['custom_skip_id'] only controls whether the ID traffic skip is included.
    $logCf(setCfCustomSkipIdWaf($cfg, $zoneId, $o['custom_skip_id']), 'Custom skip rules (social scrapers + assets' . ($o['custom_skip_id'] ? ' + ID' : '') . ')');

    if (!empty($deniedFeatures)) {
        $unique = array_values(array_unique($deniedFeatures));
        $logs[] = [
            'type'    => 'info',
            'message' => 'Hint: ' . count($unique) . ' CF feature(s) skipped (' . implode(', ', $unique) .
                '). To enable them, grant the CF token these scopes in Cloudflare → My Profile → API Tokens: ' .
                'Zone → Zone Settings:Edit, Zone → Page Shield:Edit, Zone → Bot Management:Edit, ' .
                'Zone → Leaked Credential Checks:Edit, Zone → Zone WAF:Edit. ' .
                'Some features (Auto Minify, Rocket Loader, 0-RTT) may be plan-restricted or deprecated on your plan.',
        ];
    }
}

// ============================================================
// ACTION: Sync Cloudflare
// ============================================================
if ($action === 'sync_cloudflare') {
    set_time_limit(120);
    $logs   = [];
    $domain = trim($data['domain'] ?? '');

    if (!$domain) {
        exit(json_encode(['success' => false, 'message' => 'Domain is required', 'logs' => []]));
    }
    if (!isCloudflareConfigured($config)) {
        exit(json_encode(['success' => false, 'message' => 'Cloudflare token not configured — sync requires CF credentials', 'logs' => []]));
    }

    $serverIp    = trim($config['server_ip'] ?? '');
    $proxied     = ($config['cf_proxied'] ?? 'true') === 'true';
    $wildcardDir = trim($config['wildcard_dir'] ?? '');

    if (!$serverIp) {
        exit(json_encode(['success' => false, 'message' => 'Server IP not configured', 'logs' => []]));
    }

    // ---- CF Security & Speed flags (accept from request, defaults = all on) ----
    $cfUnderAttack     = (bool)($data['cf_under_attack']      ?? false);
    $cfPageShield      = (bool)($data['cf_pageshield']        ?? true);
    $cfBotFight        = (bool)($data['cf_bot_fight']         ?? true);
    $cfLeakedCreds     = (bool)($data['cf_leaked_creds']      ?? true);
    $cfWaf             = (bool)($data['cf_waf']               ?? true);
    $cfAlwaysOnline    = (bool)($data['cf_always_online']     ?? true);
    $cfCacheAggressive = (bool)($data['cf_cache_aggressive']  ?? true);
    $cfBrowserCacheTtl = (bool)($data['cf_browser_cache_ttl'] ?? true);
    $cfSpeedMinify     = (bool)($data['cf_speed_minify']      ?? true);
    $cfSpeedRocket     = (bool)($data['cf_speed_rocket']      ?? false);
    $cfSpeedHints      = (bool)($data['cf_speed_hints']       ?? true);
    $cfSpeedHttp2      = (bool)($data['cf_speed_http2']       ?? true);
    $cfSpeedBrotli     = (bool)($data['cf_speed_brotli']      ?? true);
    $cfHsts            = (bool)($data['cf_hsts']              ?? true);
    $cfResponseHeaders = (bool)($data['cf_response_headers']  ?? true);
    $cfSmartShield     = (bool)($data['cf_smart_shield']      ?? true);
    $cfDmarcMgmt       = (bool)($data['cf_dmarc_mgmt']        ?? true);
    $cfCustomSkipId    = (bool)($data['cf_custom_skip_id']    ?? true);
    $cfAuditProxyLeaks = (bool)($data['cf_audit_proxy_leaks'] ?? true);

    $overallSuccess = true;
    $zoneId         = '';
    $zoneNs         = [];
    $zoneCreated    = false;

    // ---- Step 0: Ensure cPanel wildcard *.domain.com ----
    $isAlready = function (string $err): bool {
        return stripos($err, 'already exists') !== false
            || stripos($err, 'already been') !== false
            || stripos($err, 'exist') !== false;
    };

    if ($wildcardDir) {
        $logs[] = ['type' => 'step', 'message' => "STEP 0: Ensuring cPanel wildcard *.{$domain} → /{$wildcardDir}..."];
        $wcArgs = ['domain' => '*', 'rootdomain' => $domain, 'dir' => ltrim($wildcardDir, '/'), 'disallowdot' => '0'];
        $wcRes  = cpanelRequest($config, 'SubDomain', 'addsubdomain', $wcArgs);
        if (($wcRes['body']['status'] ?? 0) == 1) {
            $logs[] = ['type' => 'success', 'message' => "cPanel: Wildcard *.{$domain} created → /{$wildcardDir}"];
        } else {
            $wcErr = cpanelErrStr($wcRes);
            if ($isAlready($wcErr)) {
                $logs[] = ['type' => 'info', 'message' => "cPanel: Wildcard *.{$domain} already exists ✓"];
            } elseif (!$wcRes['ok'] || stripos($wcErr, 'timed out') !== false) {
                $logs[] = ['type' => 'warning', 'message' => "cPanel Wildcard: {$wcErr} — continuing..."];
            } else {
                $logs[] = ['type' => 'warning', 'message' => "cPanel Wildcard Error: {$wcErr} — continuing..."];
            }
        }
    } else {
        $logs[] = ['type' => 'info', 'message' => 'STEP 0: cPanel wildcard skipped (WILDCARD_DIR not set)'];
    }

    // ---- Step 1: Find or create CF zone ----
    $logs[] = ['type' => 'step', 'message' => "STEP 1: Syncing Cloudflare zone for {$domain}..."];
    $zoneResult = findOrCreateCfZone($config, $domain);
    if (!$zoneResult['ok']) {
        $msg = $zoneResult['error'] ?? 'Failed to get/create Cloudflare zone';
        $logs[] = ['type' => 'error', 'message' => 'Zone CF: ' . $msg];
        exit(json_encode(['success' => false, 'message' => $msg, 'logs' => $logs]));
    }

    $zoneId      = $zoneResult['zone_id'];
    $zoneCreated = $zoneResult['created'] ?? false;
    $zoneStatus  = $zoneResult['status']  ?? 'unknown';
    $zoneNs      = $zoneResult['nameservers'] ?? [];

    if ($zoneCreated) {
        $logs[] = ['type' => 'success', 'message' => "New CF zone created for {$domain} (status: {$zoneStatus})"];
        if (!empty($zoneNs)) {
            $nsStr = implode('  •  ', $zoneNs);
            $logs[] = ['type' => 'warning', 'message' => "‼ Update NS at the registrar → {$nsStr}"];
        }
    } else {
        $logs[] = ['type' => 'info', 'message' => "Zone found for {$domain} (status: {$zoneStatus})"];
    }

    if (!empty($zoneNs)) {
        $logs[] = ['type' => 'info', 'message' => "Nameserver CF: " . implode('  •  ', $zoneNs)];
    }

    // ---- Step 2: DNS records ----
    $logs[] = ['type' => 'step', 'message' => "STEP 2: Syncing DNS records..."];

    $r = addDnsRecord($config, $zoneId, 'A', $domain, $serverIp, $proxied, true);
    logDnsResult($r, 'A @', $logs, $overallSuccess);

    $r = addDnsRecord($config, $zoneId, 'CNAME', 'www.' . $domain, $domain, $proxied, true);
    logDnsResult($r, 'CNAME www', $logs, $overallSuccess);

    addWildcardDnsRecord($config, $zoneId, $domain, $serverIp, $proxied, true, $logs, $overallSuccess);

    $r = addDnsRecord($config, $zoneId, 'MX', $domain, '.', false, true, 0);
    logDnsResult($r, 'MX @ null', $logs, $overallSuccess);

    $r = addDnsRecord($config, $zoneId, 'TXT', $domain, 'v=spf1 -all', false, true);
    logDnsResult($r, 'TXT SPF', $logs, $overallSuccess);

    $r = addDnsRecord($config, $zoneId, 'TXT', '_dmarc.' . $domain, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100', false, true);
    logDnsResult($r, 'TXT DMARC', $logs, $overallSuccess);

    // ---- Step 3: CF Security & Speed settings ----
    $logs[] = ['type' => 'step', 'message' => "STEP 3: Applying Cloudflare Security & Speed settings..."];
    applyCfSecuritySpeed($config, $zoneId, $logs, [
        'under_attack'     => $cfUnderAttack,
        'page_shield'      => $cfPageShield,
        'bot_fight'        => $cfBotFight,
        'leaked_creds'     => $cfLeakedCreds,
        'waf'              => $cfWaf,
        'always_online'    => $cfAlwaysOnline,
        'cache_aggressive' => $cfCacheAggressive,
        'browser_cache_ttl' => $cfBrowserCacheTtl,
        'minify'           => $cfSpeedMinify,
        'rocket'           => $cfSpeedRocket,
        'early_hints'      => $cfSpeedHints,
        'http2'            => $cfSpeedHttp2,
        'brotli'           => $cfSpeedBrotli,
        'hsts'             => $cfHsts,
        'response_headers' => $cfResponseHeaders,
        'smart_shield'     => $cfSmartShield,
        'dmarc_mgmt'       => $cfDmarcMgmt,
        'custom_skip_id'   => $cfCustomSkipId,
    ]);

    // ---- Step 4: Proxy-leak audit ----
    if ($cfAuditProxyLeaks) {
        $logs[] = ['type' => 'step', 'message' => 'STEP 4: Auditing DNS proxy leaks...'];
        $audit  = auditAndFixProxyLeaks($config, $zoneId, $logs);
        $logs[] = [
            'type'    => 'success',
            'message' => 'Proxy-leak audit: checked ' . (int)($audit['checked'] ?? 0)
                . ', flipped ' . (is_array($audit['fixed'] ?? null) ? count($audit['fixed']) : 0)
                . ', kept ' . (is_array($audit['unfixable'] ?? null) ? count($audit['unfixable']) : 0) . ' as-is',
        ];
    }

    if ($overallSuccess) {
        $logs[] = ['type' => 'success', 'message' => "Done! {$domain} fully synced."];
    } else {
        $logs[] = ['type' => 'error', 'message' => "Sync completed with some errors. Check the log above."];
    }

    exit(json_encode([
        'success'      => $overallSuccess,
        'message'      => $overallSuccess ? "Sync {$domain} successful" : "Sync completed with errors",
        'logs'         => $logs,
        'nameservers'  => $zoneNs,
        'zone_created' => $zoneCreated,
        'domain'       => $domain,
    ]));
}

// ============================================================
// ACTION: Test cPanel
// ============================================================
if ($action === 'test_cpanel') {
    $res = cpanelRequest($config, 'Quota', 'get_quota_info');

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'Connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (($res['code'] ?? 0) === 401) {
        exit(json_encode(['success' => false, 'message' => 'Authentication failed — check username and API token']));
    }
    if (($res['code'] ?? 0) !== 200) {
        exit(json_encode(['success' => false, 'message' => 'cPanel responded with HTTP ' . ($res['code'] ?? '?')]));
    }
    if (!($res['body']['status'] ?? false) && isset($res['body']['errors'])) {
        $err = cpanelErrStr($res);
        exit(json_encode(['success' => false, 'message' => $err]));
    }

    exit(json_encode(['success' => true, 'message' => 'cPanel connection successful!']));
}

// ============================================================
// ACTION: Test Cloudflare
// ============================================================
if ($action === 'test_cloudflare') {
    $res = cfRequest($config, 'user/tokens/verify');

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'Connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (($res['code'] ?? 0) === 403 || ($res['code'] ?? 0) === 401) {
        exit(json_encode(['success' => false, 'message' => 'Token invalid or lacks permission']));
    }
    if (!($res['body']['success'] ?? false)) {
        $errMsg = ($res['body']['errors'][0]['message'] ?? null) ?? 'Invalid token';
        exit(json_encode(['success' => false, 'message' => $errMsg]));
    }

    $status = $res['body']['result']['status'] ?? 'unknown';
    if ($status !== 'active') {
        exit(json_encode(['success' => false, 'message' => "Token status: {$status} (not active)"]));
    }

    exit(json_encode(['success' => true, 'message' => 'Cloudflare token is valid and active!']));
}

// ============================================================
// ACTION: Save Config
// ============================================================
if ($action === 'save_config') {
    $configFile = __DIR__ . '/../data/config.json';
    $envFile    = __DIR__ . '/../.env';
    $cpanelManagedInEnv = !empty(getenv('CPANEL_HOST'))
        && !empty(getenv('CPANEL_USER'))
        && !empty(getenv('CPANEL_TOKEN'));

    // Load whatever is currently on disk so we can preserve stored
    // values when the UI submits an empty or masked ('****') field.
    $existingSavedConfig = [];
    if (is_file($configFile)) {
        $existingSavedConfig = json_decode((string) file_get_contents($configFile), true) ?: [];
    }

    // Helper: pick the submitted value if it's a real value, otherwise
    // fall back to the previously stored value. '****' and '' both
    // mean "unchanged / preserve existing".
    $pickCf = static function (string $key) use ($rawRequestConfig, $existingSavedConfig): string {
        $submitted = trim((string) ($rawRequestConfig[$key] ?? ''));
        if ($submitted !== '' && $submitted !== '****') {
            return $submitted;
        }
        return trim((string) ($existingSavedConfig[$key] ?? ''));
    };

    // ── All 4 CF fields are now stored in config.json (in addition
    //    to app_users and .env). Admin edits propagate to all three
    //    storage locations so any of them can act as a source of truth.
    $cfToken     = $pickCf('cf_token');
    $cfAccountId = $pickCf('cf_account_id');
    $cfZoneId    = $pickCf('cf_zone_id');
    $cfProxied   = $pickCf('cf_proxied');
    if ($cfProxied === '') {
        $cfProxied = 'true';
    }

    // filter_redirect_url is now managed exclusively via the hantuin
    // dashboard (RedirectDecision config). We preserve any existing value
    // in config.json so go.php keeps working, but the admin UI no longer
    // exposes or overwrites it.
    $toSave = [
        'cf_token'           => $cfToken,
        'cf_account_id'      => $cfAccountId,
        'cf_zone_id'         => $cfZoneId,
        'cf_proxied'         => $cfProxied,
    ];
    // Preserve existing filter_redirect_url if present (backward compat)
    if (isset($existingSavedConfig['filter_redirect_url'])
        && $existingSavedConfig['filter_redirect_url'] !== '') {
        $toSave['filter_redirect_url'] = $existingSavedConfig['filter_redirect_url'];
    }

    if (!$cpanelManagedInEnv) {
        $toSave['cpanel_host']  = trim((string) ($rawRequestConfig['cpanel_host'] ?? $existingSavedConfig['cpanel_host'] ?? ''));
        $toSave['cpanel_port']  = intval($rawRequestConfig['cpanel_port'] ?? $existingSavedConfig['cpanel_port'] ?? 2083);
        $toSave['cpanel_user']  = trim((string) ($rawRequestConfig['cpanel_user'] ?? $existingSavedConfig['cpanel_user'] ?? ''));
        $toSave['server_ip']    = trim((string) ($rawRequestConfig['server_ip']    ?? $existingSavedConfig['server_ip']    ?? ''));
        $toSave['base_dir']     = trim((string) ($rawRequestConfig['base_dir']     ?? $existingSavedConfig['base_dir']     ?? 'public_html'));
        $toSave['wildcard_dir'] = trim((string) ($rawRequestConfig['wildcard_dir'] ?? $existingSavedConfig['wildcard_dir'] ?? ''));
    }

    // ── Write all 4 CF fields + cpanel_token to .env. Masked ('****')
    //    or empty values are preserved by tp_env_file_set so the stored
    //    token isn't clobbered when the UI only displays the mask.
    $rawCpanelToken = trim((string) ($rawRequestConfig['cpanel_token'] ?? ''));
    if (
        !updateEnvConfigValues(
            $envFile,
            [
                'CPANEL_TOKEN'  => $rawCpanelToken,
                'CF_TOKEN'      => $cfToken,
                'CF_ACCOUNT_ID' => $cfAccountId,
                'CF_ZONE_ID'    => $cfZoneId,
                'CF_PROXIED'    => $cfProxied,
            ]
        )
    ) {
        exit(json_encode(['success' => false, 'message' => 'Failed to write .env — check file permissions.']));
    }

    $written = file_put_contents($configFile, json_encode($toSave, JSON_PRETTY_PRINT));
    if ($written === false) {
        exit(json_encode(['success' => false, 'message' => 'Failed to write config file. Check directory permissions.']));
    }

    // Mirror the same 4 CF fields into the admin's app_users row.
    // syncAdminCfToAppUsers already preserves the stored token when it
    // receives '' or '****', so passing $cfToken (already picked) is fine.
    $adminDbSync = syncAdminCfToAppUsers([
        'cf_token'      => $cfToken,
        'cf_account_id' => $cfAccountId,
        'cf_zone_id'    => $cfZoneId,
        'cf_proxied'    => $cfProxied,
    ]);

    if (function_exists('tp_apcu_store')) {
        tp_apcu_store('tp_dashboard_version', time());
    }
    // Bust go.php's admin-config cache so filter_redirect_url changes
    // take effect on the next request instead of after the 120s TTL.
    if (function_exists('tp_apcu_delete')) {
        tp_apcu_delete('tp:admin_filter_redirect_url');
    }
    exit(json_encode([
        'success'         => true,
        'message'         => 'Configuration saved',
        'admin_db_synced' => $adminDbSync,
        'synced_fields'   => ['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'],
    ]));
}

// ============================================================
// ACTION: Add Domain
// ============================================================
if ($action === 'add_domain') {
    set_time_limit(120);
    $logs     = [];
    $domain   = trim($data['domain'] ?? '');
    $domainId = trim($data['domain_id'] ?? 'admin'); // owner username, 'admin' = all users

    // Wildcard directory (required)
    $wildcardDir = trim($data['wildcard_dir'] ?? '') ?: trim($config['wildcard_dir'] ?? '');

    // ---- DNS flags from the form ----
    $addDnsA      = (bool)($data['add_dns_a']     ?? true);   // @ A → server_ip  [proxied]
    $addWww       = (bool)($data['add_www']        ?? true);   // www CNAME → domain [proxied]
    $addWildcard  = (bool)($data['add_wildcard']   ?? true);   // * A → server_ip   [proxied]
    $addMxNull    = (bool)($data['add_mx_null']    ?? true);   // @ MX 0 .
    $addSpf       = (bool)($data['add_spf']        ?? true);   // @ TXT "v=spf1 -all"
    $addDmarc     = (bool)($data['add_dmarc']      ?? true);   // _dmarc TXT DMARC1
    $skipExisting = (bool)($data['skip_existing']  ?? true);

    // ---- Flags Cloudflare Security & Speed ----
    $cfUnderAttack = (bool) ($data['cf_under_attack'] ?? false);
    $cfPageShield = (bool) ($data['cf_pageshield'] ?? true);
    $cfBotFight = (bool) ($data['cf_bot_fight'] ?? true);
    $cfLeakedCreds = (bool) ($data['cf_leaked_creds'] ?? true);
    $cfWaf = (bool) ($data['cf_waf'] ?? true);
    $cfAlwaysOnline = (bool) ($data['cf_always_online'] ?? true);
    $cfCacheAggressive = (bool) ($data['cf_cache_aggressive'] ?? true);
    $cfBrowserCacheTtl = (bool) ($data['cf_browser_cache_ttl'] ?? true);
    $cfSpeedMinify = (bool) ($data['cf_speed_minify'] ?? true);
    $cfSpeedRocket = (bool) ($data['cf_speed_rocket'] ?? false);  // off — breaks tracking JS
    $cfSpeedHints = (bool) ($data['cf_speed_hints'] ?? true);
    $cfSpeedHttp2 = (bool) ($data['cf_speed_http2'] ?? true);
    $cfSpeedBrotli = (bool) ($data['cf_speed_brotli'] ?? true);
    $cfHsts            = (bool) ($data['cf_hsts']            ?? true);
    $cfResponseHeaders = (bool) ($data['cf_response_headers'] ?? true);
    $cfSmartShield     = (bool) ($data['cf_smart_shield']    ?? true);
    $cfDmarcMgmt       = (bool) ($data['cf_dmarc_mgmt']      ?? true);
    $cfCustomSkipId    = (bool) ($data['cf_custom_skip_id']  ?? true);
    $cfAuditProxyLeaks = (bool) ($data['cf_audit_proxy_leaks'] ?? true);
    // ── SSL / TLS ─────────────────────────────────────────────
    $cfSsl                 = (bool) ($data['cf_ssl']                   ?? true);
    $cfAlwaysUseHttps      = (bool) ($data['cf_always_use_https']      ?? true);
    $cfAutoHttpsRewrites   = (bool) ($data['cf_auto_https_rewrites']   ?? true);
    $cfOpportunisticEnc    = (bool) ($data['cf_opportunistic_enc']     ?? true);
    $cfOpportunisticOnion  = (bool) ($data['cf_opportunistic_onion']   ?? true);
    $cfMinTlsVersion       = (bool) ($data['cf_min_tls_version']       ?? true);
    $cfTls13               = (bool) ($data['cf_tls_1_3']               ?? true);
    // ── Security settings ─────────────────────────────────────
    $cfSecurityLevelMedium = (bool) ($data['cf_security_level_medium'] ?? true);
    $cfBrowserCheck        = (bool) ($data['cf_browser_check']         ?? true);
    $cfChallengeTtl        = (bool) ($data['cf_challenge_ttl']         ?? true);
    $cfEmailObfuscation    = (bool) ($data['cf_email_obfuscation']     ?? true);
    $cfServerSideExclude   = (bool) ($data['cf_server_side_exclude']   ?? true);
    $cfHotlinkProtection   = (bool) ($data['cf_hotlink_protection']    ?? true);
    $cfIpGeolocation       = (bool) ($data['cf_ip_geolocation']        ?? true);
    $cfPrivacyPass         = (bool) ($data['cf_privacy_pass']          ?? true);
    // ── Performance extras ────────────────────────────────────
    $cfWebsockets          = (bool) ($data['cf_websockets']            ?? true);
    $cfPrefetchPreload     = (bool) ($data['cf_prefetch_preload']      ?? true);
    $cfSpeedBrain          = (bool) ($data['cf_speed_brain']           ?? true);
    $cfFonts               = (bool) ($data['cf_fonts']                 ?? true);

    $serverIp = trim($config['server_ip'] ?? '');
    $proxied  = ($config['cf_proxied'] ?? 'true') === 'true';

    // ── Cloudflare availability gate ─────────────────────────
    // When CF is not configured, the whole flow falls back to
    // "cPanel only": Park + wildcard subdomain. No CF zone, no CF
    // DNS template, no CF security/speed tweaks. server_ip also
    // becomes optional because it's only used by CF DNS A records.
    $cfEnabled = isCloudflareConfigured($config);

    // ── Input sanitization and validation ────────────────────
    $domain = preg_replace('/^www\./i', '', strtolower(trim($domain)));

    if (!$domain) {
        exit(json_encode(['success' => false, 'message' => 'Domain is required', 'logs' => []]));
    }

    // Format domain (RFC 1035)
    if (strlen($domain) > 253) {
        exit(json_encode(['success' => false, 'message' => 'Domain too long (max. 253 characters)', 'logs' => []]));
    }
    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain)) {
        exit(json_encode(['success' => false, 'message' => 'Invalid domain format', 'logs' => []]));
    }
    foreach (explode('.', $domain) as $label) {
        if (strlen($label) > 63) {
            exit(json_encode(['success' => false, 'message' => "Domain label \"{$label}\" too long (max. 63 characters)", 'logs' => []]));
        }
    }

    // Validate the server IP — only required when CF is configured
    // AND the user asked for A / wildcard records.
    $needsServerIp = $cfEnabled && ($addDnsA || $addWildcard);
    if ($needsServerIp) {
        if (!$serverIp) {
            exit(json_encode(['success' => false, 'message' => 'Server IP not configured (required for A / wildcard DNS records on Cloudflare)', 'logs' => []]));
        }
        if (!filter_var($serverIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            exit(json_encode(['success' => false, 'message' => "Invalid server IP: {$serverIp}", 'logs' => []]));
        }
    } elseif ($serverIp && !filter_var($serverIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // Still warn (non-fatal) if a bogus IP is set but unused.
        $logs[] = ['type' => 'warning', 'message' => "Server IP \"{$serverIp}\" is not a valid IPv4 address — ignored in fallback mode"];
        $serverIp = '';
    }

    // Check for duplicate domain in database
    $dbConn = dbConnect();
    if ($dbConn) {
        try {
            $dupStmt = $dbConn->prepare('SELECT id FROM addondomain WHERE domain = ? LIMIT 1');
            $dupStmt->execute([$domain]);
            if ($dupStmt->fetch()) {
                exit(json_encode(['success' => false, 'message' => "Domain {$domain} already exists in the database", 'logs' => []]));
            }
        } catch (PDOException $e) {
            // Continue anyway if duplicate check fails
        }
    }

    $overallSuccess = true;
    $zoneId         = '';
    $zoneNs         = [];
    $zoneCreated    = false;

    if (!$wildcardDir) {
        $logs[] = ['type' => 'error', 'message' => 'WILDCARD_DIR is not configured in Server settings'];
        exit(json_encode(['success' => false, 'message' => 'WILDCARD_DIR not configured', 'logs' => $logs]));
    }

    // ── Announce mode up-front so the UI log is unambiguous ──
    if ($cfEnabled) {
        $logs[] = ['type' => 'info', 'message' => 'Mode: cPanel + Cloudflare'];
    } else {
        $logs[] = ['type' => 'info', 'message' => 'Mode: cPanel only (Cloudflare not configured — fallback)'];
    }

    // ── Initial connection: get cPanel main domain ──
    $mainDomainRes = cpanelRequest($config, 'DomainInfo', 'list_domains');
    if (!$mainDomainRes['ok']) {
        $logs[] = ['type' => 'error', 'message' => 'cPanel: Connection failed — ' . ($mainDomainRes['error'] ?? 'Unknown')];
        exit(json_encode(['success' => false, 'message' => 'Failed to connect to cPanel', 'logs' => $logs]));
    }
    if (($mainDomainRes['code'] ?? 0) === 401) {
        $logs[] = ['type' => 'error', 'message' => 'cPanel: Authentication failed — check username & API token'];
        exit(json_encode(['success' => false, 'message' => 'cPanel authentication failed', 'logs' => $logs]));
    }
    $rootDomain = tp_normalize_host_value((string) ($mainDomainRes['body']['data']['main_domain'] ?? ''));
    if (!$rootDomain) {
        $logs[] = ['type' => 'error', 'message' => 'cPanel: Failed to get main domain'];
        exit(json_encode(['success' => false, 'message' => 'Failed to get cPanel main domain', 'logs' => $logs]));
    }

    // Helper to detect "already exists" in the error string
    $isAlready = function (string $err): bool {
        return stripos($err, 'already exists') !== false
            || stripos($err, 'already been') !== false
            || stripos($err, 'exist') !== false;
    };

    // DB insert helper (skip if the record already exists)
    $saveToDb = function () use ($domain, $domainId, &$logs) {
        $conn = dbConnect();
        if (!$conn) {
            return;
        }
        ensureAddondomainTable($conn);
        try {
            $chk = $conn->prepare('SELECT id FROM addondomain WHERE domain = ? LIMIT 1');
            $chk->execute([$domain]);
            if (!$chk->fetch()) {
                $ins = $conn->prepare('INSERT INTO addondomain (sub_domain, domain_id, domain) VALUES (?, ?, ?)');
                $ins->execute(['', $domainId, $domain]);
                $logs[] = ['type' => 'success', 'message' => "DB: {$domain} saved (owner: {$domainId})"];
            }
        } catch (PDOException $e) {
            $logs[] = ['type' => 'warning', 'message' => 'DB: ' . $e->getMessage()];
        }
    };

    // ---- Step 1a: Park domain.com ----
    $logs[] = ['type' => 'step', 'message' => "STEP 1a: Registering {$domain} in cPanel (Parked Domain)..."];
    $parkRes = cpanelApi2Request($config, 'Park', 'park', ['domain' => $domain]);
    if (($parkRes['body']['status'] ?? 0) == 1) {
        $logs[] = ['type' => 'success', 'message' => "cPanel: {$domain} registered successfully"];
    } else {
        $parkErr = cpanelErrStr($parkRes);
        $parkTimedOut = stripos($parkErr, 'timed out') !== false || stripos($parkErr, 'timeout') !== false;
        if ($isAlready($parkErr)) {
            $logs[] = ['type' => 'warning', 'message' => "cPanel: {$domain} already registered, continuing..."];
        } elseif ($parkTimedOut) {
            // cPanel may have completed the operation server-side despite our timeout; continue
            $logs[] = ['type' => 'warning', 'message' => "cPanel: Park request timed out — may have succeeded, continuing..."];
        } else {
            $logs[] = ['type' => 'error', 'message' => "cPanel Park Error: {$parkErr}"];
            $overallSuccess = false;
        }
    }

    // ---- Step 1b: Wildcard *.domain.com ----
    $logs[] = ['type' => 'step', 'message' => "STEP 1b: Creating wildcard *.{$domain} → /{$wildcardDir}..."];
    $wcArgs = ['domain' => '*', 'rootdomain' => $domain, 'dir' => ltrim($wildcardDir, '/'), 'disallowdot' => '0'];
    $wcRes  = cpanelRequest($config, 'SubDomain', 'addsubdomain', $wcArgs);
    if (($wcRes['body']['status'] ?? 0) == 1) {
        $logs[] = ['type' => 'success', 'message' => "cPanel: Wildcard *.{$domain} created successfully → /{$wildcardDir}"];
        $saveToDb();
    } else {
        $wcErr = cpanelErrStr($wcRes);
        if ($isAlready($wcErr)) {
            $logs[] = ['type' => 'warning', 'message' => "cPanel: Wildcard *.{$domain} already exists, continuing..."];
            $saveToDb();
        } else {
            $logs[] = ['type' => 'error', 'message' => "cPanel Wildcard Error: {$wcErr}"];
            $overallSuccess = false;
        }
    }

    $zoneNs      = [];
    $zoneCreated = false;

    // ---- Step 2: Cloudflare DNS (zone template) ----
    //
    // Template:
    //   @ IN A     ip          ; proxied
    //   www IN CNAME domain.   ; proxied
    //   * IN A     ip          ; proxied
    //   @ IN MX    0 .         ; null MX
    //   @ IN TXT   "v=spf1 -all"
    //   _dmarc IN TXT "v=DMARC1; p=reject; ..."
    // --------------------------------------------------
    $anyDns = $addDnsA || $addWww || $addWildcard || $addMxNull || $addSpf || $addDmarc;

    if (!$cfEnabled) {
        // cPanel-only fallback — no CF zone to create, but we still
        // want to tell the user which nameservers to point the
        // registrar at. These come from the cPanel server itself.
        $logs[] = ['type' => 'step', 'message' => 'STEP 2: Auto-detecting cPanel nameservers (Cloudflare flow skipped)...'];

        $nsResult = resolveCpanelNameservers($config, $rootDomain);
        $zoneNs   = $nsResult['nameservers'] ?? [];
        $nsMethod = $nsResult['method']      ?? '';
        $nsSourceKey = $nsResult['source']   ?? 'none';

        if (!empty($zoneNs)) {
            $nsStr = implode('  •  ', $zoneNs);
            if ($nsMethod !== '') {
                $logs[] = ['type' => 'info', 'message' => "Auto-detected via: {$nsMethod}"];
            }
            $logs[] = ['type' => 'success', 'message' => "cPanel nameservers: {$nsStr}"];
            $logs[] = ['type' => 'warning', 'message' => "‼ Point {$domain} at the registrar to -> {$nsStr}"];
        } else {
            $logs[] = ['type' => 'warning', 'message' => "cPanel nameservers could not be auto-detected — set CPANEL_NAMESERVERS in .env or cpanel_nameservers in admin settings"];
        }
    } elseif (!$anyDns) {
        $logs[] = ['type' => 'info', 'message' => 'All DNS options disabled — Cloudflare DNS skipped'];
    } elseif (!$serverIp && ($addDnsA || $addWildcard)) {
        $logs[] = ['type' => 'warning', 'message' => 'Server IP not set — A/wildcard records skipped'];
    } else {
        $logs[] = ['type' => 'step', 'message' => "STEP 2: Adding domain to Cloudflare & configuring DNS..."];

        // Find or create CF zone for this domain
        $zoneResult = findOrCreateCfZone($config, $domain);
        if (!$zoneResult['ok']) {
            // CF failed → warning only, cPanel already succeeded
            $logs[] = ['type' => 'warning', 'message' => 'Cloudflare Zone failed (' . ($zoneResult['error'] ?? 'unknown') . ') — domain still active via cPanel'];
        } else {
            $zoneId      = $zoneResult['zone_id'];
            $zoneCreated = $zoneResult['created'] ?? false;
            $zoneStatus  = $zoneResult['status']  ?? 'unknown';
            $zoneNs      = $zoneResult['nameservers'] ?? [];

            if ($zoneCreated) {
                $logs[] = ['type' => 'success', 'message' => "New CF zone created for {$domain} (status: {$zoneStatus})"];
            } else {
                $logs[] = ['type' => 'info', 'message' => "CF zone found for {$domain} (status: {$zoneStatus})"];
            }
            $logs[] = ['type' => 'info', 'message' => "Zone ID: {$zoneId}"];

            // Log nameservers - the user must update NS at the registrar
            if (!empty($zoneNs)) {
                $nsStr = implode('  •  ', $zoneNs);
                if ($zoneCreated) {
                    $logs[] = ['type' => 'warning', 'message' => "‼ Update NS at the registrar -> {$nsStr}"];
                } else {
                    $logs[] = ['type' => 'info',    'message' => "Nameserver CF: {$nsStr}"];
                }
            }

            if ($addDnsA && $serverIp) {
                $r = addDnsRecord($config, $zoneId, 'A', $domain, $serverIp, $proxied, $skipExisting);
                logDnsResult($r, 'A @', $logs, $overallSuccess);
            }
            if ($addWww) {
                $r = addDnsRecord($config, $zoneId, 'CNAME', 'www.' . $domain, $domain, $proxied, $skipExisting);
                logDnsResult($r, 'CNAME www', $logs, $overallSuccess);
            }
            if ($addWildcard && $serverIp) {
                addWildcardDnsRecord($config, $zoneId, $domain, $serverIp, $proxied, $skipExisting, $logs, $overallSuccess);
            }
            if ($addMxNull) {
                $r = addDnsRecord($config, $zoneId, 'MX', $domain, '.', false, $skipExisting, 0);
                logDnsResult($r, 'MX @ null', $logs, $overallSuccess);
            }
            if ($addSpf) {
                $r = addDnsRecord($config, $zoneId, 'TXT', $domain, 'v=spf1 -all', false, $skipExisting);
                logDnsResult($r, 'TXT SPF', $logs, $overallSuccess);
            }
            if ($addDmarc) {
                $r = addDnsRecord($config, $zoneId, 'TXT', '_dmarc.' . $domain, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100', false, $skipExisting);
                logDnsResult($r, 'TXT DMARC', $logs, $overallSuccess);
            }
        }
    }

    // ---- Step 3: Cloudflare Security & Speed Settings ----
    $anyCfSetting = $cfUnderAttack || $cfPageShield || $cfBotFight || $cfLeakedCreds || $cfWaf
        || $cfAlwaysOnline || $cfCacheAggressive || $cfBrowserCacheTtl
        || $cfSpeedMinify || $cfSpeedRocket || $cfSpeedHints
        || $cfSpeedHttp2  || $cfSpeedBrotli
        || $cfHsts || $cfResponseHeaders || $cfSmartShield
        || $cfDmarcMgmt || $cfCustomSkipId || $cfAuditProxyLeaks;

    if ($anyCfSetting && $cfEnabled) {
        // Need the zone_id - fetch it if Step 2 was skipped (all DNS off)
        if (empty($zoneId)) {
            $zr = findOrCreateCfZone($config, $domain);
            if (!$zr['ok']) {
                // CF failed → skip step 3, don't block cPanel success
                $logs[] = ['type' => 'warning', 'message' => 'Step 3 skip: CF zone not available — ' . ($zr['error'] ?? 'unknown')];
                goto cf_done;
            }
            $zoneId = $zr['zone_id'];
            if ($zr['created'] ?? false) {
                $zoneNs      = $zr['nameservers'] ?? [];
                $zoneCreated = true;
                $logs[] = ['type' => 'success', 'message' => "New CF zone created for {$domain}"];
                if (!empty($zoneNs)) {
                    $logs[] = ['type' => 'warning', 'message' => '‼ Update NS at the registrar -> ' . implode('  •  ', $zoneNs)];
                }
            }
        }

        $logs[] = ['type' => 'step', 'message' => "STEP 3: Activating Cloudflare Security & Speed..."];
        applyCfSecuritySpeed($config, $zoneId, $logs, [
            // ── SSL / TLS ─────────────────────────────────────
            'ssl'                      => $cfSsl,
            'always_use_https'         => $cfAlwaysUseHttps,
            'automatic_https_rewrites' => $cfAutoHttpsRewrites,
            'opportunistic_encryption' => $cfOpportunisticEnc,
            'opportunistic_onion'      => $cfOpportunisticOnion,
            'min_tls_version'          => $cfMinTlsVersion,
            'tls_1_3'                  => $cfTls13,
            // ── Security settings ─────────────────────────────
            'under_attack'             => $cfUnderAttack,
            'security_level_medium'    => $cfSecurityLevelMedium,
            'browser_check'            => $cfBrowserCheck,
            'challenge_ttl'            => $cfChallengeTtl,
            'email_obfuscation'        => $cfEmailObfuscation,
            'server_side_exclude'      => $cfServerSideExclude,
            'hotlink_protection'       => $cfHotlinkProtection,
            'ip_geolocation'           => $cfIpGeolocation,
            'privacy_pass'             => $cfPrivacyPass,
            // ── Advanced security ─────────────────────────────
            'page_shield'              => $cfPageShield,
            'bot_fight'                => $cfBotFight,
            'leaked_creds'             => $cfLeakedCreds,
            'waf'                      => $cfWaf,
            'hsts'                     => $cfHsts,
            'response_headers'         => $cfResponseHeaders,
            'smart_shield'             => $cfSmartShield,
            'dmarc_mgmt'               => $cfDmarcMgmt,
            'custom_skip_id'           => $cfCustomSkipId,
            // ── Cache ─────────────────────────────────────────
            'always_online'            => $cfAlwaysOnline,
            'cache_aggressive'         => $cfCacheAggressive,
            'browser_cache_ttl'        => $cfBrowserCacheTtl,
            // ── Performance ───────────────────────────────────
            'http2'                    => $cfSpeedHttp2,
            'brotli'                   => $cfSpeedBrotli,
            'early_hints'              => $cfSpeedHints,
            'minify'                   => $cfSpeedMinify,
            'websockets'               => $cfWebsockets,
            'prefetch_preload'         => $cfPrefetchPreload,
            'speed_brain'              => $cfSpeedBrain,
            'fonts'                    => $cfFonts,
            'rocket'                   => $cfSpeedRocket,
        ]);

        if ($cfAuditProxyLeaks && !empty($zoneId)) {
            $logs[] = ['type' => 'step', 'message' => 'STEP 4: Auditing DNS proxy leaks...'];
            $audit = auditAndFixProxyLeaks($config, $zoneId, $logs);
            $checked = (int) ($audit['checked'] ?? 0);
            $fixedCount = is_array($audit['fixed'] ?? null) ? count($audit['fixed']) : 0;
            $unfixableCount = is_array($audit['unfixable'] ?? null) ? count($audit['unfixable']) : 0;
            $logs[] = [
                'type' => 'success',
                'message' => "Proxy-leak audit: checked {$checked}, flipped {$fixedCount}, kept {$unfixableCount} as-is",
            ];
        }
    } elseif (!$cfEnabled) {
        $logs[] = ['type' => 'info', 'message' => 'STEP 3 skipped — Cloudflare not configured (cPanel-only fallback)'];
    }

    cf_done:
    // ---- Summary ----
    $responseNs      = $zoneNs;
    $responseCreated = $zoneCreated;
    $nsSource        = $cfEnabled ? 'cloudflare' : 'cpanel';
    $responseBase    = [
        'logs'            => $logs,
        'nameservers'     => $responseNs,
        'zone_created'    => $responseCreated,
        'domain'          => $domain,
        'ns_source'       => $nsSource,
        'ns_detect_key'   => $cfEnabled ? '' : ($nsSourceKey ?? 'none'),
        'ns_detect_label' => $cfEnabled ? '' : ($nsMethod ?? ''),
        'cf_enabled'      => $cfEnabled,
    ];
    if ($overallSuccess) {
        $logs[] = ['type' => 'success', 'message' => "Done! Domain {$domain} has been successfully configured."];
        $responseBase['logs'] = $logs;
        if (function_exists('tp_apcu_store')) {
            tp_apcu_store('tp_dashboard_version', time());
        }
        exit(json_encode(['success' => true, 'message' => "Domain {$domain} added successfully!"] + $responseBase));
    } else {
        $logs[] = ['type' => 'error', 'message' => "Process completed with some errors. Check the log above."];
        $responseBase['logs'] = $logs;
        exit(json_encode(['success' => false, 'message' => 'Process completed with errors'] + $responseBase));
    }
}

// ============================================================
// ACTION: Create cPanel User
// ============================================================
if ($action === 'create_cpanel_user') {
    $username = trim($data['username'] ?? '');
    $password = $data['password']      ?? '';

    if ($username === '' || $password === '') {
        exit(json_encode(['success' => false, 'message' => 'Username and password are required']));
    }
    if (!preg_match('/^[a-z][a-z0-9_]{1,31}$/', $username)) {
        exit(json_encode(['success' => false, 'message' => 'Invalid username (lowercase letters/digits/underscore, 2–32 characters, starting with a letter)']));
    }
    if (strlen($password) < 5) {
        exit(json_encode(['success' => false, 'message' => 'Password must be at least 5 characters']));
    }

    $userDomain = resolveCpanelUserDomain($config);
    if (!($userDomain['ok'] ?? false)) {
        exit(json_encode(['success' => false, 'message' => $userDomain['message'] ?? 'Failed to determine the cPanel account domain']));
    }

    $res = cpanelRequest($config, 'UserManager', 'create_user', [
        'username' => $username,
        'password' => $password,
        'domain'   => $userDomain['domain'],
    ]);

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'cPanel connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (!($res['body']['status'] ?? false)) {
        $err = cpanelErrStr($res);
        exit(json_encode(['success' => false, 'message' => $err ?: 'Failed to create user']));
    }

    syncAppUser($username, $password);
    exit(json_encode(['success' => true, 'message' => "User '{$username}' created successfully"]));
}

// ============================================================
// ACTION: List cPanel Users
// ============================================================
if ($action === 'list_cpanel_users') {
    $res = cpanelRequest($config, 'UserManager', 'list_users');

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'cPanel connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (!($res['body']['status'] ?? false)) {
        $err = cpanelErrStr($res);
        exit(json_encode(['success' => false, 'message' => $err ?: 'Failed to fetch user list']));
    }

    $users   = [];
    $seen    = [];
    foreach (($res['body']['data'] ?? []) as $u) {
        $username = $u['username'] ?? '';
        $type     = $u['type']     ?? 'sub';
        if ($username === '') {
            continue;
        }
        // Skip cPanel main account and any service-account entries
        // (email/ftp/webdisk/service/cpanel) so the list only shows real sub-accounts.
        if (in_array(strtolower($type), ['cpanel', 'service', 'email', 'ftp', 'webdisk'], true)) {
            continue;
        }
        // Dedup in case cPanel returns the same sub-account multiple times.
        if (isset($seen[$username])) {
            continue;
        }
        $seen[$username] = true;
        $users[] = [
            'username' => $username,
            'type'     => $type,
        ];
    }

    exit(json_encode(['success' => true, 'users' => $users]));
}

// ============================================================
// ACTION: Reset cPanel User Password
// ============================================================
if ($action === 'reset_cpanel_password') {
    $username = trim($data['username'] ?? '');
    $password = $data['password']      ?? '';

    if ($username === '' || $password === '') {
        exit(json_encode(['success' => false, 'message' => 'Username and new password are required']));
    }
    if (strlen($password) < 5) {
        exit(json_encode(['success' => false, 'message' => 'Password must be at least 5 characters']));
    }

    $sub = lookupCpanelSubaccount($config, $username);
    if (!($sub['ok'] ?? false)) {
        exit(json_encode(['success' => false, 'message' => $sub['message'] ?? 'User not found']));
    }

    $domain = $sub['domain'] !== '' ? $sub['domain'] : resolveCpanelUserDomain($config)['domain'] ?? '';

    $res = cpanelRequest($config, 'UserManager', 'change_password', [
        'username' => $username,
        'domain'   => $domain,
        'password' => $password,
    ]);

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'cPanel connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (!($res['body']['status'] ?? false)) {
        $err = cpanelErrStr($res);
        exit(json_encode(['success' => false, 'message' => $err ?: 'Failed to reset password']));
    }

    syncAppUser($username, $password);
    exit(json_encode(['success' => true, 'message' => "Password for user '{$username}' reset successfully"]));
}

// ============================================================
// ACTION: Delete cPanel User
// ============================================================
if ($action === 'delete_cpanel_user') {
    $username = trim($data['username'] ?? '');

    if ($username === '') {
        exit(json_encode(['success' => false, 'message' => 'Username is required']));
    }

    $sub = lookupCpanelSubaccount($config, $username);
    if (!($sub['ok'] ?? false)) {
        exit(json_encode(['success' => false, 'message' => $sub['message'] ?? 'User not found']));
    }

    $domain = $sub['domain'] !== '' ? $sub['domain'] : resolveCpanelUserDomain($config)['domain'] ?? '';

    $res = cpanelRequest($config, 'UserManager', 'delete_user', [
        'username' => $username,
        'domain'   => $domain,
    ]);

    if (!$res['ok']) {
        exit(json_encode(['success' => false, 'message' => 'cPanel connection failed: ' . ($res['error'] ?? 'Unknown')]));
    }
    if (!($res['body']['status'] ?? false)) {
        $err = cpanelErrStr($res);
        exit(json_encode(['success' => false, 'message' => $err ?: 'Failed to delete user']));
    }

    removeAppUser($username);
    exit(json_encode(['success' => true, 'message' => "User '{$username}' deleted successfully"]));
}

// ============================================================
// Smartlink helpers
// ============================================================
function ensureSmartlinksTable(PDO $conn): void
{
    $isSqlite = $conn->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    if ($isSqlite) {
        $conn->exec("CREATE TABLE IF NOT EXISTS smartlinks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            country    TEXT NOT NULL DEFAULT 'all',
            device     TEXT NOT NULL DEFAULT 'all',
            network    TEXT NOT NULL DEFAULT 'direct',
            url        TEXT NOT NULL,
            params     TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )");
        // Migration: add params column if missing
        try {
            $conn->exec("ALTER TABLE smartlinks ADD COLUMN params TEXT NOT NULL DEFAULT ''");
        } catch (PDOException $e) {
        }
    } else {
        $conn->exec("CREATE TABLE IF NOT EXISTS smartlinks (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            country    TEXT         NOT NULL,
            device     VARCHAR(10)  NOT NULL DEFAULT 'both',
            network    VARCHAR(50)  NOT NULL DEFAULT 'direct',
            url        TEXT         NOT NULL,
            params     TEXT         NOT NULL DEFAULT '',
            created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try {
            $conn->exec("ALTER TABLE smartlinks MODIFY COLUMN country TEXT NOT NULL");
        } catch (PDOException $e) {
        }
        // Migration: add params column if missing
        try {
            $conn->exec("ALTER TABLE smartlinks ADD COLUMN params TEXT NOT NULL DEFAULT ''");
        } catch (PDOException $e) {
        }
    }
}

$validDevices  = ['all', 'mobile', 'desktop'];
$validNetworks = ['direct', 'fb', 'google', 'organic', 'tiktok']; // traffic source; custom alphanumeric also allowed

function normalizeCountries(string $raw): string
{
    $raw = trim($raw);
    if ($raw === '' || strtolower($raw) === 'all') {
        return 'all';
    }
    $parts = array_values(array_unique(array_filter(array_map(
        function ($p) {
            return strtoupper(preg_replace('/[^A-Za-z]/', '', trim($p)));
        },
        explode(',', $raw)
    ))));
    if (empty($parts) || in_array('ALL', $parts, true)) {
        return 'all';
    }
    return implode(',', $parts);
}

// ── Helper: Validate & parse smartlink fields from $data ──
// Removes exact duplication in create_link and update_link
/**
 * @param array<string, mixed> $data
 * @param array<int, string> $validDevices
 * @param array<int, string> $validNetworks
 * @return array<string, mixed>
 */
function parseSmartlinkFields(array $data, array $validDevices, array $validNetworks): array
{
    $country = normalizeCountries($data['country'] ?? 'all');
    $device  = trim($data['device']  ?? 'all');
    $network = trim($data['network'] ?? 'direct');
    $url     = trim($data['url']     ?? '');
    $params  = trim($data['params']  ?? '');

    if (!in_array($device, $validDevices, true)) {
        return ['error' => 'Invalid device'];
    }
    if (!in_array($network, $validNetworks, true) && !preg_match('/^[a-z0-9_\-]{1,50}$/i', $network)) {
        return ['error' => 'Invalid network name'];
    }
    if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
        return ['error' => 'Invalid URL'];
    }
    // params: allow query-string characters + placeholder tokens {…} and <…>
    if ($params !== '' && !preg_match('/^[A-Za-z0-9%_.~:@!$&\'()*+,;=\-\[\]{}|<>\/?#]+$/', $params)) {
        return ['error' => 'Invalid params — use standard query-string characters'];
    }

    return compact('country', 'device', 'network', 'url', 'params');
}

// ============================================================
// ACTION: List Smartlinks
// ============================================================
if ($action === 'list_smartlinks') {
    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'smartlinks' => [], 'message' => 'DB not connected']));
    }
    ensureSmartlinksTable($conn);
    $rows = $conn->query('SELECT id, country, device, network, url, params FROM smartlinks ORDER BY id DESC')->fetchAll();
    exit(json_encode(['success' => true, 'smartlinks' => $rows]));
}

// ============================================================
// ACTION: Create Smartlink
// ============================================================
if ($action === 'create_smartlink') {
    $fields = parseSmartlinkFields($data, $validDevices, $validNetworks);
    if (isset($fields['error'])) {
        exit(json_encode(['success' => false, 'message' => $fields['error']]));
    }

    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'message' => 'DB not connected']));
    }
    ensureSmartlinksTable($conn);

    $stmt = $conn->prepare('INSERT INTO smartlinks (country, device, network, url, params) VALUES (?,?,?,?,?)');
    $stmt->execute([$fields['country'], $fields['device'], $fields['network'], $fields['url'], $fields['params']]);
    exit(json_encode(['success' => true, 'message' => 'Smartlink saved successfully', 'id' => (int)$conn->lastInsertId()]));
}

// ============================================================
// ACTION: Update Smartlink
// ============================================================
if ($action === 'update_smartlink') {
    $id = intval($data['id'] ?? 0);
    if (!$id) {
        exit(json_encode(['success' => false, 'message' => 'Invalid ID']));
    }

    $fields = parseSmartlinkFields($data, $validDevices, $validNetworks);
    if (isset($fields['error'])) {
        exit(json_encode(['success' => false, 'message' => $fields['error']]));
    }

    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'message' => 'DB not connected']));
    }
    ensureSmartlinksTable($conn);

    $stmt = $conn->prepare('UPDATE smartlinks SET country=?, device=?, network=?, url=?, params=? WHERE id=?');
    $stmt->execute([$fields['country'], $fields['device'], $fields['network'], $fields['url'], $fields['params'], $id]);
    exit(json_encode(['success' => true, 'message' => 'Smartlink updated successfully']));
}

// ============================================================
// ACTION: Delete Smartlink
// ============================================================
if ($action === 'delete_smartlink') {
    $id = intval($data['id'] ?? 0);
    if (!$id) {
        exit(json_encode(['success' => false, 'message' => 'Invalid ID']));
    }

    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'message' => 'DB not connected']));
    }
    ensureSmartlinksTable($conn);

    $conn->prepare('DELETE FROM smartlinks WHERE id=?')->execute([$id]);
    exit(json_encode(['success' => true, 'message' => 'Smartlink deleted successfully']));
}

// ── ACTION: List Global Domains ───────────────────────────────
if ($action === 'list_global_domains') {
    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'data' => []]));
    }
    try {
        $rows = $conn->query('SELECT id, domain, created_at FROM user_domains WHERE user_id = 0 ORDER BY id DESC')->fetchAll();
        exit(json_encode(['success' => true, 'data' => $rows]));
    } catch (PDOException $e) {
        exit(json_encode(['success' => false, 'data' => [], 'message' => $e->getMessage()]));
    }
}

// ── ACTION: Add Global Domain ─────────────────────────────────
if ($action === 'add_global_domain') {
    $domain = strtolower(trim($data['domain'] ?? ''));
    if (!$domain) {
        exit(json_encode(['success' => false, 'message' => 'Domain cannot be empty']));
    }

    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'message' => 'DB not connected']));
    }

    try {
        // Check for duplicate
        $chk = $conn->prepare('SELECT id FROM user_domains WHERE domain = ? AND user_id = 0 LIMIT 1');
        $chk->execute([$domain]);
        if ($chk->fetch()) {
            exit(json_encode(['success' => false, 'message' => 'Domain already exists in the global list']));
        }

        $conn->prepare('INSERT INTO user_domains (user_id, domain) VALUES (0, ?)')->execute([$domain]);
        $newId = $conn->lastInsertId();
        exit(json_encode(['success' => true, 'data' => ['id' => (int)$newId, 'domain' => $domain, 'user_id' => 0]]));
    } catch (PDOException $e) {
        exit(json_encode(['success' => false, 'message' => 'Failed to save domain']));
    }
}

// ── ACTION: Delete Global Domain ──────────────────────────────
if ($action === 'delete_global_domain') {
    $id = intval($data['id'] ?? 0);
    if (!$id) {
        exit(json_encode(['success' => false, 'message' => 'Invalid ID']));
    }

    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'message' => 'DB not connected']));
    }

    try {
        $conn->prepare('DELETE FROM user_domains WHERE id = ? AND user_id = 0')->execute([$id]);
        exit(json_encode(['success' => true]));
    } catch (PDOException $e) {
        exit(json_encode(['success' => false, 'message' => 'Failed to delete domain']));
    }
}

// ── ACTION: List Redirect Decision Audit ──────────────────────
// Returns the latest N rows from `redirect_decision_audit_log` so the
// admin dashboard can surface why specific visitors were routed to the
// filter URL vs the smartlink target. Supports:
//   - `limit`   : rows to return (default 100, max 500)
//   - `slug`    : filter to a single shortlink
//   - `since`   : minimum created_at_unix timestamp
//   - `decision`: filter by decision label (e.g. 'redirect_url', 'normal')
// Admin-only endpoint — relies on handler.php's session/app-token guard
// at the top of the file.
if ($action === 'list_decision_audit') {
    $conn = dbConnect();
    if (!$conn) {
        exit(json_encode(['success' => false, 'rows' => [], 'message' => 'DB not connected']));
    }

    $limit = (int) ($data['limit'] ?? 100);
    if ($limit < 1) {
        $limit = 100;
    }
    if ($limit > 500) {
        $limit = 500;
    }
    $slugFilter = trim((string) ($data['slug'] ?? ''));
    if ($slugFilter !== '' && !preg_match('/^[a-zA-Z0-9_-]{1,30}$/', $slugFilter)) {
        $slugFilter = '';
    }
    $since = (int) ($data['since'] ?? 0);
    $decisionFilter = trim((string) ($data['decision'] ?? ''));
    if ($decisionFilter !== '' && !preg_match('/^[a-z_]{1,32}$/', $decisionFilter)) {
        $decisionFilter = '';
    }

    $where  = [];
    $params = [];
    if ($slugFilter !== '') {
        $where[]  = 'slug = ?';
        $params[] = $slugFilter;
    }
    if ($since > 0) {
        $where[]  = 'created_at_unix >= ?';
        $params[] = $since;
    }
    if ($decisionFilter !== '') {
        $where[]  = 'decision = ?';
        $params[] = $decisionFilter;
    }
    $whereSql = $where === [] ? '' : ' WHERE ' . implode(' AND ', $where);

    try {
        $sql = 'SELECT id, created_at_unix, link_id, slug, decision, primary_reason,
                       window_mode, delivery_outcome, country_code, device,
                       visitor_network, is_vpn_like, is_bot, profile_country_code,
                       profile_asn, profile_organization, target_host, redirect_host
                FROM redirect_decision_audit_log'
              . $whereSql .
              ' ORDER BY id DESC LIMIT ' . $limit;
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (PDOException $e) {
        // Likely table doesn't exist yet — return empty so the UI shows
        // "no data" instead of an error banner.
        $rows = [];
    }

    // Best-effort health counter from APCu (populated by go.php on
    // RedirectDecision catch block — see #7).
    $redirectDecisionErrors = 0;
    if (function_exists('tp_apcu_fetch')) {
        $raw = tp_apcu_fetch('redirect_decision_errors');
        if (is_int($raw)) {
            $redirectDecisionErrors = $raw;
        }
    }

    exit(json_encode([
        'success'                  => true,
        'rows'                     => $rows,
        'count'                    => count($rows),
        'redirect_decision_errors' => $redirectDecisionErrors,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

// ── Reset the redirect_decision_errors APCu counter ─────────────
// Called from the Decision Audit card in the System tab when the
// operator has acknowledged and investigated the current error spike.
// Resetting is a no-op if APCu is unavailable.
if ($action === 'reset_decision_audit_errors') {
    $reset = false;
    if (function_exists('tp_apcu_delete')) {
        tp_apcu_delete('redirect_decision_errors');
        $reset = true;
    } elseif (function_exists('apcu_delete')) {
        @apcu_delete('redirect_decision_errors');
        $reset = true;
    }

    exit(json_encode([
        'success' => $reset,
        'message' => $reset ? 'Counter reset.' : 'APCu unavailable.',
    ], JSON_UNESCAPED_SLASHES));
}

if ($action === 'get_redirect_engine_config') {
    loadRedirectDecisionBootstrap();
    $configPayload = redirectDecisionPayload(RedirectDecision::loadConfig());

    exit(json_encode([
        'success' => true,
        'config' => $configPayload['config'],
        'window' => $configPayload['window'],
        'health' => $configPayload['health'],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

if ($action === 'save_redirect_engine_config') {
    loadRedirectDecisionBootstrap();
    $submittedConfig = is_array($data['config'] ?? null) ? $data['config'] : [];

    try {
        $savedConfig = RedirectDecision::saveConfig($submittedConfig);
        touchDashboardVersion();
        $configPayload = redirectDecisionPayload($savedConfig);

        exit(json_encode([
            'success' => true,
            'message' => 'Redirect engine configuration saved.',
            'config' => $configPayload['config'],
            'window' => $configPayload['window'],
            'health' => $configPayload['health'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    } catch (Throwable $e) {
        exit(json_encode([
            'success' => false,
            'message' => 'Failed to save redirect engine configuration.',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}

if ($action === 'reset_redirect_engine_cycle') {
    loadRedirectDecisionBootstrap();
    $submittedConfig = is_array($data['config'] ?? null) ? $data['config'] : RedirectDecision::loadConfig();

    try {
        $savedConfig = RedirectDecision::resetCycle($submittedConfig);
        touchDashboardVersion();
        $configPayload = redirectDecisionPayload($savedConfig);

        exit(json_encode([
            'success' => true,
            'message' => 'Redirect engine cycle reset.',
            'config' => $configPayload['config'],
            'window' => $configPayload['window'],
            'health' => $configPayload['health'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    } catch (Throwable $e) {
        exit(json_encode([
            'success' => false,
            'message' => 'Failed to reset redirect engine cycle.',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}

if ($action === 'preview_redirect_engine') {
    loadRedirectDecisionBootstrap();
    $submittedConfig = is_array($data['config'] ?? null) ? $data['config'] : [];
    $context = is_array($data['context'] ?? null) ? $data['context'] : [];
    $config = RedirectDecision::normalizeConfig($submittedConfig, RedirectDecision::loadConfig());
    $result = RedirectDecision::evaluate($config, $context);

    exit(json_encode([
        'success' => true,
        'result' => $result,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

// ── Lightweight broadcast version check ─────────────────────────
// Returns the current shared APCu version counter so clients can
// detect state changes without fetching the full payload.
$v = 0;
if (function_exists('tp_apcu_fetch')) {
    $raw = tp_apcu_fetch('tp_dashboard_version');
    if (is_int($raw) || is_float($raw)) {
        $v = (int) $raw;
    }
}
exit(json_encode(['success' => true, 'version' => $v], JSON_UNESCAPED_SLASHES));
