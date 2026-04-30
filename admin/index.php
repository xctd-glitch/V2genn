<?php

declare(strict_types=1);

function requestMethod(): string
{
    $method = $_SERVER['REQUEST_METHOD'] ?? null;

    if (!is_string($method) || $method === '') {
        return 'CLI';
    }

    return strtoupper($method);
}

require_once __DIR__ . '/../bootstrap/security_bootstrap.php';
require_once __DIR__ . '/../bootstrap/host_utils.php';
require_once __DIR__ . '/../bootstrap/admin_auth.php';

tp_runtime_harden();
tp_secure_session_bootstrap();
session_start();
tp_send_security_headers();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

$requestMethod = requestMethod();

$nonceAttr = tp_csp_nonce_attr();
$csrfToken = tp_csrf_token();

// ── Logout ──
if ($requestMethod === 'POST' && isset($_POST['_logout'])) {
    if (!tp_is_valid_csrf_token((string) ($_POST['csrf_token'] ?? ''))) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    tp_destroy_session();
    header('Location: /');
    exit;
}

if ($requestMethod === 'GET' && isset($_GET['ajax']) && $_GET['ajax'] === 'csrf_token') {
    header('Content-Type: application/json');

    if (empty($_SESSION['dashboard_auth'])) {
        http_response_code(401);
        exit(json_encode(['success' => false, 'message' => 'Unauthorized']));
    }

    exit(json_encode([
        'success' => true,
        'csrf_token' => tp_csrf_token(),
    ]));
}

// ── Load .env file into getenv() ──
// (called early so ADMIN_USER and DB settings are available)
tp_load_env_file(__DIR__ . '/../.env');

function dashboardScheme(): string
{
    return tp_is_https() ? 'https' : 'http';
}

function dashboardHost(): string
{
    return tp_request_host();
}

function dashboardWildcardBaseHost(): string
{
    $configuredHost = tp_normalize_host_value((string) getenv('CPANEL_DOMAIN'));
    if ($configuredHost !== '') {
        return $configuredHost;
    }

    return preg_replace('/^www\./i', '', dashboardHost()) ?? dashboardHost();
}

/** @param array<string, mixed> $savedConfig */
function dashboardPublicBaseUrl(array $savedConfig): string
{
    $configuredHost = tp_normalize_host_value((string) getenv('CPANEL_DOMAIN'));
    if ($configuredHost === '') {
        $configuredHost = dashboardSavedConfigValue($savedConfig, 'cpanel_domain');
    }

    return tp_public_base_url($configuredHost);
}

/** @param array<string, mixed> $savedConfig */
function dashboardSavedConfigValue(array $savedConfig, string $key): string
{
    $value = $savedConfig[$key] ?? null;

    return is_string($value) ? trim($value) : '';
}

/**
 * @param array<string, mixed> $savedConfig
 * @return array<int, string>
 */
function dashboardWildcardWarnings(array $savedConfig): array
{
    $warnings = [];
    $configuredHost = tp_normalize_host_value((string) getenv('CPANEL_DOMAIN'));
    $wildcardBaseHost = dashboardWildcardBaseHost();

    if ($configuredHost === '') {
        $warnings[] = 'CPANEL_DOMAIN is not configured. User dashboard links are falling back to the current admin host, which often breaks wildcard logins behind tunnels, proxies, or alternate hostnames.';
    }

    if (!tp_is_public_domain_host($wildcardBaseHost)) {
        $warnings[] = 'The wildcard dashboard base host must be a public domain such as example.com. IP addresses and single-label hosts will not resolve for {username}.domain logins.';
    }

    $wildcardDir = trim((string) getenv('WILDCARD_DIR'));
    if ($wildcardDir === '') {
        $wildcardDir = dashboardSavedConfigValue($savedConfig, 'wildcard_dir');
    }
    if ($wildcardDir === '') {
        $warnings[] = 'WILDCARD_DIR is not configured. cPanel wildcard subdomains need a stable docroot before user dashboard hosts can be published reliably.';
    }

    return array_values(array_unique($warnings));
}

$configFile  = __DIR__ . '/../data/config.json';
$savedConfig = [];
if (file_exists($configFile)) {
    $savedConfig = json_decode(file_get_contents($configFile), true) ?? [];
}

// ── Auto-sync: merge admin's app_users cf_* row into $savedConfig ──
// Keeps the admin dashboard UI, data/config.json, .env and the admin's
// app_users DB row in lock-step across all 4 CF fields (cf_token,
// cf_account_id, cf_zone_id, cf_proxied). If the DB row holds values
// that differ from config.json / .env, mirror them back so subsequent
// handler.php requests pick up the same config.
$dashboardAdminDbCfSynced = false;
try {
    $adminUserForSync = tp_admin_username();
    $pdoForSync       = $adminUserForSync !== '' ? tp_app_pdo() : null;
    if ($pdoForSync instanceof PDO) {
        $stmtSync = $pdoForSync->prepare(
            'SELECT cf_token, cf_account_id, cf_zone_id, cf_proxied
               FROM app_users WHERE username = ? LIMIT 1'
        );
        $stmtSync->execute([$adminUserForSync]);
        $adminDbRow = $stmtSync->fetch(PDO::FETCH_ASSOC) ?: [];

        $cfKeys        = ['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'];
        $cfEnvKeyMap   = [
            'cf_token'      => 'CF_TOKEN',
            'cf_account_id' => 'CF_ACCOUNT_ID',
            'cf_zone_id'    => 'CF_ZONE_ID',
            'cf_proxied'    => 'CF_PROXIED',
        ];
        $configChanged  = false;
        $envUpdatePairs = [];

        foreach ($cfKeys as $k) {
            $dbVal  = trim((string) ($adminDbRow[$k] ?? ''));
            if ($dbVal === '') {
                continue;
            }

            $cfgVal = trim((string) ($savedConfig[$k] ?? ''));
            if ($dbVal !== $cfgVal) {
                $savedConfig[$k] = $dbVal;
                $configChanged   = true;
            }

            $envKey = $cfEnvKeyMap[$k];
            $envVal = trim((string) (getenv($envKey) ?: ''));
            if ($dbVal !== $envVal) {
                $envUpdatePairs[$envKey] = $dbVal;
            }
        }

        // Mirror any drift back to .env in a single write.
        if (!empty($envUpdatePairs) && function_exists('tp_env_file_set')) {
            @tp_env_file_set(__DIR__ . '/../.env', $envUpdatePairs);
        }

        // Persist config.json drift. All 4 CF fields are now stored here.
        if ($configChanged) {
            @file_put_contents($configFile, json_encode($savedConfig, JSON_PRETTY_PRINT));
        }

        $dashboardAdminDbCfSynced = $configChanged || !empty($envUpdatePairs);
    }
} catch (Throwable $e) {
    // Silent — fall back to whatever config.json contains.
}

$dashboardConfig = $savedConfig;

// Detect whether the cPanel configuration comes from environment variables.
$cpanelFromEnv = !empty(getenv('CPANEL_HOST'))
              && !empty(getenv('CPANEL_USER'))
              && !empty(getenv('CPANEL_TOKEN'));
$cpanelTokenStored = !empty(getenv('CPANEL_TOKEN')) || dashboardSavedConfigValue($savedConfig, 'cpanel_token') !== '';
$cfTokenFromEnv = trim((string) (getenv('CF_TOKEN') ?: ''));
$cfTokenStored  = $cfTokenFromEnv !== '' || dashboardSavedConfigValue($savedConfig, 'cf_token') !== '';

// Remove secret fields from the browser-exposed config when env values exist.
if ($cpanelFromEnv) {
    foreach (['cpanel_host','cpanel_port','cpanel_user','cpanel_token','server_ip','base_dir','wildcard_dir'] as $k) {
        unset($savedConfig[$k]);
    }
}
unset($savedConfig['cpanel_token'], $savedConfig['cf_token']);

$dashboardWildcardBaseHost = dashboardWildcardBaseHost();
$dashboardPostbackSigned = !empty(getenv('POSTBACK_SECRET'));
$dashboardRecvUrl = dashboardPublicBaseUrl($dashboardConfig)
    . '/postback?clickid={clickid}&payout={payout}&status={status}'
    . ($dashboardPostbackSigned ? '&ts={ts}&sig={sig}' : '');
$dashboardUserUrlPattern = dashboardScheme() . '://{username}.' . $dashboardWildcardBaseHost . '/gen';
$dashboardWildcardWarnings = dashboardWildcardWarnings($dashboardConfig);

// ── Admin AJAX API (JSON POST, authenticated) ──
if ($requestMethod === 'POST' && !empty($_SESSION['dashboard_auth']) && !isset($_POST['_login'])) {
    $raw = file_get_contents('php://input', false, null, 0, 262144);
    $inp = json_decode($raw ?: '', true);
    if (is_array($inp)) {
        ob_clean();
        header('Content-Type: application/json');

        if (!tp_is_valid_csrf_token(is_string($inp['csrf_token'] ?? null) ? $inp['csrf_token'] : null)) {
            http_response_code(403);
            exit(json_encode(['success' => false, 'message' => 'Invalid CSRF token']));
        }

        $act = $inp['action'] ?? '';

        if ($act === 'logout') {
            tp_destroy_session();
            exit(json_encode(['success' => true]));
        }

        // ── System status ──
        if ($act === 'get_system_status') {
            $dbOk = false;
            $dbInfo = '';
            $apcuHitRatioPercent = 0;
            $queueDir = trim((string) getenv('POSTBACK_QUEUE_DIR'));
            if ($queueDir === '') {
                $queueDir = __DIR__ . '/../data/postback_queue';
            }
            $queueHealth = tp_postback_queue_health(
                $queueDir,
                time(),
                max(60, (int) (getenv('POSTBACK_WORKER_STALE_AFTER') ?: 900))
            );
            if (function_exists('apcu_cache_info')) {
                $cacheInfo = @apcu_cache_info(true);
                if (is_array($cacheInfo)) {
                    $hits = (int) ($cacheInfo['num_hits'] ?? 0);
                    $misses = (int) ($cacheInfo['num_misses'] ?? 0);
                    $apcuHitRatioPercent = (int) round(($hits / max(1, $hits + $misses)) * 100);
                }
            }
            try {
                $h = getenv('DB_HOST') ?: 'localhost';
                $u = getenv('DB_USER') ?: '';
                $pw = getenv('DB_PASS') ?: '';
                $n = getenv('DB_NAME') ?: '';
                if ($u && $n) {
                    $pdo = new PDO(
                        "mysql:host={$h};dbname={$n};charset=utf8mb4",
                        $u,
                        $pw,
                        tp_mysql_pdo_options([
                            PDO::ATTR_TIMEOUT => 3,
                        ])
                    );
                    $row = $pdo->query('SELECT VERSION() as v')->fetch(PDO::FETCH_ASSOC);
                    $dbOk = true;
                    $dbInfo = 'MySQL ' . ($row['v'] ?? '');
                }
            } catch (Throwable $e) {
                error_log('admin.get_system_status: ' . $e->getMessage());
                $dbInfo = 'Error: database unreachable';
            }
            exit(json_encode([
                'success'     => true,
                'db_ok'       => $dbOk,
                'db_info'     => $dbInfo,
                'apcu_ok'     => tp_apcu_enabled(),
                'apcu_hit_ratio_percent' => $apcuHitRatioPercent,
                'curl_ok'     => function_exists('curl_init'),
                'queue_depth' => (int) $queueHealth['queue_depth'],
                'queue_failed_depth' => (int) $queueHealth['failed_depth'],
                'queue_worker_ok' => !empty($queueHealth['worker_ok']),
                'queue_worker_stale' => !empty($queueHealth['worker_stale']),
                'queue_worker_running' => !empty($queueHealth['worker_running']),
                'php_ver'     => PHP_VERSION,
                'has_ixg'     => !empty(getenv('IXG_API_SECRET')),
                'has_tinyurl' => !empty(getenv('TINYURL_API_KEY')),
                'has_gsb'     => !empty(getenv('GSB_API_KEY')),
                'has_postback_secret' => !empty(getenv('POSTBACK_SECRET')),
                'ixg_secret'  => getenv('IXG_API_SECRET') ?: '',
                'ixg_url'     => getenv('IXG_API_URL') ?: '',
                'tinyurl_key' => getenv('TINYURL_API_KEY') ?: '',
                'gsb_key'     => getenv('GSB_API_KEY') ?: '',
                'recv_url'    => $dashboardRecvUrl,
                'sl_url'      => $dashboardUserUrlPattern,
                'sl_url_warnings' => $dashboardWildcardWarnings,
            ]));
        }

        // ── Save API keys to .env ──
        if ($act === 'save_api_keys') {
            $envFile = __DIR__ . '/../.env';
            $ixgUrl = is_string($inp['ixg_url'] ?? null) ? trim($inp['ixg_url']) : '';
            if ($ixgUrl !== '' && filter_var($ixgUrl, FILTER_VALIDATE_URL) === false) {
                exit(json_encode(['success' => false, 'message' => 'Invalid IXG API URL']));
            }

            $newKeys = [
                'IXG_API_SECRET'  => is_string($inp['ixg_secret'] ?? null) ? trim($inp['ixg_secret']) : '',
                'IXG_API_URL'     => $ixgUrl,
                'TINYURL_API_KEY' => is_string($inp['tinyurl_key'] ?? null) ? trim($inp['tinyurl_key']) : '',
                'GSB_API_KEY'     => is_string($inp['gsb_key'] ?? null) ? trim($inp['gsb_key']) : '',
            ];

            if (tp_env_file_set($envFile, $newKeys)) {
                exit(json_encode(['success' => true, 'message' => 'API keys saved to .env']));
            }

            exit(json_encode(['success' => false, 'message' => 'Failed to write .env — check file permissions']));
        }

        // ── Admin Analytics (all users) ──
        if ($act === 'admin_get_analytics') {
            $days  = max(1, min(365, (int)($inp['days'] ?? 30)));
            $uidF  = (int)($inp['user_id'] ?? 0);
            $where = $uidF ? 'AND sl.user_id = ?' : '';
            try {
                $h  = getenv('DB_HOST') ?: 'localhost';
                $u  = getenv('DB_USER') ?: '';
                $pw = getenv('DB_PASS') ?: '';
                $n = getenv('DB_NAME') ?: '';
                $pdo = new PDO(
                    "mysql:host={$h};dbname={$n};charset=utf8mb4",
                    $u,
                    $pw,
                    tp_mysql_pdo_options()
                );

                $p = $uidF ? [$uidF] : [];
                $st = $pdo->prepare("SELECT lh.hit_date AS d, SUM(lh.hits) AS h
                    FROM link_hits lh JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                    WHERE lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY) {$where}
                    GROUP BY lh.hit_date ORDER BY lh.hit_date ASC");
                $st->execute($p);
                $dailyMap = [];
                foreach ($st->fetchAll() as $r) {
                    $dailyMap[$r['d']] = (int)$r['h'];
                }
                $daily = [];
                for ($i = $days - 1; $i >= 0; $i--) {
                    $d = date('Y-m-d', strtotime("-{$i} days"));
                    $daily[] = ['date' => $d, 'hits' => $dailyMap[$d] ?? 0];
                }
                $total = array_sum(array_column($daily, 'hits'));

                $mk = function ($col, $alias) use ($pdo, $where, $uidF, $days) {
                    $p2 = $uidF ? [$uidF] : [];
                    $s  = $pdo->prepare("SELECT lh.{$col} AS {$alias}, SUM(lh.hits) AS hits
                        FROM link_hits lh JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                        WHERE lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY) {$where}
                        AND lh.{$col} != '' GROUP BY lh.{$col} ORDER BY hits DESC LIMIT 20");
                    $s->execute($p2);
                    return $s->fetchAll();
                };

                $p3 = $uidF ? [$uidF] : [];
                $ls = $pdo->prepare("SELECT lh.slug, sl.title, au.username, SUM(lh.hits) AS hits
                    FROM link_hits lh
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = lh.slug COLLATE utf8mb4_unicode_ci
                    JOIN app_users au ON au.id = sl.user_id
                    WHERE lh.hit_date >= DATE_SUB(CURDATE(), INTERVAL {$days} DAY) {$where}
                    GROUP BY lh.slug, sl.title, au.username ORDER BY hits DESC LIMIT 20");
                $ls->execute($p3);

                $users = $pdo->query("SELECT id, username FROM app_users ORDER BY username")->fetchAll();

                exit(json_encode(['success' => true, 'total' => $total, 'daily' => $daily,
                    'by_country' => $mk('country', 'country'), 'by_device' => $mk('device', 'device'),
                    'by_network' => $mk('network', 'network'), 'by_link' => $ls->fetchAll(), 'users' => $users]));
            } catch (Throwable $e) {
                error_log('admin.admin_get_analytics: ' . $e->getMessage());
                exit(json_encode(['success' => false, 'message' => 'Failed to load analytics.']));
            }
        }

        // ── Admin Live Feed (all users) ──
        if ($act === 'admin_get_live_feed') {
            $limit = 100;
            $after = (int)($inp['after_click'] ?? 0);
            $afterC = (int)($inp['after_conv'] ?? 0);
            $clicks = [];
            $convs = [];
            $stats = ['clicks_24h' => 0, 'conversions_24h' => 0, 'revenue_24h' => 0.0, 'cr' => 0.0];
            try {
                $h = getenv('DB_HOST') ?: 'localhost';
                $u = getenv('DB_USER') ?: '';
                $pw = getenv('DB_PASS') ?: '';
                $n = getenv('DB_NAME') ?: '';
                $pdo = new PDO(
                    "mysql:host={$h};dbname={$n};charset=utf8mb4",
                    $u,
                    $pw,
                    tp_mysql_pdo_options()
                );
                $afterSql  = $after ? "AND c.id > {$after}" : '';
                $afterCSql = $afterC ? "AND v.id > {$afterC}" : '';
                $st = $pdo->prepare("SELECT c.id, c.slug, c.clickid, c.subid, c.country, c.device, c.network, c.payout, c.ip, c.created_at, COALESCE(au.username,'—') AS username FROM clicks c LEFT JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci LEFT JOIN app_users au ON au.id = sl.user_id WHERE 1=1 {$afterSql} ORDER BY c.id DESC LIMIT {$limit}");
                $st->execute([]);
                $clicks = $st->fetchAll();
                $sv = $pdo->prepare("SELECT v.id, v.clickid, v.subid, v.slug, v.country, v.device, v.network, v.payout, v.status, v.source_ip AS ip, v.created_at, COALESCE(au.username,'—') AS username FROM conversions v LEFT JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci LEFT JOIN app_users au ON au.id = sl.user_id WHERE 1=1 {$afterCSql} AND v.subid != '' AND v.network != '' AND v.payout > 0 AND v.slug != '' AND sl.slug IS NOT NULL AND au.id IS NOT NULL ORDER BY v.id DESC LIMIT {$limit}");
                $sv->execute([]);
                $convs = $sv->fetchAll();
                $sc   = $pdo->query("SELECT COUNT(*) as n FROM clicks WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")->fetch();
                $sv2  = $pdo->query("SELECT COUNT(*) as n, COALESCE(SUM(payout),0) as rev FROM conversions WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci)")->fetch();
                $cl24 = (int)($sc['n'] ?? 0);
                $cv24 = (int)($sv2['n'] ?? 0);
                $rev24 = (float)($sv2['rev'] ?? 0);
                $stats = ['clicks_24h' => $cl24, 'conversions_24h' => $cv24, 'revenue_24h' => round($rev24, 4), 'cr' => $cl24 > 0 ? round($cv24 / $cl24 * 100, 2) : 0];
            } catch (Throwable $e) {
            }
            exit(json_encode(['success' => true, 'clicks' => $clicks, 'conversions' => $convs, 'stats' => $stats]));
        }

        // ── Admin Conv Stats (date range) ──
        if ($act === 'admin_get_conv_stats') {
            $dateFrom = preg_replace('/[^0-9\-]/', '', $inp['date_from'] ?? date('Y-m-d', strtotime('-30 days')));
            $dateTo   = preg_replace('/[^0-9\-]/', '', $inp['date_to']   ?? date('Y-m-d'));
            try {
                $h = getenv('DB_HOST') ?: 'localhost';
                $u = getenv('DB_USER') ?: '';
                $pw = getenv('DB_PASS') ?: '';
                $n = getenv('DB_NAME') ?: '';
                $pdo = new PDO(
                    "mysql:host={$h};dbname={$n};charset=utf8mb4",
                    $u,
                    $pw,
                    tp_mysql_pdo_options()
                );

                // Totals clicks
                $sc = $pdo->prepare("SELECT COUNT(*) FROM clicks WHERE DATE(created_at) BETWEEN ? AND ?");
                $sc->execute([$dateFrom, $dateTo]);
                $totalClicks = (int)$sc->fetchColumn();

                // Totals conversions + revenue
                $sv = $pdo->prepare("SELECT COUNT(*) AS n, COALESCE(SUM(payout),0) AS rev FROM conversions WHERE DATE(created_at) BETWEEN ? AND ? AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci)");
                $sv->execute([$dateFrom, $dateTo]);
                $cvRow = $sv->fetch();
                $totalConv = (int)($cvRow['n'] ?? 0);
                $totalRev  = round((float)($cvRow['rev'] ?? 0), 4);
                $cr = $totalClicks > 0 ? round($totalConv / $totalClicks * 100, 2) : 0;

                // Daily breakdown
                $d = new DateTime($dateFrom);
                $end = new DateTime($dateTo);
                $dateList = [];
                while ($d <= $end) {
                    $dateList[] = $d->format('Y-m-d');
                    $d->modify('+1 day');
                }
                $sdCl = $pdo->prepare("SELECT DATE(created_at) AS d, COUNT(*) AS n FROM clicks WHERE DATE(created_at) BETWEEN ? AND ? GROUP BY DATE(created_at)");
                $sdCl->execute([$dateFrom, $dateTo]);
                $clMap = [];
                foreach ($sdCl->fetchAll() as $r) {
                    $clMap[$r['d']] = (int)$r['n'];
                }
                $sdCv = $pdo->prepare("SELECT DATE(created_at) AS d, COUNT(*) AS n FROM conversions WHERE DATE(created_at) BETWEEN ? AND ? AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci) GROUP BY DATE(created_at)");
                $sdCv->execute([$dateFrom, $dateTo]);
                $cvMap = [];
                foreach ($sdCv->fetchAll() as $r) {
                    $cvMap[$r['d']] = (int)$r['n'];
                }

                // Daily payout breakdown
                $sdPay = $pdo->prepare("
                    SELECT DATE(created_at) AS d,
                           COALESCE(SUM(payout),0) AS rev,
                           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) AS approved,
                           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) AS pending,
                           COALESCE(SUM(CASE WHEN status='rejected' THEN payout ELSE 0 END),0) AS rejected
                    FROM conversions WHERE DATE(created_at) BETWEEN ? AND ?
                    AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci)
                    GROUP BY DATE(created_at)
                ");
                $sdPay->execute([$dateFrom, $dateTo]);
                $payMap = [];
                foreach ($sdPay->fetchAll() as $r) {
                    $payMap[$r['d']] = ['payout' => round((float)$r['rev'],4), 'approved' => round((float)$r['approved'],4), 'pending' => round((float)$r['pending'],4), 'rejected' => round((float)$r['rejected'],4)];
                }

                $daily = [];
                foreach ($dateList as $day) {
                    $p = $payMap[$day] ?? ['payout'=>0,'approved'=>0,'pending'=>0,'rejected'=>0];
                    $daily[] = ['date' => $day, 'clicks' => $clMap[$day] ?? 0, 'conversions' => $cvMap[$day] ?? 0, 'payout' => $p['payout'], 'approved' => $p['approved'], 'pending' => $p['pending'], 'rejected' => $p['rejected']];
                }

                // By country (clicks)
                $sCo = $pdo->prepare("SELECT country, COUNT(*) AS n FROM clicks WHERE DATE(created_at) BETWEEN ? AND ? AND country != '' GROUP BY country ORDER BY n DESC LIMIT 20");
                $sCo->execute([$dateFrom, $dateTo]);
                // By network (clicks)
                $sNe = $pdo->prepare("SELECT network, COUNT(*) AS n FROM clicks WHERE DATE(created_at) BETWEEN ? AND ? AND network != '' GROUP BY network ORDER BY n DESC LIMIT 20");
                $sNe->execute([$dateFrom, $dateTo]);
                // By status (conversions)
                $sSt = $pdo->prepare("SELECT status, COUNT(*) AS n, COALESCE(SUM(payout),0) AS rev FROM conversions WHERE DATE(created_at) BETWEEN ? AND ? AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci) GROUP BY status ORDER BY n DESC");
                $sSt->execute([$dateFrom, $dateTo]);
                // By slug (conversions)
                $sSl = $pdo->prepare("SELECT slug, COUNT(*) AS n, COALESCE(SUM(payout),0) AS rev FROM conversions WHERE DATE(created_at) BETWEEN ? AND ? AND subid != '' AND network != '' AND payout > 0 AND slug != '' AND EXISTS (SELECT 1 FROM short_links _sl JOIN app_users _au ON _au.id = _sl.user_id WHERE _sl.slug COLLATE utf8mb4_unicode_ci = conversions.slug COLLATE utf8mb4_unicode_ci) GROUP BY slug ORDER BY rev DESC LIMIT 20");
                $sSl->execute([$dateFrom, $dateTo]);
                // By user — LEFT JOIN from app_users so ALL users appear even with 0 conversions
                $sUsr = $pdo->prepare("
                    SELECT au.id AS user_id, au.username,
                           COUNT(v.id) AS conv_count,
                           COALESCE(SUM(v.payout), 0) AS total_payout,
                           COALESCE(SUM(CASE WHEN v.status='approved' THEN v.payout ELSE 0 END), 0) AS approved_payout,
                           COALESCE(SUM(CASE WHEN v.status='pending'  THEN v.payout ELSE 0 END), 0) AS pending_payout,
                           COALESCE(SUM(CASE WHEN v.status='rejected' THEN v.payout ELSE 0 END), 0) AS rejected_payout
                    FROM app_users au
                    LEFT JOIN short_links sl ON sl.user_id = au.id
                    LEFT JOIN conversions v
                        ON v.slug COLLATE utf8mb4_unicode_ci = sl.slug COLLATE utf8mb4_unicode_ci
                        AND DATE(v.created_at) BETWEEN ? AND ?
                        AND v.subid != '' AND v.network != '' AND v.payout > 0 AND v.slug != ''
                    GROUP BY au.id, au.username
                    ORDER BY total_payout DESC, au.username ASC
                ");
                $sUsr->execute([$dateFrom, $dateTo]);

                // Conversions by user + subid
                $sCvSub = $pdo->prepare("
                    SELECT au.id AS user_id, au.username, COALESCE(v.subid,'') AS subid,
                           COUNT(v.id) AS conv_count,
                           COALESCE(SUM(v.payout),0) AS total_payout,
                           COALESCE(SUM(CASE WHEN v.status='approved' THEN v.payout ELSE 0 END),0) AS approved_payout,
                           COALESCE(SUM(CASE WHEN v.status='pending'  THEN v.payout ELSE 0 END),0) AS pending_payout,
                           COALESCE(SUM(CASE WHEN v.status='rejected' THEN v.payout ELSE 0 END),0) AS rejected_payout
                    FROM conversions v
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = v.slug COLLATE utf8mb4_unicode_ci
                    JOIN app_users au ON au.id = sl.user_id
                    WHERE DATE(v.created_at) BETWEEN ? AND ? AND v.subid != '' AND v.network != '' AND v.payout > 0
                    GROUP BY au.id, au.username, v.subid
                    ORDER BY au.username ASC, total_payout DESC
                ");
                $sCvSub->execute([$dateFrom, $dateTo]);

                // Clicks by user + subid — also join app_users so click-only
                // subids (which have no matching conversion row) still carry
                // a username and can be merged into the combined result set.
                $sClSub = $pdo->prepare("
                    SELECT sl.user_id, au.username, COALESCE(c.subid,'') AS subid, COUNT(c.id) AS click_count
                    FROM clicks c
                    JOIN short_links sl ON sl.slug COLLATE utf8mb4_unicode_ci = c.slug COLLATE utf8mb4_unicode_ci
                    JOIN app_users au ON au.id = sl.user_id
                    WHERE DATE(c.created_at) BETWEEN ? AND ?
                    GROUP BY sl.user_id, au.username, c.subid
                ");
                $sClSub->execute([$dateFrom, $dateTo]);

                // Merge conversions + clicks into a single keyed map so every
                // (user, subid) pair shows up — even when there are clicks
                // without any matching conversion, or conversions recorded
                // against a subid that has no clicks in this window.
                $merged = [];
                foreach ($sCvSub->fetchAll() as $r) {
                    $key = $r['user_id'] . '|' . $r['subid'];
                    $merged[$key] = [
                        'user_id'         => (int) $r['user_id'],
                        'username'        => (string) $r['username'],
                        'subid'           => (string) $r['subid'],
                        'click_count'     => 0,
                        'conv_count'      => (int) $r['conv_count'],
                        'total_payout'    => (float) $r['total_payout'],
                        'approved_payout' => (float) $r['approved_payout'],
                        'pending_payout'  => (float) $r['pending_payout'],
                        'rejected_payout' => (float) $r['rejected_payout'],
                    ];
                }
                foreach ($sClSub->fetchAll() as $r) {
                    $key = $r['user_id'] . '|' . $r['subid'];
                    if (!isset($merged[$key])) {
                        $merged[$key] = [
                            'user_id'         => (int) $r['user_id'],
                            'username'        => (string) $r['username'],
                            'subid'           => (string) $r['subid'],
                            'click_count'     => (int) $r['click_count'],
                            'conv_count'      => 0,
                            'total_payout'    => 0.0,
                            'approved_payout' => 0.0,
                            'pending_payout'  => 0.0,
                            'rejected_payout' => 0.0,
                        ];
                    } else {
                        $merged[$key]['click_count'] = (int) $r['click_count'];
                    }
                }
                // Sort: payout desc first, then clicks desc as tie-breaker so
                // click-only subids still surface near the top when relevant.
                $bySubid = array_values($merged);
                usort($bySubid, static function (array $a, array $b): int {
                    if ($a['total_payout'] !== $b['total_payout']) {
                        return $b['total_payout'] <=> $a['total_payout'];
                    }
                    return $b['click_count'] <=> $a['click_count'];
                });

                exit(json_encode([
                    'success'      => true,
                    'total_clicks' => $totalClicks,
                    'total_conv'   => $totalConv,
                    'total_rev'    => $totalRev,
                    'cr'           => $cr,
                    'daily'        => $daily,
                    'by_country'   => $sCo->fetchAll(),
                    'by_network'   => $sNe->fetchAll(),
                    'by_status'    => $sSt->fetchAll(),
                    'by_slug'      => $sSl->fetchAll(),
                    'by_user'      => $sUsr->fetchAll(),
                    'by_subid'     => $bySubid,
                ]));
            } catch (Throwable $e) {
                error_log('admin.admin_get_conversions: ' . $e->getMessage());
                exit(json_encode(['success' => false, 'message' => 'Failed to load conversions.']));
            }
        }

        exit(json_encode(['success' => false, 'message' => 'Unknown action']));
    }
}

// ── Login handler ──
$loginError = '';

if ($requestMethod === 'POST' && isset($_POST['_login'])) {
    $submittedUsername = (string) ($_POST['username'] ?? '');
    $submittedPassword = (string) ($_POST['password'] ?? '');

    // Brute-force throttle: 5 failed attempts per 15 minutes per IP+username.
    // Counter is APCu-only (no DB) so login stays fast and survives DB outage.
    $loginIp = trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['REMOTE_ADDR'] ?? ''));
    $loginThrottleKey = 'login_fail_' . sha1($loginIp . '|' . strtolower(trim($submittedUsername)));
    $throttled = false;
    if (function_exists('tp_apcu_fetch')) {
        $failCount = (int) tp_apcu_fetch($loginThrottleKey);
        if ($failCount >= 5) {
            $throttled = true;
            http_response_code(429);
            $loginError = 'Too many failed attempts. Try again in 15 minutes.';
        }
    }

    if ($throttled) {
        // skip credential check; fall through to render login page with $loginError
    } elseif (!tp_is_valid_csrf_token((string) ($_POST['csrf_token'] ?? ''))) {
        $loginError = 'Invalid CSRF token.';
    } elseif (tp_verify_super_admin_credentials($submittedUsername, $submittedPassword)) {
        session_regenerate_id(true);
        $_SESSION['dashboard_auth'] = true;
        $_SESSION['dashboard_super'] = true;
        header('Location: /');
        exit;
    } elseif (tp_verify_admin_credentials($submittedUsername, $submittedPassword)) {
        session_regenerate_id(true);
        $_SESSION['dashboard_auth'] = true;
        $_SESSION['dashboard_super'] = false;
        header('Location: /');
        exit;
    } else {
        $loginError = 'Username or password is incorrect.';
        if (function_exists('tp_apcu_inc') && function_exists('tp_apcu_add')) {
            tp_apcu_add($loginThrottleKey, 0, 900);
            tp_apcu_inc($loginThrottleKey);
        }
        error_log('admin.login_failed: user=' . substr($submittedUsername, 0, 60)
            . ' ip=' . $loginIp);
    }
}

// ── Auth gate ──
if (empty($_SESSION['dashboard_auth'])) {
    ?><!DOCTYPE html>
    <html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — Dashboard</title>
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="stylesheet" href="/assets/vendor/tailwind-3.4.17.css">
    <link rel="stylesheet" href="/assets/style.css?v=<?= @filemtime(__DIR__ . '/../assets/style.css') ?: time() ?>">
    <link rel="stylesheet" href="/assets/flags/flags.css?v=<?= @filemtime(__DIR__ . '/../assets/flags/flags.css') ?: time() ?>">
</head>
<body class="auth-shell">
    <div class="auth-card-wrap">
        <div class="auth-card">
            <div class="auth-head">
                <div class="auth-logo">
                    <img src="/assets/logo.png" width="28" height="28" alt="Logo">
                </div>
                <h1 class="auth-title">Dashboard</h1>
                <p class="auth-subtitle">Sign in to continue</p>
            </div>

            <?php if ($loginError) : ?>
                <div class="auth-alert auth-alert-error mb-3">
                    <?= htmlspecialchars($loginError, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
                </div>
            <?php endif; ?>

            <form method="POST" id="loginForm">
                <input type="hidden" name="_login" value="1">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
                <div class="mb-3">
                    <label class="field-label">Username</label>
                    <input type="text" name="username" id="inp-user" required autofocus
                        placeholder="Enter username"
                        class="input">
                </div>
                <div class="mb-4">
                    <label class="field-label">Password</label>
                    <div class="relative">
                        <input type="password" name="password" id="inp-pass" required
                            placeholder="Enter password"
                            class="input pr-10">
                        <button type="button" id="login-toggle-password"
                            aria-label="Toggle password visibility" aria-pressed="false"
                            class="input-icon-btn">
                            <svg aria-hidden="true" id="eye-show" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                            </svg>
                            <svg id="eye-hide" class="w-4 h-4 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 4.411m0 0L21 21"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <button type="submit"
                    class="btn btn-default btn-default-size w-full">
                    Sign In
                </button>
            </form>
        </div>
    </div>
    <script<?php echo $nonceAttr; ?>>
        function togglePw() {
            const inp = document.getElementById('inp-pass');
            const show = document.getElementById('eye-show');
            const hide = document.getElementById('eye-hide');
            const btn = document.getElementById('login-toggle-password');
            if (inp.type === 'password') {
                inp.type = 'text'; show.classList.add('hidden'); hide.classList.remove('hidden');
                if (btn) btn.setAttribute('aria-pressed', 'true');
            } else {
                inp.type = 'password'; show.classList.remove('hidden'); hide.classList.add('hidden');
                if (btn) btn.setAttribute('aria-pressed', 'false');
            }
        }

        const loginToggleButton = document.getElementById('login-toggle-password');
        if (loginToggleButton) {
            loginToggleButton.addEventListener('click', togglePw);
        }
    </script>
</body>
</html><?php
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>

    <!-- PWA -->
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#0f0f14">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content=".0089">
    <!-- Favicons -->
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="192x192" href="/assets/android-chrome-192x192.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png">

    <link rel="stylesheet" href="/assets/vendor/tailwind-3.4.17.css">
    <link rel="stylesheet" href="/assets/style.css?v=<?= @filemtime(__DIR__ . '/../assets/style.css') ?: time() ?>">
    <link rel="stylesheet" href="/assets/flags/flags.css?v=<?= @filemtime(__DIR__ . '/../assets/flags/flags.css') ?: time() ?>">
    <script src="/assets/vendor/chart-4.4.2.umd.js"></script>
    <script src="/assets/vendor/alpine-3.15.11.min.js" defer></script>
</head>
<body class="min-h-screen text-foreground" x-data="app" x-init="init()">
<form method="POST" id="logoutForm" class="hidden">
    <input type="hidden" name="_logout" value="1">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
</form>

<!-- ══════════════════════════════════════════════════════
     HEADER
══════════════════════════════════════════════════════ -->
<header class="sticky top-0 z-30">
    <div class="max-w-7xl mx-auto px-4 h-12 flex items-center justify-between gap-3">

        <!-- Brand -->
        <div class="flex items-center gap-2.5">
            <img src="/assets/logo.png" class="w-6 h-6" alt="Logo">
            <div>
                <p class="text-[13px] font-semibold leading-none tracking-tight">Admin Dashboard</p>
                <p class="text-[10px] text-muted-foreground leading-none mt-0.5">cPanel + Cloudflare Wildcard</p>
            </div>
        </div>

        <!-- Right actions -->
        <div class="flex items-center gap-2">
            <!-- Connected badge -->
            <div x-show="isConnected" class="flex items-center gap-1.5">
                <span class="badge badge-outline text-emerald-700 border-emerald-200 bg-emerald-50 flex items-center gap-1">
                    <span class="w-1.5 h-1.5 bg-emerald-500 rounded-full pulse-dot inline-block"></span>
                    Connected
                </span>
            </div>

            <?php if (tp_is_super_admin()) : ?>
            <a href="/redirect-engine"
                class="btn btn-outline btn-sm flex items-center gap-1.5">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 7h16M4 12h10m-10 5h16"/>
                </svg>
                Redirect Engine
            </a>
            <?php endif; ?>

            <button @click="handleLogout()"
                class="btn btn-outline btn-sm flex items-center gap-1.5 text-destructive border-destructive/30 hover:bg-destructive/10">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                </svg>
                Logout
            </button>

            <button @click="showSettings = !showSettings"
                class="btn btn-outline btn-sm flex items-center gap-1.5"
                :class="showSettings ? 'bg-secondary' : ''">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
                Configuration
            </button>
        </div>
    </div>
</header>

<!-- ── Tab nav ── -->
<div class="tab-nav-bar">
    <div class="max-w-7xl mx-auto px-4">
        <nav class="tab-nav-list" role="tablist">
            <button @click="mainTab='add'" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'add' }" :aria-selected="mainTab === 'add'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg>
                Add Domain
            </button>
            <!-- Domain List merged into Add Domain tab -->
            <button @click="mainTab='users'" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'users' }" :aria-selected="mainTab === 'users'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                User
            </button>
            <button @click="mainTab='smartlink'" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'smartlink' }" :aria-selected="mainTab === 'smartlink'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                Smartlink
                <span x-show="smartlinks.length > 0" class="tab-badge tab-badge-dark" x-text="smartlinks.length"></span>
            </button>
            <button @click="openMainTab('analytics')" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'analytics' }" :aria-selected="mainTab === 'analytics'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                Analytics
            </button>
            <button @click="openMainTab('conversion')" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'conversion' }" :aria-selected="mainTab === 'conversion'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Statistics
                <span x-show="adminConv.newConvCount > 0" class="tab-badge tab-badge-dark" x-text="adminConv.newConvCount"></span>
            </button>
            <button @click="openMainTab('system')" class="tab-btn" role="tab"
                :class="{ active: mainTab === 'system' }" :aria-selected="mainTab === 'system'">
                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                System
            </button>
        </nav>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     MAIN
══════════════════════════════════════════════════════ -->
<main class="flex-1 max-w-7xl mx-auto w-full px-4 py-4">

    <!-- ── Settings Modal ── -->
    <div x-show="showSettings" x-cloak
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0"
        x-transition:enter-end="opacity-100"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100"
        x-transition:leave-end="opacity-0"
        class="fixed inset-0 z-50 flex items-start justify-center p-4 pt-16 bg-black/50 backdrop-blur-sm overflow-y-auto"
        @keydown.escape.window="showSettings = false"
        @click.self="showSettings = false">
        <div class="sl-card"
            x-transition:enter="transition ease-out duration-200"
            x-transition:enter-start="opacity-0 -translate-y-4 scale-95"
            x-transition:enter-end="opacity-100 translate-y-0 scale-100"
            x-transition:leave="transition ease-in duration-150"
            x-transition:leave-start="opacity-100 translate-y-0 scale-100"
            x-transition:leave-end="opacity-0 -translate-y-4 scale-95"
            @click.stop>
        <div class="sl-card-header">
            <div class="sl-card-header-left">
                <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
                <h2 class="sl-card-title">Credential Configuration</h2>
            </div>
            <div class="flex items-center gap-2">
                <!-- Auto-sync status for Cloudflare fields -->
                <div class="flex items-center gap-1.5 text-[11px] font-medium"
                     x-show="cfAutoSaveStatus"
                     :class="{
                        'text-muted-foreground':    cfAutoSaveStatus === 'pending',
                        'text-blue-600 dark:text-blue-400':  cfAutoSaveStatus === 'saving',
                        'text-emerald-600 dark:text-emerald-400': cfAutoSaveStatus === 'saved',
                        'text-destructive':         cfAutoSaveStatus === 'error'
                     }">
                    <template x-if="cfAutoSaveStatus === 'pending'">
                        <svg class="w-3 h-3 animate-pulse" fill="currentColor" viewBox="0 0 20 20"><circle cx="10" cy="10" r="4"/></svg>
                    </template>
                    <template x-if="cfAutoSaveStatus === 'saving'">
                        <svg class="w-3 h-3 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M4 12a8 8 0 018-8V2l4 4-4 4V6a6 6 0 106 6h2a8 8 0 11-14 0z"/></svg>
                    </template>
                    <template x-if="cfAutoSaveStatus === 'saved'">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
                    </template>
                    <template x-if="cfAutoSaveStatus === 'error'">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M6 18L18 6M6 6l12 12"/></svg>
                    </template>
                    <span x-text="{
                        pending: 'Waiting…',
                        saving:  'Syncing…',
                        saved:   'Auto-synced',
                        error:   'Sync failed'
                    }[cfAutoSaveStatus] || ''"></span>
                </div>
                <!-- Close button -->
                <button type="button" @click="showSettings = false"
                    class="btn btn-ghost btn-sm p-1" aria-label="Close">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        </div>
        <div class="sl-card-body">

        <!-- Tab bar -->
        <div class="border-b border-border -mx-4 mb-4">
            <nav class="tab-nav-list px-4">
                <button @click="settingsTab = 'cloudflare'" class="tab-btn" :class="{ active: settingsTab === 'cloudflare' }">
                    Cloudflare API
                </button>
            </nav>
        </div>

        <!-- ── Cloudflare tab ── -->
        <div x-show="settingsTab === 'cloudflare'" class="space-y-3">

            <!-- Info: Token Permissions -->
            <div class="notice-box notice-box-amber" x-data="{ open: false }">
                <button type="button" @click="open = !open" class="font-semibold flex items-center justify-between w-full text-left gap-1.5">
                    <span class="flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        Cloudflare Runtime Token — Required Permissions
                    </span>
                    <svg class="w-3.5 h-3.5 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                </button>
                <div x-show="open" x-transition class="mt-1.5 space-y-2">
                    <p class="text-[11px]">Ini adalah <strong>runtime token</strong> yang dipakai dashboard untuk operasional harian (beda dengan bootstrap token di installer). Minimal harus punya permission inti berikut:</p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                        <div class="flex items-start gap-1.5 bg-amber-100/60 dark:bg-amber-900/20 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
                            <div>
                                <p class="font-semibold">Account : Account Settings : Read</p>
                                <p class="text-amber-700/80 dark:text-amber-400/70">Resolve Account ID saat field dikosongkan</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-1.5 bg-amber-100/60 dark:bg-amber-900/20 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
                            <div>
                                <p class="font-semibold">Zone : Zone : Read + Edit</p>
                                <p class="text-amber-700/80 dark:text-amber-400/70">List, create &amp; delete zone untuk domain baru</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-1.5 bg-amber-100/60 dark:bg-amber-900/20 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
                            <div>
                                <p class="font-semibold">Zone : DNS : Edit</p>
                                <p class="text-amber-700/80 dark:text-amber-400/70">Tambah / update record A, CNAME, MX, TXT</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-1.5 bg-amber-100/60 dark:bg-amber-900/20 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
                            <div>
                                <p class="font-semibold">Zone : Zone Settings : Edit</p>
                                <p class="text-amber-700/80 dark:text-amber-400/70">SSL, HTTP/2, HTTP/3, Brotli, Rocket Loader</p>
                            </div>
                        </div>
                    </div>
                    <p class="text-[11px] mt-2"><span class="font-semibold">Opsional (enhanced security)</span> — akan di-skip kalau tidak ada:</p>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                        <div class="flex items-start gap-1.5 bg-amber-100/40 dark:bg-amber-900/10 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
                            <p class="font-semibold">Zone : Client-side Security : Edit</p>
                        </div>
                        <div class="flex items-start gap-1.5 bg-amber-100/40 dark:bg-amber-900/10 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
                            <p class="font-semibold">Zone : Bot Management : Edit</p>
                        </div>
                        <div class="flex items-start gap-1.5 bg-amber-100/40 dark:bg-amber-900/10 rounded px-2 py-1.5">
                            <svg class="w-3 h-3 mt-0.5 shrink-0 text-amber-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
                            <p class="font-semibold">Zone : Zone WAF : Edit</p>
                        </div>
                    </div>
                    <p class="mt-2"><strong>Account Resources:</strong> pilih akun Anda. <strong>Zone Resources:</strong> <em>All zones from an account</em> agar token bisa mengelola zone yang sudah ada dan yang akan dibuat.</p>
                </div>
            </div>

            <!-- Guide: How to create a token -->
            <details class="group panel-box">
                <summary class="flex items-center justify-between px-3 py-2 cursor-pointer select-none bg-secondary/50 hover:bg-secondary text-xs font-semibold list-none">
                    <span class="flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        How to create a Cloudflare API token
                    </span>
                    <svg class="w-3.5 h-3.5 text-muted-foreground transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                </summary>
                <div class="px-3 py-3 text-[11px] leading-relaxed space-y-1.5 text-foreground/80">
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">1</span>
                        <p>Buka <strong>dash.cloudflare.com</strong>, klik ikon profil, pilih <strong>My Profile</strong>.</p>
                    </div>
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">2</span>
                        <p>Buka tab <strong>API Tokens</strong>, klik <strong>Create Token</strong>.</p>
                    </div>
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">3</span>
                        <p>Scroll ke bawah, pilih <strong>"Create Custom Token" → Get started</strong> (bukan template "Edit zone DNS", karena kurang permission).</p>
                    </div>
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">4</span>
                        <div>
                            <p class="mb-1">Isi permission berikut di bagian <em>Permissions</em> (klik <strong>+ Add more</strong> untuk menambah baris):</p>
                            <div class="macro-box font-mono space-y-0.5">
                                <p>Account — Account Settings — <strong>Read</strong></p>
                                <p>Zone — Zone — <strong>Read</strong></p>
                                <p>Zone — Zone — <strong>Edit</strong></p>
                                <p>Zone — DNS — <strong>Edit</strong></p>
                                <p>Zone — Zone Settings — <strong>Edit</strong></p>
                            </div>
                            <p class="mt-1 text-muted-foreground">Opsional (untuk fitur keamanan lanjutan): Zone — Client-side Security — Edit, Zone — Bot Management — Edit, Zone — Zone WAF — Edit.</p>
                        </div>
                    </div>
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">5</span>
                        <p><strong>Account Resources:</strong> Include → pilih akun Anda. <strong>Zone Resources:</strong> Include → <strong>All zones from an account</strong> → pilih akun yang sama.</p>
                    </div>
                    <div class="flex gap-2.5 items-start">
                        <span class="w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-[9px] font-bold shrink-0 mt-0.5">6</span>
                        <p>Klik <strong>Continue to summary</strong> → <strong>Create Token</strong>, lalu copy token ke field di atas.</p>
                    </div>
                    <div class="mt-2 pt-2 border-t border-border flex gap-1.5 items-start text-muted-foreground">
                        <svg class="w-3 h-3 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        <p><strong>Account ID</strong> ada di sidebar kanan dashboard Cloudflare, di bawah nama akun. Kalau dikosongkan, sistem coba ambil otomatis via <code>GET /accounts</code>.</p>
                    </div>
                </div>
            </details>

            <!-- Fields -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">

                <div class="md:col-span-2">
                    <label class="field-label">API Token Cloudflare <span class="text-destructive">*</span></label>
                    <div class="relative">
                        <input :type="showCfToken ? 'text' : 'password'" x-model="config.cf_token"
                            placeholder="cfut_xxxxxxxxxxxxxxxxxxxxxxxx"
                            class="input pr-9 font-mono"/>
                        <button type="button" @click="showCfToken = !showCfToken"
                            aria-label="Toggle password visibility" :aria-pressed="showCfToken.toString()"
                            class="input-icon-btn">
                            <svg aria-hidden="true" x-show="!showCfToken" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                            </svg>
                            <svg x-show="showCfToken" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                            </svg>
                        </button>
                    </div>
                    <p class="hint">Permission minimal: <code>Account:Account Settings:Read</code> · <code>Zone:Zone:Read+Edit</code> · <code>Zone:DNS:Edit</code> · <code>Zone:Zone Settings:Edit</code></p>
                </div>

                <div>
                    <label class="field-label">Account ID <span class="text-muted-foreground font-normal">(recommended)</span></label>
                    <input type="text" x-model="config.cf_account_id"
                        placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                        class="input font-mono"/>
                    <p class="hint">Copy the account ID from the right sidebar in the Cloudflare Dashboard. It is used when creating new zones.</p>
                </div>

                <div>
                    <label class="field-label">Reference Zone ID <span class="text-muted-foreground font-normal">(optional)</span></label>
                    <input type="text" x-model="config.cf_zone_id"
                        placeholder="Zone ID from a domain already in Cloudflare"
                        class="input font-mono"/>
                    <p class="hint">Fallback source for the Account ID if the field above is empty.</p>
                </div>

                <div class="md:col-span-2">
                    <label class="field-label">Default Proxy Mode</label>
                    <select x-model="config.cf_proxied" class="input">
                        <option value="true">Proxied — Orange Cloud ☁ (recommended)</option>
                        <option value="false">DNS Only — Grey Cloud</option>
                    </select>
                    <p class="hint">Applies to all automatically created A and CNAME DNS records.</p>
                </div>

            </div>

            <!-- Info: Cloudflare domain creation flow -->
            <div class="notice-box notice-box-blue" x-data="{ open: false }">
                <button type="button" @click="open = !open" class="font-semibold flex items-center justify-between w-full text-left gap-1.5">
                    <span class="flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                        Flow when a new domain is added
                    </span>
                    <svg class="w-3.5 h-3.5 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                </button>
                <ol x-show="open" x-transition class="space-y-1 list-none pl-0 mt-1.5">
                    <li class="flex gap-2"><span class="text-blue-500 font-bold shrink-0">①</span> <span>The addon domain is created in cPanel using <code>public_html</code>.</span></li>
                    <li class="flex gap-2"><span class="text-blue-500 font-bold shrink-0">②</span> <span>The <code>domain.com</code> zone is checked in Cloudflare. If it does not exist, a <strong>new zone is created automatically</strong>.</span></li>
                    <li class="flex gap-2"><span class="text-blue-500 font-bold shrink-0">③</span> <span>DNS records are configured automatically: A, www, wildcard, MX, SPF, and DMARC.</span></li>
                    <li class="flex gap-2"><span class="text-blue-500 font-bold shrink-0">④</span> <span>The process log shows the <strong>Cloudflare nameservers</strong> that must be set at the domain registrar.</span></li>
                    <li class="flex gap-2"><span class="text-blue-500 font-bold shrink-0">⑤</span> <span>Update the registrar nameservers, such as GoDaddy or Namecheap, to the displayed values. Propagation typically takes 24 to 48 hours.</span></li>
                </ol>
            </div>

            <!-- Test Cloudflare -->
            <div class="flex items-center gap-2.5 pt-1">
                <button type="button" @click="testCloudflare()" :disabled="testingCf"
                    class="btn btn-outline btn-sm flex items-center gap-1.5">
                    <div x-show="testingCf" class="spinner w-3 h-3"></div>
                    <svg x-show="!testingCf" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span x-text="testingCf ? 'Testing...' : 'Test Cloudflare Connection'"></span>
                </button>
                <span x-show="cfTestResult" x-text="cfTestResult"
                    :class="cfTestOk ? 'text-emerald-600' : 'text-destructive'"
                    class="text-xs font-medium"></span>
            </div>
        </div>

        <!-- Footer: save -->
        <div class="separator mt-4 mb-3"></div>
        <div class="flex items-center justify-between">
            <label class="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" x-model="saveConfig"/>
                <span class="text-xs text-muted-foreground">Save configuration to the server</span>
            </label>
            <button type="button" @click="saveConfiguration()"
                :disabled="savingConfig"
                class="btn btn-default btn-sm flex items-center gap-1.5">
                <svg x-show="savingConfig" class="w-3.5 h-3.5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 12a8 8 0 018-8V2l4 4-4 4V6a6 6 0 106 6h2a8 8 0 11-14 0z"/>
                </svg>
                <svg x-show="!savingConfig" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/>
                </svg>
                <span x-text="savingConfig ? 'Saving…' : 'Save Configuration'"></span>
            </button>
        </div>
        </div><!-- /.sl-card-body -->
        </div><!-- /.modal-card -->
    </div><!-- /.settings-modal -->
    <!-- /Settings -->

    <!-- ══ TAB: Add Domain ══ -->
    <div x-show="mainTab==='add'">
    <div class="grid grid-cols-1 lg:grid-cols-5 gap-5">

        <!-- ══ Form Add Domain (2 cols) ══ -->
        <div class="lg:col-span-2 sl-card">
            <div class="sl-card-header">
                <div class="sl-card-header-left">
                    <h2 class="sl-card-title">Add New Domain</h2>
                </div>
            </div>
            <div class="sl-card-body">
            <form @submit.prevent="addDomain()" class="space-y-4">

                <!-- Domain -->
                <div>
                    <label class="field-label">Domain Name <span class="text-destructive">*</span></label>
                    <input type="text" x-model="form.domain"
                        @input="trimFormDomainStart()"
                        @blur="normalizeFormDomain()"
                        placeholder="example.com" autocomplete="off" spellcheck="false"
                        class="input font-mono" :class="errors.domain ? 'input-error' : (domainDuplicate ? 'border-yellow-400 focus:ring-yellow-400/30' : '')"/>
                    <p x-show="errors.domain" x-text="errors.domain" class="hint text-destructive"></p>
                    <p x-show="!errors.domain && domainDuplicate" class="hint text-yellow-600 flex items-center gap-1">
                        <svg class="w-3 h-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                        This domain is already in the list
                    </p>
                    <p x-show="!errors.domain && !domainDuplicate" class="hint">A wildcard entry for <code>*.domain.com</code> will be created in cPanel using <code x-text="config.wildcard_dir || 'WILDCARD_DIR'"></code>.</p>
                </div>

                <!-- Cloudflare master toggle -->
                <div class="flex items-center justify-between p-3 rounded-lg border border-border bg-secondary/30">
                    <div class="flex items-center gap-2">
                        <svg class="w-4 h-4 text-orange-500" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M16.309 9.302c-.133-.004-.266 0-.4.008l-.137.988c-.083.6-.485 1.039-1.079 1.127l-.196.025c-.147.016-.291-.04-.39-.156a.55.55 0 01-.104-.421l.072-.506c-.473-.2-.98-.312-1.513-.312-2.208 0-4 1.793-4 4 0 .356.047.701.135 1.03h10.3c1.103 0 2-.897 2-2 0-2.05-1.636-3.72-3.688-3.783zM5.114 14.085l.535-3.488a.462.462 0 01.466-.393h.682a.46.46 0 01.46.517l-.064.44c1.078-1.178 2.635-1.918 4.37-1.918.696 0 1.363.114 1.988.324l.267-1.73a.462.462 0 01.466-.393h.682a.46.46 0 01.46.517l-.168 1.094c2.555.312 4.553 2.453 4.553 5.063 0 1.654-1.346 3-3 3H5.581a.463.463 0 01-.467-.517V14.085z"/>
                        </svg>
                        <div>
                            <p class="text-xs font-semibold">Use Cloudflare</p>
                            <p class="text-[10px] text-muted-foreground">DNS zone, Security &amp; Speed optimization</p>
                        </div>
                    </div>
                    <button type="button" @click="useCf = !useCf"
                        :class="useCf ? 'border' : 'bg-secondary text-muted-foreground border-border border'"
                        :style="useCf ? 'background-color:#75c38d;color:#ffffff;border-color:#5fae7a' : ''"
                        class="inline-flex items-center justify-center w-8 h-7 rounded-md transition-all"
                        :aria-label="useCf ? 'Cloudflare on' : 'Cloudflare off'">
                        <svg aria-hidden="true" x-show="useCf" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
                        </svg>
                        <svg x-show="!useCf" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>

                <!-- DNS Options — zone template -->
                <div class="panel-box" x-show="useCf">
                    <!-- Header -->
                    <div class="px-3 py-2 border-b border-border flex items-center justify-between bg-secondary/60 cursor-pointer select-none"
                        @click="showDnsSection = !showDnsSection">
                        <p class="text-xs font-semibold flex items-center gap-1.5"
                            :class="config.cf_token?.trim() ? 'text-foreground' : 'text-muted-foreground'">
                            <svg class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064"/>
                            </svg>
                            DNS Records Cloudflare
                            <span x-show="!config.cf_token?.trim()"
                                class="text-[9px] font-normal text-amber-600 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded">
                                Cloudflare token required
                            </span>
                        </p>
                        <div class="flex items-center gap-2">
                            <!-- Toggle all -->
                            <button type="button" @click.stop="toggleAllDns()" x-show="showDnsSection"
                                class="text-[10px] font-medium text-muted-foreground hover:text-foreground transition-colors">
                                <span x-text="allDnsChecked() ? 'Disable all' : 'Enable all'"></span>
                            </button>
                            <!-- Chevron -->
                            <svg class="w-3.5 h-3.5 text-muted-foreground transition-transform duration-200"
                                :class="showDnsSection ? 'rotate-0' : '-rotate-90'"
                                fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </div>
                    </div>

                    <!-- Records -->
                    <div x-show="showDnsSection"
                        x-transition:enter="transition ease-out duration-150"
                        x-transition:enter-start="opacity-0 -translate-y-1"
                        x-transition:enter-end="opacity-100 translate-y-0"
                        x-transition:leave="transition ease-in duration-100"
                        x-transition:leave-start="opacity-100"
                        x-transition:leave-end="opacity-0"
                        class="divide-y divide-border">

                        <!-- ① @ A -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_dns_a"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs"><code class="font-mono">@</code> A → <code class="font-mono" x-text="config.server_ip || 'IP_SERVER'"></code></span>
                                <span class="badge text-[10px] shrink-0 font-semibold" style="background:#f6821f1a;color:#f6821f;border-color:#f6821f55">Proxied</span>
                            </div>
                        </label>

                        <!-- ② www CNAME -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_www"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs"><code class="font-mono">www</code> CNAME → <code class="font-mono" x-text="form.domain || 'domain.com'"></code></span>
                                <span class="badge text-[10px] shrink-0 font-semibold" style="background:#f6821f1a;color:#f6821f;border-color:#f6821f55">Proxied</span>
                            </div>
                        </label>

                        <!-- ③ * A wildcard -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_wildcard"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs"><code class="font-mono">*</code> A → <code class="font-mono" x-text="config.server_ip || 'IP_SERVER'"></code></span>
                                <span class="badge text-[10px] shrink-0 font-semibold" style="background:#f6821f1a;color:#f6821f;border-color:#f6821f55">Proxied</span>
                            </div>
                        </label>

                        <!-- ④ MX null -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_mx_null"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs"><code class="font-mono">@</code> MX <code class="font-mono">0 .</code> <span class="text-muted-foreground">(null MX)</span></span>
                                <span class="badge badge-outline text-[10px] shrink-0">DNS-only</span>
                            </div>
                        </label>

                        <!-- ⑤ SPF -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_spf"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs truncate"><code class="font-mono">@</code> TXT <code class="font-mono text-[10px]">"v=spf1 -all"</code></span>
                                <span class="badge badge-outline text-[10px] shrink-0">DNS-only</span>
                            </div>
                        </label>

                        <!-- ⑥ DMARC -->
                        <label class="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.add_dmarc"/>
                            <div class="flex-1 flex items-center justify-between gap-2 min-w-0">
                                <span class="text-xs truncate"><code class="font-mono">_dmarc</code> TXT <code class="font-mono text-[10px]">"v=DMARC1; p=reject…"</code></span>
                                <span class="badge badge-outline text-[10px] shrink-0">DNS-only</span>
                            </div>
                        </label>

                    </div>

                    <!-- Footer: skip existing toggle -->
                    <div x-show="showDnsSection" class="px-3 py-2 border-t border-border bg-secondary/60">
                        <label class="flex items-center gap-2 cursor-pointer">
                            <input type="checkbox" x-model="form.skip_existing"/>
                            <span class="text-xs text-muted-foreground">Skip records that already exist without overwriting them</span>
                        </label>
                    </div>
                </div>

                <!-- ═══ Cloudflare Security & Speed ═══ -->
                <div class="panel-box" x-show="useCf">

                    <!-- Header -->
                    <div class="px-3 py-2 border-b border-border flex items-center justify-between bg-secondary/60 cursor-pointer select-none"
                        @click="showCfSection = !showCfSection">
                        <p class="text-xs font-semibold flex items-center gap-1.5"
                            :class="config.cf_token?.trim() ? 'text-foreground' : 'text-muted-foreground'">
                            <svg class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                            </svg>
                            Cloudflare Security &amp; Speed
                            <span x-show="!config.cf_token?.trim()"
                                class="text-[9px] font-normal text-amber-600 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded">
                                Cloudflare token required
                            </span>
                        </p>
                        <div class="flex items-center gap-2">
                            <button type="button" @click.stop="toggleAllCf()" x-show="showCfSection"
                                class="text-[10px] font-medium text-muted-foreground hover:text-foreground transition-colors">
                                <span x-text="allCfChecked() ? 'Disable all' : 'Enable all'"></span>
                            </button>
                            <!-- Chevron -->
                            <svg class="w-3.5 h-3.5 text-muted-foreground transition-transform duration-200"
                                :class="showCfSection ? 'rotate-0' : '-rotate-90'"
                                fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </div>
                    </div>

                    <!-- Collapsible body -->
                    <div x-show="showCfSection"
                        x-transition:enter="transition ease-out duration-150"
                        x-transition:enter-start="opacity-0 -translate-y-1"
                        x-transition:enter-end="opacity-100 translate-y-0"
                        x-transition:leave="transition ease-in duration-100"
                        x-transition:leave-start="opacity-100"
                        x-transition:leave-end="opacity-0">

                    <!-- Group: Security -->
                    <div class="px-3 pt-2 pb-1">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1">Security</p>
                    </div>

                    <div class="divide-y divide-border">

                        <!-- Under Attack Mode -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_under_attack" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Under Attack Mode</span>
                                    <span class="badge badge-outline text-[9px] text-amber-700 border-amber-200 shrink-0">Challenge</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Enable challenge mode during active attacks to slow abusive traffic before it reaches origin</p>
                            </div>
                        </label>

                        <!-- Client-side Security / Page Shield -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_pageshield" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Client-side Security</span>
                                    <span class="badge badge-outline text-[9px] text-emerald-700 border-emerald-200 shrink-0">Page Shield</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Monitor and block malicious scripts on the client side</p>
                            </div>
                        </label>

                        <!-- Bot Fight Mode -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_bot_fight" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Bot Fight Mode</span>
                                    <span class="badge badge-outline text-[9px] text-orange-700 border-orange-200 shrink-0">Free</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Automatically block crawler and scraper bots</p>
                            </div>
                        </label>

                        <!-- Leaked Credentials -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_leaked_creds" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Leaked Credentials</span>
                                    <span class="badge badge-outline text-[9px] text-red-700 border-red-200 shrink-0">WAF</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Detect and mitigate logins that use leaked passwords</p>
                            </div>
                        </label>

                        <!-- WAF Managed Rules -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_waf" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">WAF Managed Rules</span>
                                    <span class="badge badge-outline text-[9px] text-red-700 border-red-200 shrink-0">WAF</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Enable the Cloudflare Managed Ruleset to block exploits and common attacks</p>
                            </div>
                        </label>

                    </div>

                    <!-- Group: Caching & Traffic -->
                    <div class="px-3 pt-2.5 pb-1 border-t border-border mt-1">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1">Caching &amp; Traffic</p>
                    </div>

                    <div class="divide-y divide-border">

                        <!-- Always Online -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_always_online" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Always Online</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">Reliability</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Serve cached snapshots when origin is temporarily unavailable</p>
                            </div>
                        </label>

                        <!-- Cache Level -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_cache_aggressive" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Aggressive Cache Level</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">Static</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Cache static assets more aggressively even when query strings are present</p>
                            </div>
                        </label>

                        <!-- Browser Cache TTL -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_browser_cache_ttl" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Browser Cache TTL</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">4h</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Encourage browsers to reuse static assets for four hours to cut repeat origin traffic</p>
                            </div>
                        </label>

                    </div>

                    <!-- Group: Speed -->
                    <div class="px-3 pt-2.5 pb-1 border-t border-border mt-1">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1">Speed</p>
                    </div>

                    <div class="divide-y divide-border">

                        <!-- Auto Minify -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_speed_minify" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Auto Minify</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">CSS · JS · HTML</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Remove whitespace and comments from static assets</p>
                            </div>
                        </label>

                        <!-- Rocket Loader -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_speed_rocket" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Rocket Loader</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">async JS</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Load JavaScript asynchronously to speed up rendering</p>
                            </div>
                        </label>

                        <!-- Early Hints -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_speed_hints" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Early Hints</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">HTTP 103</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Send preload hints before the main response is ready</p>
                            </div>
                        </label>

                        <!-- HTTP/2 + HTTP/3 + 0-RTT -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_speed_http2" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">HTTP/2 · HTTP/3 · 0-RTT</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">QUIC</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">Modern protocols with 0-RTT connection resumption</p>
                            </div>
                        </label>

                        <!-- Brotli -->
                        <label class="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-secondary/60 transition-colors">
                            <input type="checkbox" x-model="form.cf_speed_brotli" class="mt-0.5"/>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center justify-between gap-2">
                                    <span class="text-xs font-medium">Brotli Compression</span>
                                    <span class="badge badge-secondary text-[9px] shrink-0">br</span>
                                </div>
                                <p class="text-[10px] text-muted-foreground leading-tight mt-0.5">More efficient compression than gzip for modern browsers</p>
                            </div>
                        </label>

                    </div>

                    </div><!-- /collapsible CF body -->
                </div>
                <!-- /Security & Speed -->

                <!-- Submit -->
                <button type="submit" :disabled="isLoading || !form.domain"
                    class="btn btn-default btn-lg w-full flex items-center justify-center gap-2">
                    <div x-show="isLoading" class="spinner spinner-light w-4 h-4"></div>
                    <svg x-show="!isLoading" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                    </svg>
                    <span x-text="isLoading ? 'Processing...' : 'Add Domain'"></span>
                </button>

            </form>
            </div><!-- /.sl-card-body -->
        </div><!-- /.sl-card -->
        <!-- /Form -->

        <!-- ══ Right panel (3 cols) — Domain List ══ -->
        <div class="lg:col-span-3 flex flex-col gap-5" style="grid-row: span 2">

            <!-- ── Nameserver Panel ── -->
            <div x-show="nameservers.length > 0" x-cloak
                x-transition:enter="transition ease-out duration-300"
                x-transition:enter-start="opacity-0 scale-98 -translate-y-1"
                x-transition:enter-end="opacity-100 scale-100 translate-y-0"
                x-transition:leave="transition ease-in duration-200"
                x-transition:leave-start="opacity-100 scale-100"
                x-transition:leave-end="opacity-0 scale-98"
                class="rounded-xl overflow-hidden"
                :class="zoneCreated ? 'border-2 border-amber-400' : 'border border-blue-300'">

                <!-- Header -->
                <div class="flex items-center justify-between px-4 py-2.5"
                    :class="zoneCreated ? 'bg-amber-400 text-amber-950' : 'bg-blue-500 text-white'">
                    <div class="flex items-center gap-2">
                        <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5"
                                d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064"/>
                        </svg>
                        <span class="text-xs font-bold tracking-wide">
                            <span x-text="nsSource === 'cpanel' ? 'Nameserver cPanel' : 'Nameserver Cloudflare'"></span>
                            <span x-show="zoneCreated"> — New Zone Created</span>
                            <span x-show="!zoneCreated"> — <span x-text="lastDomain"></span></span>
                        </span>
                    </div>
                    <button type="button" @click="resetNameserverPreview()"
                        class="icon-action-btn opacity-70 hover:opacity-100">
                        <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>

                <!-- Body -->
                <div class="px-4 py-3 space-y-3"
                    :class="zoneCreated ? 'bg-amber-50 dark:bg-amber-900/20' : 'bg-blue-50 dark:bg-blue-900/20'">

                    <!-- Context message -->
                    <p class="text-[11px] leading-relaxed"
                        :class="zoneCreated ? 'text-amber-800 dark:text-amber-300' : 'text-blue-800 dark:text-blue-300'">
                        <template x-if="nsSource === 'cpanel'">
                            <span>
                                <strong x-text="lastDomain"></strong> was added via <strong>cPanel only</strong> (Cloudflare not configured).
                                Point the domain registrar at the <strong>cPanel nameservers</strong> below to activate it.
                                <span x-show="nsDetectLabel" class="block mt-1 opacity-80 italic">
                                    Auto-detected via: <span x-text="nsDetectLabel"></span>
                                </span>
                            </span>
                        </template>
                        <template x-if="nsSource !== 'cpanel' && zoneCreated">
                            <span>
                                The Cloudflare zone for <strong x-text="lastDomain"></strong> was just created.
                                <strong>Update the nameservers at your domain registrar</strong> to the values below to activate the domain:
                            </span>
                        </template>
                        <template x-if="nsSource !== 'cpanel' && !zoneCreated">
                            <span>
                                Cloudflare nameservers for <strong x-text="lastDomain"></strong>:
                                Make sure your domain registrar is already using these nameservers.
                            </span>
                        </template>
                    </p>

                    <!-- NS List -->
                    <div class="space-y-1.5">
                        <template x-for="(ns, idx) in nameservers" :key="ns">
                            <div class="flex items-center gap-2.5 rounded-lg px-3 py-2 border"
                                :class="zoneCreated
                                    ? 'bg-white dark:bg-amber-900/40 border-amber-200 dark:border-amber-700'
                                    : 'bg-white dark:bg-blue-900/40 border-blue-200 dark:border-blue-700'">
                                <span class="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
                                    :class="zoneCreated ? 'bg-amber-400 text-amber-950' : 'bg-blue-500 text-white'"
                                    x-text="idx + 1"></span>
                                <code class="text-sm font-mono font-semibold flex-1 tracking-tight"
                                    :class="zoneCreated ? 'text-amber-900 dark:text-amber-200' : 'text-blue-900 dark:text-blue-200'"
                                    x-text="ns"></code>
                                <button type="button"
                                    @click="copyVal(ns, $el)"
                                    class="shrink-0 rounded p-1 transition-colors"
                                    :class="zoneCreated ? 'text-amber-500 hover:bg-amber-100 dark:hover:bg-amber-800/40' : 'text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-800/40'"
                                    title="Copy nameserver">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                            d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                                    </svg>
                                </button>
                            </div>
                        </template>
                    </div>

                    <!-- Copy all + footer note -->
                    <div class="flex items-center justify-between pt-0.5">
                        <p class="text-[10px]"
                            :class="zoneCreated ? 'text-amber-600 dark:text-amber-500' : 'text-blue-500 dark:text-blue-400'">
                            <span x-show="zoneCreated">Nameserver propagation usually takes 24-48 hours after you update them at the registrar.</span>
                            <span x-show="!zoneCreated">Make sure the nameservers are already active at the domain registrar.</span>
                        </p>
                        <button type="button"
                            @click="copyVal(nameservers.join('\n'), $el)"
                            class="text-[10px] font-semibold flex items-center gap-1 shrink-0 ml-3 rounded px-2 py-1 transition-colors"
                            :class="zoneCreated ? 'text-amber-700 hover:bg-amber-100 dark:hover:bg-amber-800/40' : 'text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-800/40'">
                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                            </svg>
                            Copy all
                        </button>
                    </div>
                </div>
            </div>
            <!-- /Nameserver Panel -->

            <!-- ── Domain List (inline) ── -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Domain List</h2>
                        <span class="sl-card-count" x-show="domains.length > 0" x-text="domains.length"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <button @click="loadDomains()" :disabled="domainsLoading" class="sl-card-refresh">
                            <div x-show="domainsLoading" class="spinner w-3 h-3"></div>
                            <svg x-show="!domainsLoading" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                            </svg>
                            Refresh
                        </button>
                    </div>
                </div>

                <!-- Empty state -->
                <div x-show="!domainsLoading && domains.length === 0"
                    class="empty-state empty-state-panel mx-4 my-4">
                    <div class="empty-state-icon">
                        <svg class="w-5 h-5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25zm0 3.75h.008v7.5H12v-7.5z"/>
                        </svg>
                    </div>
                    <p class="empty-state-title">No saved domains yet</p>
                </div>

                <!-- Loading -->
                <div x-show="domainsLoading" class="flex items-center justify-center py-10 gap-2 text-xs text-muted-foreground">
                    <div class="spinner w-4 h-4"></div>
                    <span>Loading data...</span>
                </div>

                <!-- Table -->
                <div x-show="!domainsLoading && domains.length > 0" class="overflow-x-auto">
                    <table class="w-full tbl">
                        <thead>
                            <tr class="border-b border-border">
                                <th scope="col" class="text-center py-2 px-3 font-semibold text-muted-foreground w-8">#</th>
                                <th scope="col" class="text-left py-2 px-3 font-semibold text-muted-foreground">Domain</th>
                                <th scope="col" class="text-left py-2 px-3 font-semibold text-muted-foreground w-24">Owner</th>
                                <th scope="col" class="text-left py-2 px-3 font-semibold text-muted-foreground w-28">
                                    <span class="flex items-center gap-1">
                                        Cloudflare
                                        <span x-show="cfStatusUpdating" title="Refreshing CF status...">
                                            <div class="spinner spinner-orange w-2.5 h-2.5 opacity-50"></div>
                                        </span>
                                    </span>
                                </th>
                                <th scope="col" class="text-right py-2 px-3 font-semibold text-muted-foreground w-20">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-border">
                            <template x-for="(d, i) in pagedDomains" :key="d.id">
                                <tr class="hover:bg-secondary/40 transition-colors">
                                    <td class="py-2 px-3 text-muted-foreground font-mono text-center" x-text="(domainPage - 1) * domainPerPage + i + 1"></td>
                                    <td class="py-2 px-3">
                                        <span class="font-medium" x-text="d.domain"></span>
                                        <span x-show="d.sub_domain"
                                            x-text="d.sub_domain"
                                            class="ml-1.5 px-1.5 py-px rounded text-[9px] font-semibold uppercase tracking-wide bg-emerald-100 text-emerald-700 border border-emerald-200"></span>
                                    </td>
                                    <td class="py-2 px-3">
                                        <span :class="d.domain_id === 'admin' || !d.domain_id
                                            ? 'bg-blue-100 text-blue-700'
                                            : 'bg-amber-100 text-amber-700'"
                                            class="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                                            x-text="d.domain_id || 'admin'"></span>
                                    </td>
                                    <td class="py-2 px-3 whitespace-nowrap">
                                        <!-- CF: Active (zone active) -->
                                        <span x-show="d.cf_status === 'active'"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400">
                                            <svg class="w-2.5 h-2.5" viewBox="0 0 24 24" fill="currentColor"><path d="M16.5 8.25a4.5 4.5 0 00-8.71-1.5H7a3.5 3.5 0 000 7h9a3 3 0 000-6c-.17 0-.34.01-.5.03z"/></svg>
                                            Active
                                        </span>
                                        <!-- CF: Pending (zone exists, nameservers not updated yet) -->
                                        <span x-show="d.cf_status === 'pending'"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-50 text-blue-500 dark:bg-blue-900/20 dark:text-blue-400">
                                            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                            Pending NS
                                        </span>
                                        <!-- CF: Zone not found -->
                                        <span x-show="d.cf_status === 'not_found'"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-50 text-red-500 dark:bg-red-900/20 dark:text-red-400">
                                            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                            Not Found
                                        </span>
                                        <!-- CF: Not configured (token missing) -->
                                        <span x-show="d.cf_status === 'unconfigured'"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-yellow-50 text-yellow-600 dark:bg-yellow-900/20 dark:text-yellow-400">
                                            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                                            Not Configured
                                        </span>
                                        <!-- Fallback if the status is not loaded yet -->
                                        <span x-show="!d.cf_status" class="text-muted-foreground">—</span>
                                    </td>
                                    <td class="py-2 px-3 text-right">
                                        <div class="flex items-center justify-end gap-1">
                                            <!-- Show Sync CF for all states except unconfigured (no CF token = can't sync) -->
                                            <button x-show="d.cf_status && d.cf_status !== 'unconfigured'"
                                                @click="syncCloudflare(d)"
                                                :disabled="syncingCfId === d.id || deletingId === d.id"
                                                class="btn btn-ghost btn-sm text-orange-500 hover:bg-orange-50 dark:hover:bg-orange-900/20 flex items-center gap-1 disabled:opacity-40">
                                                <div x-show="syncingCfId === d.id" class="spinner spinner-orange w-3 h-3"></div>
                                                <svg x-show="syncingCfId !== d.id" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                                                </svg>
                                                <span x-text="syncingCfId === d.id ? '...' : 'Sync CF'"></span>
                                            </button>
                                            <!-- Delete -->
                                            <button @click="deleteDomain(d)"
                                                :disabled="deletingId === d.id || syncingCfId === d.id"
                                                class="btn btn-ghost btn-sm text-destructive hover:bg-destructive/10 flex items-center gap-1 disabled:opacity-40">
                                                <div x-show="deletingId === d.id" class="spinner spinner-danger w-3 h-3"></div>
                                                <svg x-show="deletingId !== d.id" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                </svg>
                                                <span x-text="deletingId === d.id ? '...' : 'Delete'"></span>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <div x-show="!domainsLoading && domains.length > domainPerPage"
                    class="flex items-center justify-between px-3 py-2 border-t border-border text-xs text-muted-foreground">
                    <span x-text="domainPaginationLabel"></span>
                    <div class="flex items-center gap-1">
                        <button @click="domainPage--" :disabled="domainPage <= 1"
                            aria-label="Previous page"
                            class="btn btn-ghost btn-sm px-2 disabled:opacity-40">
                            <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
                        </button>
                        <template x-for="p in Math.ceil(domains.length / domainPerPage)" :key="p">
                            <button @click="domainPage = p" :class="domainPage === p ? 'bg-primary text-primary-foreground' : 'hover:bg-secondary'"
                                class="btn btn-ghost btn-sm w-6 h-6 p-0 text-[11px] rounded" x-text="p"></button>
                        </template>
                        <button @click="domainPage++" :disabled="domainPage >= Math.ceil(domains.length / domainPerPage)"
                            aria-label="Next page"
                            class="btn btn-ghost btn-sm px-2 disabled:opacity-40">
                            <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                        </button>
                    </div>
                </div>
            </div>
            <!-- /Domain List -->

        </div>
        <!-- /Right panel -->

        <!-- ── Process Log (below form, left column) ── -->
        <div class="lg:col-span-2">
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Process Log</h2>
                    </div>
                    <div class="sl-card-header-right">
                        <button type="button" @click="clearLogs()" x-show="logs.length > 0"
                            class="sl-card-refresh hover:text-destructive hover:bg-destructive/10">
                            <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                            </svg>
                            Clear
                        </button>
                    </div>
                </div>
                <div class="sl-card-body">

                <!-- Empty state -->
                <div x-show="logs.length === 0"
                    class="empty-state empty-state-panel">
                    <div class="empty-state-icon">
                        <svg class="w-5 h-5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
                                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                        </svg>
                    </div>
                    <p class="empty-state-title">No process yet</p>
                    <p class="empty-state-desc">Activity logs will appear here</p>
                </div>

                <!-- Log list -->
                <div x-show="logs.length > 0" aria-live="polite" aria-label="Activity log" class="space-y-1.5 max-h-72 overflow-y-auto scroll-logs pr-1">
                    <template x-for="(log, i) in logs" :key="i">
                        <div class="log-entry flex items-start gap-2 px-2.5 py-2 rounded text-xs"
                            :class="{
                                'log-success bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400': log.type === 'success',
                                'log-error bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400':   log.type === 'error',
                                'log-warning bg-yellow-50 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-400': log.type === 'warning',
                                'log-info bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-400':    log.type === 'info',
                                'log-step bg-muted/40 text-foreground font-medium':    log.type === 'step'
                            }">
                            <!-- Icon -->
                            <span class="mt-px shrink-0">
                                <svg x-show="log.type==='success'" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                                <svg x-show="log.type==='error'"   class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/></svg>
                                <svg x-show="log.type==='warning'" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                <svg x-show="log.type==='info'"    class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                <svg x-show="log.type==='step'"    class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                            </span>
                            <span class="flex-1 break-words leading-relaxed" x-text="log.message"></span>
                            <span class="text-[10px] shrink-0 opacity-50 font-mono" x-text="log.time"></span>
                        </div>
                    </template>
                </div>

                <!-- Status bar -->
                <div x-show="currentStatus" class="mt-3 pt-3 border-t border-border">
                    <div class="flex items-center gap-2">
                        <div x-show="isLoading" class="spinner w-3.5 h-3.5"></div>
                        <svg x-show="!isLoading && lastSuccess" class="w-3.5 h-3.5 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                        <svg x-show="!isLoading && !lastSuccess && currentStatus" class="w-3.5 h-3.5 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/></svg>
                        <span class="text-xs font-medium"
                            :class="isLoading ? 'text-muted-foreground' : (lastSuccess ? 'text-emerald-600' : 'text-destructive')"
                            x-text="currentStatus"></span>
                    </div>
                </div>
                </div><!-- /.sl-card-body -->
            </div><!-- /.sl-card -->
        </div>
        <!-- /Process Log -->

    </div>
    <!-- /grid -->
    </div>
    <!-- /TAB: Add Domain -->

    <!-- ══ TAB: User ══ -->
    <div x-show="mainTab==='users'" x-cloak>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">

            <!-- ── Create User ── -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Create User</h2>
                    </div>
                </div>
                <div class="sl-card-body space-y-3">
                    <div>
                        <label class="label">Username <span class="text-destructive">*</span></label>
                        <input x-model="userCreate.username" type="text" placeholder="example: john_doe"
                            class="input font-mono" autocomplete="off" spellcheck="false"
                            @input="sanitizeNewUsername()">
                        <p class="hint">Lowercase letters, numbers, underscore — starts with a letter, 2–32 characters</p>
                    </div>
                    <div>
                        <label class="label">Password <span class="text-destructive">*</span></label>
                        <div class="relative">
                            <input x-model="userCreate.password"
                                :type="userCreate.showPw ? 'text' : 'password'"
                                placeholder="Minimum 5 characters"
                                class="input pr-8" autocomplete="new-password">
                            <button type="button" @click="toggleUserCreatePassword()"
                                aria-label="Toggle password visibility" :aria-pressed="userCreate.showPw.toString()"
                                class="input-icon-btn">
                                <svg aria-hidden="true" x-show="!userCreate.showPw" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                <svg x-show="userCreate.showPw" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
                            </button>
                        </div>
                    </div>
                    <button @click="createCpanelUser()" :disabled="userCreateLoading || !userCreate.username || !userCreate.password"
                        class="btn btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50">
                        <div x-show="userCreateLoading" class="spinner spinner-light w-4 h-4"></div>
                        <svg x-show="!userCreateLoading" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/></svg>
                        <span x-text="userCreateLoading ? 'Creating…' : 'Create User'"></span>
                    </button>
                    <p x-show="userCreateMsg" x-text="userCreateMsg"
                        :class="userCreateOk ? 'text-emerald-600' : 'text-destructive'"
                        class="text-xs font-medium"></p>
                </div><!-- /.sl-card-body -->
            </div><!-- /.sl-card Create User -->

            <!-- ── User List ── -->
            <div class="sl-card lg:col-span-2">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Users</h2>
                        <span class="sl-card-count" x-show="cpanelUsers.length > 0" x-text="nonSystemCpanelUserCount"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <button @click="loadUsers()" :disabled="usersLoading" class="sl-card-refresh">
                            <div x-show="usersLoading" class="spinner w-3 h-3"></div>
                            <svg x-show="!usersLoading" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>

                <div x-show="sys.sl_url_warnings.length > 0"
                    class="mx-4 mt-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-3 text-xs text-amber-900"
                    x-data="{ open: false }">
                    <button type="button" @click="open = !open" class="flex items-center gap-2.5 w-full text-left font-semibold">
                        <svg aria-hidden="true" class="w-4 h-4 shrink-0 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                        <span class="flex-1">User dashboard links need wildcard host routing.</span>
                        <svg class="w-3.5 h-3.5 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                    </button>
                    <div x-show="open" x-transition class="mt-2 pl-6 space-y-2">
                        <template x-for="warning in sys.sl_url_warnings" :key="'users-' + warning">
                            <p class="leading-relaxed" x-text="warning"></p>
                        </template>
                        <p class="text-[11px] text-amber-800/90">If the URL still fails after these settings are correct, check wildcard DNS, the cPanel wildcard subdomain, and any tunnel or proxy that should publish the same host.</p>
                    </div>
                </div>

                <!-- Empty state -->
                <div x-show="!usersLoading && cpanelUsers.length === 0"
                    class="empty-state empty-state-panel mx-4 my-4">
                    <p class="empty-state-title">No sub-users yet</p>
                    <p class="empty-state-desc">Click Refresh or create a new user.</p>
                </div>

                <!-- Loading -->
                <div x-show="usersLoading" class="flex items-center justify-center py-10 gap-2 text-xs text-muted-foreground">
                    <div class="spinner w-4 h-4"></div> Loading…
                </div>

                <!-- Table -->
                <div x-show="!usersLoading && cpanelUsers.length > 0">
                    <div class="overflow-x-auto">
                        <table class="tbl w-full text-[11px]">
                            <thead>
                                <tr>
                                    <th scope="col">User</th>
                                    <th scope="col">Dashboard URL</th>
                                    <th scope="col" class="text-right w-20">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="u in usersPaged" :key="u.username">
                                    <tr class="hover:bg-secondary/20">
                                        <!-- User -->
                                        <td class="whitespace-nowrap">
                                            <div class="flex items-center gap-2">
                                                <div class="w-6 h-6 rounded-full bg-secondary flex items-center justify-center shrink-0">
                                                    <span class="text-[10px] font-bold text-muted-foreground uppercase"
                                                        x-text="(u.username||'?').charAt(0)"></span>
                                                </div>
                                                <div>
                                                    <div class="text-xs font-semibold font-mono text-foreground" x-text="u.username"></div>
                                                    <div class="text-[10px] text-muted-foreground capitalize" x-text="u.type || 'sub'"></div>
                                                </div>
                                            </div>
                                        </td>
                                        <!-- URL -->
                                        <td>
                                            <a :href="'<?php echo dashboardScheme(); ?>://' + u.username + '.<?php echo $dashboardWildcardBaseHost; ?>/gen'"
                                                target="_blank"
                                                class="cpanel-dashboard-link">
                                                <svg class="w-3 h-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                                                <span x-text="u.username + '.<?php echo $dashboardWildcardBaseHost; ?>/gen'"></span>
                                            </a>
                                        </td>
                                        <!-- Actions -->
                                        <td class="py-2 px-3 text-right">
                                            <div class="flex items-center justify-end gap-1">
                                                <button @click="openResetPw(u.username)" title="Reset Password" aria-label="Reset Password"
                                                    class="icon-action-btn text-sky-600 hover:text-sky-700">
                                                    <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                                                </button>
                                                <button @click="deleteCpanelUser(u.username)" title="Delete User" aria-label="Delete"
                                                    :disabled="deletingUser === u.username"
                                                    class="icon-action-btn-danger">
                                                    <div x-show="deletingUser === u.username" class="spinner spinner-danger w-3 h-3"></div>
                                                    <svg x-show="deletingUser !== u.username" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                    <!-- Pagination (always visible when users exist) -->
                    <div class="px-3 py-2.5 border-t border-border flex items-center justify-between gap-2">
                        <span class="text-[11px] text-muted-foreground">
                            <span x-text="Math.min((usersPage-1)*usersPerPage+1, usersFiltered.length)"></span>–<span x-text="Math.min(usersPage*usersPerPage, usersFiltered.length)"></span>
                            <span class="text-muted-foreground/60"> of </span><span x-text="usersFiltered.length"></span>
                        </span>
                        <div class="flex items-center gap-1">
                            <button @click="usersPage=1" :disabled="usersPage===1" class="pg-btn">«</button>
                            <button @click="usersPage--" :disabled="usersPage===1" class="pg-btn">‹</button>
                            <span class="pg-btn active pointer-events-none" x-text="usersPage + ' / ' + usersTotalPages"></span>
                            <button @click="usersPage++" :disabled="usersPage>=usersTotalPages" class="pg-btn">›</button>
                            <button @click="usersPage=usersTotalPages" :disabled="usersPage>=usersTotalPages" class="pg-btn">»</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>
    <!-- /TAB: User -->

    <!-- ══ TAB: Smartlink ══ -->
    <div x-show="mainTab==='smartlink'" x-cloak>

        <div class="grid grid-cols-1 lg:grid-cols-5 gap-5">

            <!-- ── Form ── -->
            <div class="sl-card lg:col-span-2">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title" x-text="slForm.id ? 'Edit Smartlink' : 'Add Smartlink'"></h2>
                    </div>
                </div>
                <div class="sl-card-body space-y-3">
                    <!-- Country checkbox + filter -->
                    <div>
                        <label class="label">Country</label>
                        <div class="border border-border rounded-md bg-background overflow-hidden">
                            <!-- Filter input -->
                            <div class="px-2 py-1.5 border-b border-border">
                                <input x-model="slCountrySearch" type="text"
                                    placeholder="Filter countries…"
                                    class="w-full text-xs bg-transparent outline-none placeholder:text-muted-foreground"
                                    autocomplete="off">
                            </div>
                            <!-- Checkbox list -->
                            <div class="max-h-44 overflow-y-auto divide-y divide-border/40">
                                <template x-for="c in slFilteredCountries" :key="c.code">
                                    <label class="flex items-center gap-2 px-3 py-1.5 cursor-pointer hover:bg-muted select-none"
                                        :class="slForm.countries.includes(c.code) ? 'bg-primary/5' : ''">
                                        <input type="checkbox"
                                            :checked="slForm.countries.includes(c.code)"
                                            @change="slToggleCountry(c.code)"
                                            class="rounded accent-primary shrink-0">
                                        <span class="text-xs flex-1"
                                            :class="c.code === 'all' ? 'font-semibold' : ''"
                                            x-text="c.code === 'all' ? 'All Country' : c.code + ' — ' + c.name"></span>
                                        <svg x-show="slForm.countries.includes(c.code)"
                                            class="w-3 h-3 text-primary shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
                                        </svg>
                                    </label>
                                </template>
                                <div x-show="slFilteredCountries.length === 0"
                                    class="px-3 py-2 text-xs text-muted-foreground">No results</div>
                            </div>
                        </div>
                        <!-- Selected pills -->
                        <div class="flex flex-wrap gap-1 mt-1"
                            x-show="slForm.countries.length > 0 && !slForm.countries.includes('all')">
                            <template x-for="c in slForm.countries" :key="c">
                                <span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-primary text-primary-foreground text-[10px] font-semibold uppercase">
                                    <span x-text="c"></span>
                                    <button type="button" @click="slRemoveCountry(c)"
                                        class="hover:opacity-70 leading-none">&times;</button>
                                </span>
                            </template>
                        </div>
                    </div>
                    <!-- Device -->
                    <div>
                        <label class="label">Device</label>
                        <select x-model="slForm.device" class="input">
                            <option value="all">All Device</option>
                            <option value="wap">WAP</option>
                            <option value="web">WEB</option>
                        </select>
                    </div>
                    <!-- Network -->
                    <div>
                        <label class="label">Network</label>
                        <select x-model="slForm.networkPreset" @change="syncSmartlinkNetworkPreset()" class="input">
                            <option value="iMonetizeit">iMonetizeit</option>
                            <option value="Lospollos">Lospollos</option>
                            <option value="Trafee">Trafee</option>
                            <option value="custom">Custom…</option>
                        </select>
                        <input x-show="slForm.networkPreset === 'custom'"
                            x-model="slForm.network"
                            type="text" placeholder="Network name (example: twitter, telegram)"
                            class="input mt-2">
                    </div>
                    <!-- URL -->
                    <div x-data="{ showPlaceholders: true }">
                        <div class="flex items-center justify-between mb-1">
                            <label class="label mb-0">Smartlink URL <span class="text-destructive">*</span></label>
                            <button type="button" @click="showPlaceholders = !showPlaceholders"
                                class="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors">
                                <svg aria-hidden="true" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                                </svg>
                                <span x-text="showPlaceholders ? 'Hide' : 'Placeholders'"></span>
                                <svg class="w-3 h-3 transition-transform" :class="showPlaceholders ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                </svg>
                            </button>
                        </div>
                        <input x-model="slForm.url" type="url" placeholder="https://..." class="input font-mono text-xs" autocomplete="off" spellcheck="false">
                        <!-- Placeholder reference (collapsible) -->
                        <div x-show="showPlaceholders" x-transition:enter="transition ease-out duration-150"
                            x-transition:enter-start="opacity-0 -translate-y-1" x-transition:enter-end="opacity-100 translate-y-0"
                            x-transition:leave="transition ease-in duration-100"
                            x-transition:leave-start="opacity-100 translate-y-0" x-transition:leave-end="opacity-0 -translate-y-1"
                            class="mt-2 rounded-lg border border-border bg-muted/40 divide-y divide-border/60 overflow-hidden">
                            <div class="grid grid-cols-2 divide-x divide-border/60">
                                <div class="px-2.5 py-1.5">
                                    <code class="text-[11px] font-mono font-bold text-primary">{clickid}</code>
                                    <p class="text-[10px] text-muted-foreground mt-0.5 leading-snug">Unique click ID — used for conversion postback</p>
                                </div>
                                <div class="px-2.5 py-1.5">
                                    <code class="text-[11px] font-mono font-bold text-primary">{subid}</code>
                                    <p class="text-[10px] text-muted-foreground mt-0.5 leading-snug">Link owner username</p>
                                </div>
                            </div>
                            <div class="grid grid-cols-2 divide-x divide-border/60">
                                <div class="px-2.5 py-1.5">
                                    <code class="text-[11px] font-mono font-bold text-primary">{country}</code>
                                    <p class="text-[10px] text-muted-foreground mt-0.5 leading-snug">Visitor country code (ID, US, SG…)</p>
                                </div>
                                <div class="px-2.5 py-1.5">
                                    <code class="text-[11px] font-mono font-bold text-primary">{device}</code>
                                    <p class="text-[10px] text-muted-foreground mt-0.5 leading-snug">wap (mobile) / web (desktop)</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Buttons -->
                    <div class="flex gap-2">
                        <button @click="saveSmartlink()" :disabled="slLoading || !slForm.url.trim()"
                            class="btn btn-primary flex-1 flex items-center justify-center gap-2 disabled:opacity-50">
                            <div x-show="slLoading" class="spinner spinner-light w-4 h-4"></div>
                            <svg x-show="!slLoading" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                            <span x-text="slLoading ? 'Saving…' : (slForm.id ? 'Update' : 'Save')"></span>
                        </button>
                        <button x-show="slForm.id" @click="resetSlForm()"
                            class="btn btn-outline flex items-center gap-1.5">
                            <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                            Cancel
                        </button>
                    </div>
                    <p x-show="slMsg" x-text="slMsg"
                        :class="slOk ? 'text-emerald-600' : 'text-destructive'"
                        class="text-xs font-medium"></p>
                </div><!-- /.sl-card-body -->
            </div><!-- /.sl-card Smartlink Form -->

            <!-- ── List ── -->
            <div class="sl-card lg:col-span-3">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Smartlinks</h2>
                        <span class="sl-card-count" x-show="smartlinks.length > 0" x-text="smartlinks.length"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <button @click="loadSmartlinks()" :disabled="smartlinksLoading" class="sl-card-refresh">
                            <div x-show="smartlinksLoading" class="spinner w-3 h-3"></div>
                            <svg x-show="!smartlinksLoading" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>

                <div x-show="!smartlinksLoading && smartlinks.length === 0"
                    class="empty-state empty-state-panel mx-4 my-4">
                    <p class="empty-state-title">No smartlinks yet</p>
                    <p class="empty-state-desc">Add data using the form above.</p>
                </div>
                <div x-show="smartlinksLoading" class="flex items-center justify-center py-10 gap-2 text-xs text-muted-foreground">
                    <div class="spinner w-4 h-4"></div> Loading…
                </div>

                <div x-show="!smartlinksLoading && smartlinks.length > 0" class="overflow-x-auto">
                    <table class="w-full tbl">
                        <thead>
                            <tr class="border-b border-border text-muted-foreground">
                                <th scope="col" class="text-left py-2 px-2 font-medium whitespace-nowrap">Country</th>
                                <th scope="col" class="text-left py-2 px-2 font-medium whitespace-nowrap">Device</th>
                                <th scope="col" class="text-left py-2 px-2 font-medium whitespace-nowrap">Network</th>
                                <th scope="col" class="text-left py-2 px-2 font-medium">URL</th>
                                <th scope="col" class="text-right py-2 px-2 font-medium">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <template x-for="sl in smartlinks" :key="sl.id">
                                <tr class="border-b border-border/50 hover:bg-secondary/40 transition-colors"
                                    :class="slForm.id === sl.id ? 'bg-primary/5 ring-1 ring-inset ring-primary/20' : ''">
                                    <td class="py-2 px-2">
                                        <div class="flex flex-wrap gap-0.5">
                                            <template x-for="cc in slParseCountries(sl.country)" :key="cc">
                                                <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
                                                    :class="cc === 'ALL' ? 'bg-secondary text-foreground' : 'bg-primary text-primary-foreground'"
                                                    x-text="cc"></span>
                                            </template>
                                        </div>
                                    </td>
                                    <td class="py-2 px-2 whitespace-nowrap capitalize text-muted-foreground" x-text="sl.device"></td>
                                    <td class="py-2 px-2 whitespace-nowrap">
                                        <span :class="{
                                            'text-emerald-600': sl.network === 'iMonetizeit',
                                            'text-blue-600':    sl.network === 'Lospollos',
                                            'text-orange-500':  sl.network === 'Trafee',
                                            'text-slate-500':   !['iMonetizeit','Lospollos','Trafee'].includes(sl.network)
                                        }" class="font-medium text-xs" x-text="sl.network"></span>
                                    </td>
                                    <td class="py-2 px-2 max-w-[160px]">
                                        <span class="block truncate font-mono text-muted-foreground" :title="sl.url" x-text="sl.url"></span>
                                    </td>
                                    <td class="py-2 px-2 text-right">
                                        <div class="flex items-center justify-end gap-1">
                                            <button @click="editSmartlink(sl)" title="Edit" aria-label="Edit"
                                                class="btn btn-ghost btn-sm px-2 text-blue-500 hover:bg-blue-50">
                                                <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                                            </button>
                                            <button @click="deleteSmartlink(sl.id)" title="Delete" aria-label="Delete"
                                                :disabled="deletingSlId === sl.id"
                                                class="btn btn-ghost btn-sm px-2 text-destructive hover:bg-destructive/10 disabled:opacity-40">
                                                <div x-show="deletingSlId === sl.id" class="spinner spinner-danger w-3 h-3"></div>
                                                <svg x-show="deletingSlId !== sl.id" aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>
    <!-- /TAB: Smartlink -->

    <!-- ══ TAB: System ══ -->
    <div x-show="mainTab==='system'" x-cloak class="space-y-4">

        <!-- Postback Receiver URL -->
        <div class="sl-card">
            <div class="sl-card-header">
                <div class="sl-card-header-left">
                    <svg aria-hidden="true" class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                    <h2 class="sl-card-title">Postback Receiver URL</h2>
                </div>
            </div>
            <div class="sl-card-body space-y-3" x-data="{ showParams: false }">
                <p class="text-xs text-muted-foreground">Set this URL as the <strong class="text-foreground">S2S / Server Postback URL</strong> in your affiliate network. Every conversion fired here is recorded automatically in the Conversions dashboard.</p>
                <div x-show="sys.has_postback_secret" class="notice-box notice-box-amber text-[11px] leading-relaxed">
                    <strong class="text-foreground">Signed mode active</strong> — <code>POSTBACK_SECRET</code> is set. Networks must send a valid <code>ts</code> (unix seconds, within <code>POSTBACK_REPLAY_WINDOW</code>) and an HMAC-SHA256 <code>sig</code> over <code>clickid|payout|status|subid|ts</code> using the shared secret. Requests without a matching <code>sig</code> are rejected by <code>recv.php</code> with <code>401 missing or malformed signature</code>.
                </div>
                <div x-show="!sys.has_postback_secret" class="notice-box notice-box-blue text-[11px] leading-relaxed">
                    <strong class="text-foreground">Unsigned mode</strong> — <code>POSTBACK_SECRET</code> is not set. Any caller that knows the URL can post conversions. For production, set <code>POSTBACK_SECRET</code> in <code>.env</code> to require HMAC-signed postbacks.
                </div>
                <div class="inline-action-row">
                    <code class="text-[12px] font-mono text-foreground flex-1 break-all" x-text="sys.recv_url || 'Loading…'"></code>
                    <button @click="copyVal(sys.recv_url, $el)" type="button"
                        class="btn btn-outline btn-sm shrink-0">
                        Copy
                    </button>
                </div>
                <!-- Parameter table (collapsible) -->
                <button @click="showParams = !showParams" type="button"
                    class="w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg border border-border bg-muted/40 hover:bg-muted/60 transition-colors text-[11px] font-semibold text-foreground">
                    <span class="inline-flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/>
                        </svg>
                        Parameter reference
                        <span class="text-muted-foreground font-normal" x-text="sys.has_postback_secret ? '(5 params)' : '(3 params)'"></span>
                    </span>
                    <svg class="w-3.5 h-3.5 text-muted-foreground transition-transform"
                         :class="showParams ? 'rotate-180' : ''"
                         fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                    </svg>
                </button>
                <div x-show="showParams"
                     x-transition:enter="transition ease-out duration-150"
                     x-transition:enter-start="opacity-0 -translate-y-1"
                     x-transition:enter-end="opacity-100 translate-y-0"
                     x-transition:leave="transition ease-in duration-100"
                     x-transition:leave-start="opacity-100 translate-y-0"
                     x-transition:leave-end="opacity-0 -translate-y-1"
                     class="rounded-lg border border-border overflow-hidden text-[11px]">
                    <div class="grid grid-cols-3 divide-x divide-border border-b border-border bg-muted/50">
                        <div class="px-3 py-1.5 font-semibold text-muted-foreground uppercase tracking-wide">Parameter</div>
                        <div class="px-3 py-1.5 font-semibold text-muted-foreground uppercase tracking-wide">Network Macro</div>
                        <div class="px-3 py-1.5 font-semibold text-muted-foreground uppercase tracking-wide">Description</div>
                    </div>
                    <div class="grid grid-cols-3 divide-x divide-border border-b border-border/60 hover:bg-muted/20">
                        <div class="px-3 py-2">
                            <code class="font-mono font-bold text-primary">clickid</code>
                            <span class="text-destructive ml-0.5">*</span>
                            <span class="block text-muted-foreground/70 text-[10px] mt-0.5">alias: cid, click_id</span>
                        </div>
                        <div class="px-3 py-2 text-muted-foreground font-mono leading-relaxed">
                            {clickid} / {cid} / {click_id}<br>
                            &lt;clickid&gt; / &lt;cid&gt; / &lt;click_id&gt;
                        </div>
                        <div class="px-3 py-2 text-muted-foreground">Unique click ID — base64url encoded, required to attribute the conversion to the correct user</div>
                    </div>
                    <div class="grid grid-cols-3 divide-x divide-border border-b border-border/60 hover:bg-muted/20">
                        <div class="px-3 py-2"><code class="font-mono font-bold text-foreground">payout</code></div>
                        <div class="px-3 py-2 text-muted-foreground font-mono">{payout} / &lt;payout&gt;</div>
                        <div class="px-3 py-2 text-muted-foreground">Conversion value in USD (optional, default 0)</div>
                    </div>
                    <div class="grid grid-cols-3 divide-x divide-border border-b border-border/60 hover:bg-muted/20"
                         :class="sys.has_postback_secret ? '' : ''">
                        <div class="px-3 py-2"><code class="font-mono font-bold text-foreground">status</code></div>
                        <div class="px-3 py-2 text-muted-foreground font-mono">{status} / &lt;status&gt;</div>
                        <div class="px-3 py-2 text-muted-foreground">
                            <span class="inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block"></span>approved</span>
                            <span class="mx-1 text-border">·</span>
                            <span class="inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-400 inline-block"></span>pending</span>
                            <span class="mx-1 text-border">·</span>
                            <span class="inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-red-400 inline-block"></span>rejected</span>
                        </div>
                    </div>
                    <!-- ts / sig rows — only when signed mode is active -->
                    <template x-if="sys.has_postback_secret">
                        <div>
                            <div class="grid grid-cols-3 divide-x divide-border border-b border-border/60 bg-amber-50/50 dark:bg-amber-950/20 hover:bg-amber-100/50">
                                <div class="px-3 py-2">
                                    <code class="font-mono font-bold text-amber-700 dark:text-amber-400">ts</code>
                                    <span class="text-destructive ml-0.5">*</span>
                                    <span class="block text-muted-foreground/70 text-[10px] mt-0.5">unix seconds</span>
                                </div>
                                <div class="px-3 py-2 text-muted-foreground font-mono leading-relaxed">
                                    {ts}<br>
                                    &lt;ts&gt;
                                </div>
                                <div class="px-3 py-2 text-muted-foreground">Request timestamp, must fall within <code class="bg-background border border-border px-1 rounded font-mono">POSTBACK_REPLAY_WINDOW</code> seconds of server time (default 300s)</div>
                            </div>
                            <div class="grid grid-cols-3 divide-x divide-border bg-amber-50/50 dark:bg-amber-950/20 hover:bg-amber-100/50">
                                <div class="px-3 py-2">
                                    <code class="font-mono font-bold text-amber-700 dark:text-amber-400">sig</code>
                                    <span class="text-destructive ml-0.5">*</span>
                                    <span class="block text-muted-foreground/70 text-[10px] mt-0.5">hex, 64 chars</span>
                                </div>
                                <div class="px-3 py-2 text-muted-foreground font-mono leading-relaxed">
                                    {sig}<br>
                                    &lt;sig&gt;
                                </div>
                                <div class="px-3 py-2 text-muted-foreground">
                                    Lowercase HMAC-SHA256 over
                                    <code class="block mt-1 bg-background border border-border px-1.5 py-0.5 rounded font-mono text-[10px]">clickid|payout|status|subid|ts</code>
                                    signed with <code class="bg-background border border-border px-1 rounded font-mono">POSTBACK_SECRET</code>
                                </div>
                            </div>
                        </div>
                    </template>
                </div>
                <!-- How to set up — unsigned mode -->
                <div x-show="!sys.has_postback_secret" class="rounded-lg border border-border bg-muted/30 px-3 py-2.5 space-y-1.5 text-[11px]">
                    <p class="font-semibold text-foreground">How to set up in your affiliate network:</p>
                    <ol class="list-decimal list-inside space-y-1 text-muted-foreground leading-relaxed">
                        <li>Copy the URL above</li>
                        <li>Replace <code class="bg-background border border-border px-1 rounded">{clickid}</code> with the network's subid/clickid macro — the parameter name can be <code class="bg-background border border-border px-1 rounded font-mono">clickid</code>, <code class="bg-background border border-border px-1 rounded font-mono">cid</code>, or <code class="bg-background border border-border px-1 rounded font-mono">click_id</code> (e.g. <code class="bg-background border border-border px-1 rounded font-mono">&amp;clickid=##SUBID##</code>)</li>
                        <li>Replace <code class="bg-background border border-border px-1 rounded">{payout}</code> and <code class="bg-background border border-border px-1 rounded">{status}</code> with the network's payout/status macros</li>
                        <li>Paste the final URL into the <em>Postback / S2S URL</em> field in your affiliate network</li>
                    </ol>
                </div>
                <!-- How to set up — signed mode -->
                <div x-show="sys.has_postback_secret" class="rounded-lg border border-amber-200 dark:border-amber-900/50 bg-amber-50/40 dark:bg-amber-950/20 px-3 py-2.5 space-y-1.5 text-[11px]">
                    <p class="font-semibold text-foreground">How to set up in your affiliate network (signed mode):</p>
                    <ol class="list-decimal list-inside space-y-1 text-muted-foreground leading-relaxed">
                        <li>Copy the URL above</li>
                        <li>Replace <code class="bg-background border border-border px-1 rounded">{clickid}</code>, <code class="bg-background border border-border px-1 rounded">{payout}</code>, <code class="bg-background border border-border px-1 rounded">{status}</code> with the network's macros</li>
                        <li>The network (or your middleware) must compute <code class="bg-background border border-border px-1 rounded font-mono">ts = unix_time()</code> and
                            <code class="bg-background border border-border px-1 rounded font-mono">sig = hmac_sha256(secret, "clickid|payout|status|subid|ts")</code>
                            using the value of <code class="bg-background border border-border px-1 rounded font-mono">POSTBACK_SECRET</code> from <code>.env</code></li>
                        <li>If your network cannot sign requests, either share the secret with them via their webhook settings, or set <code class="bg-background border border-border px-1 rounded font-mono">POSTBACK_SECRET=</code> (empty) in <code>.env</code> to disable signing</li>
                        <li>Legacy networks that omit <code class="bg-background border border-border px-1 rounded font-mono">ts</code> are accepted when <code class="bg-background border border-border px-1 rounded font-mono">POSTBACK_STRICT_TS=0</code>; signature is still required, computed with empty <code class="bg-background border border-border px-1 rounded font-mono">ts</code></li>
                        <li>Paste the final URL into the <em>Postback / S2S URL</em> field in your affiliate network</li>
                    </ol>
                </div>
            </div>
        </div>

        <!-- User Dashboard URL -->
        <div class="sl-card">
            <div class="sl-card-header">
                <div class="sl-card-header-left">
                    <svg aria-hidden="true" class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                    <h2 class="sl-card-title">User Dashboard</h2>
                </div>
            </div>
            <div class="sl-card-body space-y-2">
                <p class="text-xs text-muted-foreground">Per-user dashboard URL format — replace <code class="bg-secondary px-1 rounded">{username}</code> with the account username.</p>
                <div class="inline-action-row">
                    <code class="text-[12px] font-mono text-foreground flex-1 break-all" x-text="sys.sl_url || 'Loading…'"></code>
                    <button @click="copyVal(sys.sl_url, $el)" type="button"
                        class="btn btn-outline btn-sm shrink-0">
                        Copy
                    </button>
                </div>
                <div x-show="sys.sl_url_warnings.length > 0"
                    class="rounded-lg border border-amber-200 bg-amber-50 px-3 py-3 text-xs text-amber-900"
                    x-data="{ open: false }">
                    <button type="button" @click="open = !open" class="flex items-center gap-2.5 w-full text-left font-semibold">
                        <svg aria-hidden="true" class="w-4 h-4 shrink-0 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                        <span class="flex-1">Wildcard dashboard access is not fully configured.</span>
                        <svg class="w-3.5 h-3.5 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                    </button>
                    <div x-show="open" x-transition class="mt-2 pl-6 space-y-2">
                        <template x-for="warning in sys.sl_url_warnings" :key="'system-' + warning">
                            <p class="leading-relaxed" x-text="warning"></p>
                        </template>
                        <p class="text-[11px] text-amber-800/90">After these settings are fixed, the remaining causes are usually outside PHP: wildcard DNS, the cPanel wildcard subdomain, or the tunnel or proxy that should expose that host.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- API Keys + System Status (sejajar) -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">

            <!-- API Keys -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg aria-hidden="true" class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        <h2 class="sl-card-title">API Keys</h2>
                    </div>
                </div>
                <form @submit.prevent="saveApiKeys()" class="sl-card-body space-y-4"
                    x-data="{ showIxg: false, showTinyurl: false, showGsb: false }">

                    <div class="notice-box notice-box-amber text-[11px] leading-relaxed" x-data="{ open: false }">
                        <button type="button" @click="open = !open" class="font-semibold flex items-center justify-between w-full text-left gap-1.5">
                            <span>How API key fields work</span>
                            <svg class="w-3 h-3 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                        </button>
                        <p x-show="open" x-transition class="mt-1">Stored API keys are never echoed back to the browser. Leave a field blank to keep the current server value, or enter a new value to replace it for this save.</p>
                    </div>

                    <!-- IXG -->
                    <div class="section-box space-y-2.5">
                        <div class="flex items-center gap-2">
                            <span class="text-[11px] font-semibold">IXG Short URL</span>
                            <span :class="sys.has_ixg ? 'bg-emerald-100 text-emerald-700' : 'bg-secondary text-muted-foreground'"
                                class="text-[9px] font-semibold px-1.5 py-0.5 rounded uppercase"
                                x-text="sys.has_ixg ? 'Active' : 'Not configured'"></span>
                        </div>
                        <div>
                            <label class="field-label">IXG_API_SECRET</label>
                            <div class="relative">
                                <input :type="showIxg ? 'text' : 'password'" x-model="apiKeys.ixg_secret"
                                    :placeholder="sys.has_ixg ? 'Stored on server' : 'Not configured'"
                                    class="input font-mono text-[12px] pr-9" autocomplete="off">
                                <button type="button" @click="showIxg = !showIxg"
                                    aria-label="Toggle password visibility" :aria-pressed="showIxg.toString()"
                                    class="input-icon-btn">
                                    <svg aria-hidden="true" x-show="!showIxg" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                    <svg x-show="showIxg" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
                                </button>
                            </div>
                        </div>
                        <div>
                            <label class="field-label">IXG_API_URL <span class="text-muted-foreground font-normal">(endpoint API)</span></label>
                            <input type="text" x-model="apiKeys.ixg_url" placeholder="https://api.ixg.llc/..." class="input font-mono text-[12px]">
                        </div>
                    </div>

                    <!-- TinyURL -->
                    <div class="section-box space-y-2.5">
                        <div class="flex items-center gap-2">
                            <span class="text-[11px] font-semibold">TinyURL</span>
                            <span :class="sys.has_tinyurl ? 'bg-emerald-100 text-emerald-700' : 'bg-secondary text-muted-foreground'"
                                class="text-[9px] font-semibold px-1.5 py-0.5 rounded uppercase"
                                x-text="sys.has_tinyurl ? 'Active (API v2)' : 'Free (no token)'"></span>
                        </div>
                        <div>
                            <label class="field-label">TINYURL_API_KEY <span class="text-muted-foreground font-normal">— optional, for custom aliases</span></label>
                            <div class="relative">
                                <input :type="showTinyurl ? 'text' : 'password'" x-model="apiKeys.tinyurl_key"
                                    :placeholder="sys.has_tinyurl ? 'Stored on server' : 'Not configured'"
                                    class="input font-mono text-[12px] pr-9" autocomplete="off">
                                <button type="button" @click="showTinyurl = !showTinyurl"
                                    aria-label="Toggle password visibility" :aria-pressed="showTinyurl.toString()"
                                    class="input-icon-btn">
                                    <svg x-show="!showTinyurl" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                    <svg x-show="showTinyurl" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Google Safe Browsing -->
                    <div class="section-box space-y-2.5">
                        <div class="flex items-center gap-2">
                            <span class="text-[11px] font-semibold">Google Safe Browsing</span>
                            <span :class="sys.has_gsb ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'"
                                class="text-[9px] font-semibold px-1.5 py-0.5 rounded uppercase"
                                x-text="sys.has_gsb ? 'Active' : 'Disabled (heuristic only)'"></span>
                        </div>
                        <div>
                            <label class="field-label">GSB_API_KEY <span class="text-muted-foreground font-normal">— check malicious URLs during redirects</span></label>
                            <div class="relative">
                                <input :type="showGsb ? 'text' : 'password'" x-model="apiKeys.gsb_key"
                                    :placeholder="sys.has_gsb ? 'Stored on server' : 'Not configured'"
                                    class="input font-mono text-[12px] pr-9" autocomplete="off">
                                <button type="button" @click="showGsb = !showGsb"
                                    aria-label="Toggle password visibility" :aria-pressed="showGsb.toString()"
                                    class="input-icon-btn">
                                    <svg x-show="!showGsb" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                    <svg x-show="showGsb" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="flex items-center gap-3">
                        <button type="submit" :disabled="sys.saving"
                            class="btn btn-default btn-sm flex items-center gap-2">
                            <svg x-show="sys.saving" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 22 6.477 22 12h-4z"></path>
                            </svg>
                            <span x-text="sys.saving ? 'Saving…' : 'Save to .env'"></span>
                        </button>
                        <span x-show="sys.saveMsg" x-text="sys.saveMsg"
                            :class="sys.saveOk ? 'text-emerald-600' : 'text-destructive'"
                            class="text-[12px] font-medium"></span>
                    </div>
                </form>
            </div>

            <!-- System Status -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg aria-hidden="true" class="w-3.5 h-3.5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>
                        <h2 class="sl-card-title">System Status</h2>
                    </div>
                </div>
                <div class="sl-card-body">
                    <div class="grid grid-cols-2 gap-2">
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span :class="sys.db_ok ? 'text-emerald-500' : 'text-red-500'">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">Database</p>
                                <p class="text-[11px] font-semibold" x-text="sys.db_info || (sys.db_ok ? 'OK' : 'Error')"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span :class="sys.apcu_ok ? 'text-emerald-500' : 'text-amber-500'">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">APCu Cache</p>
                                <p class="text-[11px] font-semibold" x-text="sys.apcu_ok ? ('Active · ' + (sys.apcu_hit_ratio_percent || 0) + '% hit') : 'Inactive'"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span :class="sys.curl_ok ? 'text-emerald-500' : 'text-red-500'">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">cURL</p>
                                <p class="text-[11px] font-semibold" x-text="sys.curl_ok ? 'Available' : 'Unavailable'"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span class="text-blue-500">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">PHP</p>
                                <p class="text-[11px] font-semibold" x-text="sys.php_ver || '…'"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span :class="sys.queue_worker_running ? 'text-blue-500' : (sys.queue_worker_ok && !sys.queue_worker_stale ? 'text-emerald-500' : 'text-amber-500')">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3-9a3 3 0 11-6 0 3 3 0 016 0zm-3 8a7.962 7.962 0 01-4.906-1.683A6.97 6.97 0 0110 13a6.97 6.97 0 014.906 2.317A7.962 7.962 0 0110 17z" clip-rule="evenodd"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">Queue Worker</p>
                                <p class="text-[11px] font-semibold" x-text="sys.queue_worker_running ? 'Running' : (sys.queue_worker_ok && !sys.queue_worker_stale ? 'Healthy' : 'Needs attention')"></p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 p-2.5 rounded-lg border border-border">
                            <span :class="(sys.queue_depth || 0) > 0 || (sys.queue_failed_depth || 0) > 0 ? 'text-amber-500' : 'text-emerald-500'">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M3 3h14a1 1 0 011 1v3H2V4a1 1 0 011-1zm-1 6h16v7a1 1 0 01-1 1H3a1 1 0 01-1-1V9zm4 2a1 1 0 100 2h8a1 1 0 100-2H6z"/></svg>
                            </span>
                            <div>
                                <p class="text-[10px] text-muted-foreground">Postback Queue</p>
                                <p class="text-[11px] font-semibold" x-text="(sys.queue_depth || 0) + ' queued · ' + (sys.queue_failed_depth || 0) + ' failed'"></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </div><!-- /.grid API Keys + System Status -->

    </div>
    <!-- /TAB: System -->

    <!-- ══ TAB: Analytics ══ -->
    <div x-show="mainTab==='analytics'" x-cloak class="space-y-4">

        <!-- Controls -->
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-2">
                <select x-model="adminAnalyticsUserFilter" @change="loadAdminAnalytics()" class="input text-[12px] w-auto">
                    <option value="">All Users</option>
                    <template x-for="u in adminAnalytics.users" :key="u.id">
                        <option :value="u.id" x-text="u.username"></option>
                    </template>
                </select>
                <select x-model.number="adminAnalyticsDays" @change="loadAdminAnalytics()" class="input text-[12px] w-auto">
                    <option value="7">7 days</option>
                    <option value="14">14 days</option>
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                </select>
            </div>
            <button @click="loadAdminAnalytics()" :disabled="adminAnalyticsLoading"
                class="btn btn-outline btn-sm flex items-center gap-1.5">
                <svg aria-hidden="true" class="w-3.5 h-3.5" :class="adminAnalyticsLoading && 'animate-spin'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                </svg>
                Refresh
            </button>
        </div>

        <!-- Chart -->
        <div class="sl-card">
            <div class="sl-card-header">
                <div class="sl-card-header-left">
                    <h3 class="sl-card-title">Clicks Per Day</h3>
                </div>
                <span class="text-[11px] text-muted-foreground" x-text="adminAnalyticsDays + ' days'"></span>
            </div>
            <div class="analytics-chart-shell">
                <div x-show="adminAnalyticsLoading" class="analytics-chart-overlay analytics-chart-overlay-surface">
                    <div class="spinner w-5 h-5"></div>
                </div>
                <div x-show="!adminAnalyticsLoading && !(adminAnalytics.total > 0)" class="analytics-chart-overlay text-sm text-muted-foreground">
                    No click data yet
                </div>
                <canvas id="adminAnalyticsChart"></canvas>
            </div>
        </div>

        <!-- Breakdown grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">

            <!-- Countries -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <h3 class="sl-card-title">Countries</h3>
                </div>
                <div x-show="!adminAnalytics.by_country?.length" class="py-8 text-center text-xs text-muted-foreground">No data yet</div>
                <div class="divide-y divide-border max-h-60 overflow-y-auto">
                    <template x-for="c in (adminAnalytics.by_country||[])" :key="c.country">
                        <div class="flex items-center justify-between px-3.5 py-2 gap-3">
                            <div class="flex items-center gap-2 min-w-0">
                                <span class="country-flag shrink-0" :class="'country-flag-' + (c.country||'').toLowerCase()" :title="c.country"></span>
                                <span class="text-xs font-medium text-foreground font-mono" x-text="c.country || '—'"></span>
                            </div>
                            <div class="flex items-center gap-2 shrink-0">
                                <div class="h-1 w-16 rounded-full bg-secondary overflow-hidden">
                                    <div class="h-full rounded-full bg-foreground/40 transition-all"
                                        :style="'width:'+Math.round(c.hits/(adminAnalytics.by_country[0]?.hits||1)*100)+'%'"></div>
                                </div>
                                <span class="text-xs text-muted-foreground w-10 text-right" style="font-variant-numeric:tabular-nums" x-text="Number(c.hits).toLocaleString()"></span>
                            </div>
                        </div>
                    </template>
                </div>
            </div>

            <!-- Device + Network -->
            <div class="space-y-4">
                <div class="sl-card">
                    <div class="sl-card-header">
                        <h3 class="sl-card-title">Devices</h3>
                    </div>
                    <div x-show="!adminAnalytics.by_device?.length" class="py-5 text-center text-xs text-muted-foreground">No data yet</div>
                    <div class="divide-y divide-border">
                        <template x-for="d in (adminAnalytics.by_device||[])" :key="d.device">
                            <div class="flex items-center justify-between px-3.5 py-2">
                                <div class="flex items-center gap-2">
                                    <span x-show="d.device === 'wap'" class="text-blue-500">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                                    </span>
                                    <span x-show="d.device !== 'wap'" class="text-muted-foreground">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                                    </span>
                                    <span class="text-xs font-medium text-foreground" x-text="d.device === 'wap' ? 'Mobile' : d.device === 'web' ? 'Desktop' : (d.device||'—')"></span>
                                </div>
                                <span class="text-xs text-muted-foreground" style="font-variant-numeric:tabular-nums" x-text="Number(d.hits).toLocaleString()"></span>
                            </div>
                        </template>
                    </div>
                </div>
                <div class="sl-card">
                    <div class="sl-card-header">
                        <h3 class="sl-card-title">Traffic Sources</h3>
                    </div>
                    <div x-show="!adminAnalytics.by_network?.length" class="py-5 text-center text-xs text-muted-foreground">No data yet</div>
                    <div class="divide-y divide-border">
                        <template x-for="n in (adminAnalytics.by_network||[])" :key="n.network">
                            <div class="flex items-center justify-between px-3.5 py-2">
                                <span class="text-xs font-medium text-foreground capitalize" x-text="n.network || 'direct'"></span>
                                <span class="text-xs text-muted-foreground" style="font-variant-numeric:tabular-nums" x-text="Number(n.hits).toLocaleString()"></span>
                            </div>
                        </template>
                    </div>
                </div>
            </div>

            <!-- Top Links -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <h3 class="sl-card-title">Top Link</h3>
                </div>
                <div x-show="!adminAnalytics.by_link?.length" class="py-8 text-center text-xs text-muted-foreground">No data yet</div>
                <div class="divide-y divide-border max-h-72 overflow-y-auto">
                    <template x-for="(l, i) in (adminAnalytics.by_link||[])" :key="l.slug">
                        <div class="flex items-center gap-2 px-3.5 py-2">
                            <span class="text-muted-foreground w-4 shrink-0" style="font-size:10px;font-variant-numeric:tabular-nums" x-text="i+1"></span>
                            <span class="font-mono text-foreground truncate flex-1" style="font-size:11px" x-text="l.slug"></span>
                            <span class="text-muted-foreground truncate" style="font-size:10px;max-width:30%" x-show="l.username" x-text="l.username"></span>
                            <span class="text-xs font-semibold text-foreground shrink-0" style="font-variant-numeric:tabular-nums" x-text="Number(l.hits).toLocaleString()"></span>
                        </div>
                    </template>
                </div>
            </div>

        </div>
    </div>
    <!-- /TAB: Analytics -->

    <!-- ══ TAB: Conversion ══ -->
    <div x-show="mainTab==='conversion'" x-cloak class="space-y-4">

        <!-- Sub-tab + controls -->
        <div class="flex items-center justify-between gap-3">
            <div role="tablist" class="flex gap-0.5 bg-secondary/50 p-0.5 rounded-lg">
                <button @click="setAdminConvTab('clicks')" type="button"
                    role="tab" :aria-selected="(adminConv.subTab === 'clicks').toString()"
                                    :class="adminConv.subTab === 'clicks' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                    class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                    <span class="relative flex h-2 w-2" x-show="adminConv.live">
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                    Live Clicks
                    <span class="text-[10px] text-muted-foreground" x-text="'(' + adminConv.clicks.length + ')'"></span>
                </button>
                <button @click="setAdminConvTab('conversions')" type="button"
                    role="tab" :aria-selected="(adminConv.subTab === 'conversions').toString()"
                                    :class="adminConv.subTab === 'conversions' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                    class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                    Conversions
                    <span class="text-[10px] text-muted-foreground" x-text="'(' + adminConv.conversions.length + ')'"></span>
                </button>
                <button @click="setAdminConvTab('stats')" type="button"
                    role="tab" :aria-selected="(adminConv.subTab === 'stats').toString()"
                                    :class="adminConv.subTab === 'stats' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                    class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                    <svg aria-hidden="true" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                    </svg>
                    Stats
                </button>
                <button @click="setAdminConvTab('subid')" type="button"
                    role="tab" :aria-selected="(adminConv.subTab === 'subid').toString()"
                                    :class="adminConv.subTab === 'subid' ? 'bg-white text-foreground' : 'text-muted-foreground hover:text-foreground'"
                    class="px-3 py-1 text-[12px] font-medium rounded-md transition-all flex items-center gap-1.5">
                    <svg aria-hidden="true" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                    </svg>
                    Performance
                </button>
            </div>
            <div class="flex items-center gap-2">
                <span class="text-[11px] text-muted-foreground" x-show="adminConv.live">Auto-refresh 5s</span>
                <button @click="adminConv.live ? stopAdminConvPoll() : startAdminConvPoll()" type="button"
                    :class="adminConv.live ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-secondary text-muted-foreground'"
                    class="px-2.5 py-1 text-[11px] font-medium border rounded-md transition-all"
                    x-text="adminConv.live ? 'Pause' : 'Resume'">
                </button>
                <button @click="loadAdminLiveFeed()" type="button" :disabled="adminConv.loading"
                    class="btn btn-outline btn-sm text-[11px] px-2.5">
                    <svg aria-hidden="true" x-show="!adminConv.loading" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    <svg x-show="adminConv.loading" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 22 6.477 22 12h-4z"></path>
                    </svg>
                </button>
            </div>
        </div>

        <!-- Live Clicks -->
        <div x-show="adminConv.subTab === 'clicks'"
             x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Live Clicks</h2>
                        <span class="sl-card-count" x-text="adminClFiltered.length"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <div class="relative">
                            <svg class="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0"/></svg>
                            <input type="text" x-model="adminConv.clSearch" @input="resetAdminClickPage()" placeholder="Search…"
                                class="input text-[11px] pl-6 h-7 w-40 sm:w-52">
                        </div>
                    </div>
                </div>
                <div class="overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="w-full tbl text-[11px]">
                            <thead>
                                <tr>
                                    <th @click="adminClSortBy('created_at')" @keydown.enter="adminClSortBy('created_at')" tabindex="0" scope="col" class="sortable whitespace-nowrap">Time <span x-show="adminConv.clSort==='created_at'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('slug')" @keydown.enter="adminClSortBy('slug')" tabindex="0" scope="col" class="sortable">Slug <span x-show="adminConv.clSort==='slug'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('subid')" @keydown.enter="adminClSortBy('subid')" tabindex="0" scope="col" class="sortable">Subid <span x-show="adminConv.clSort==='subid'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('country')" @keydown.enter="adminClSortBy('country')" tabindex="0" scope="col" class="sortable">Country <span x-show="adminConv.clSort==='country'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('device')" @keydown.enter="adminClSortBy('device')" tabindex="0" scope="col" class="sortable">Device <span x-show="adminConv.clSort==='device'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('network')" @keydown.enter="adminClSortBy('network')" tabindex="0" scope="col" class="sortable">Network <span x-show="adminConv.clSort==='network'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminClSortBy('ip')" @keydown.enter="adminClSortBy('ip')" tabindex="0" scope="col" class="sortable">IP <span x-show="adminConv.clSort==='ip'" x-text="adminConv.clSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr x-show="adminClFiltered.length === 0">
                                    <td colspan="7" class="text-center text-muted-foreground py-10 text-xs">No clicks yet</td>
                                </tr>
                                <template x-for="c in adminClPaged" :key="c.id">
                                    <tr :class="{ 'click-row-new': adminConv.freshIds[c.id], 'border-b border-border hover:bg-secondary/20': true }">
                                        <td class="px-3 py-1.5 text-muted-foreground whitespace-nowrap" x-text="adminConvRelTime(c.created_at)"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-foreground" x-text="c.slug || '—'"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-foreground" x-text="c.subid || '—'" :title="c.subid"></td>
                                        <td class="px-3 py-1.5"><span class="inline-flex items-center gap-1"><span class="country-flag shrink-0" :class="'country-flag-' + (c.country||'').toLowerCase()" :title="c.country"></span><span class="font-mono text-[10px]" x-text="c.country || '—'"></span></span></td>
                                        <td class="px-3 py-1.5"><span x-show="c.device === 'wap'" class="text-blue-500"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg></span><span x-show="c.device !== 'wap'" class="text-muted-foreground"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg></span></td>
                                        <td class="px-3 py-1.5 text-muted-foreground" x-text="c.network || 'Direct'"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-muted-foreground" x-text="c.ip || '—'"></td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                    <div x-show="adminClTotalPages > 1" class="px-3 py-2.5 border-t border-border flex items-center justify-between gap-2">
                        <span class="text-[11px] text-muted-foreground">
                            <span x-text="(adminConv.clPage-1)*adminConv.perPage+1"></span>–<span x-text="Math.min(adminConv.clPage*adminConv.perPage, adminClFiltered.length)"></span>
                            <span class="text-muted-foreground/60"> of </span><span x-text="adminClFiltered.length"></span>
                        </span>
                        <div class="flex items-center gap-1">
                            <button @click="setAdminClickPage(1)" :disabled="adminConv.clPage===1" class="pg-btn">«</button>
                            <button @click="changeAdminClickPage(-1)" :disabled="adminConv.clPage===1" class="pg-btn">‹</button>
                            <span class="pg-btn active pointer-events-none" x-text="adminConv.clPage + ' / ' + adminClTotalPages"></span>
                            <button @click="changeAdminClickPage(1)" :disabled="adminConv.clPage>=adminClTotalPages" class="pg-btn">›</button>
                            <button @click="setAdminClickPage(adminClTotalPages)" :disabled="adminConv.clPage>=adminClTotalPages" class="pg-btn">»</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Conversions -->
        <div x-show="adminConv.subTab === 'conversions'"
             x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <h2 class="sl-card-title">Conversions</h2>
                        <span class="sl-card-count" x-text="adminCvFiltered.length"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <div class="relative">
                            <svg class="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0"/></svg>
                            <input type="text" x-model="adminConv.cvSearch" @input="resetAdminConversionPage()" placeholder="Search…"
                                class="input text-[11px] pl-6 h-7 w-40 sm:w-52">
                        </div>
                    </div>
                </div>
                <div class="overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="w-full tbl text-[11px]">
                            <thead>
                                <tr>
                                    <th @click="adminCvSortBy('created_at')" @keydown.enter="adminCvSortBy('created_at')" tabindex="0" scope="col" class="sortable whitespace-nowrap">Time <span x-show="adminConv.cvSort==='created_at'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('slug')" @keydown.enter="adminCvSortBy('slug')" tabindex="0" scope="col" class="sortable">Slug <span x-show="adminConv.cvSort==='slug'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('subid')" @keydown.enter="adminCvSortBy('subid')" tabindex="0" scope="col" class="sortable">Subid <span x-show="adminConv.cvSort==='subid'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('country')" @keydown.enter="adminCvSortBy('country')" tabindex="0" scope="col" class="sortable">Country <span x-show="adminConv.cvSort==='country'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('device')" @keydown.enter="adminCvSortBy('device')" tabindex="0" scope="col" class="sortable">Device <span x-show="adminConv.cvSort==='device'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('network')" @keydown.enter="adminCvSortBy('network')" tabindex="0" scope="col" class="sortable">Network <span x-show="adminConv.cvSort==='network'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('payout')" @keydown.enter="adminCvSortBy('payout')" tabindex="0" scope="col" class="sortable">Payout <span x-show="adminConv.cvSort==='payout'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th @click="adminCvSortBy('ip')" @keydown.enter="adminCvSortBy('ip')" tabindex="0" scope="col" class="sortable">IP <span x-show="adminConv.cvSort==='ip'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                    <th scope="col">Clickid</th>
                                    <th @click="adminCvSortBy('status')" @keydown.enter="adminCvSortBy('status')" tabindex="0" scope="col" class="sortable">Status <span x-show="adminConv.cvSort==='status'" x-text="adminConv.cvSortDir==='asc'?'↑':'↓'" class="text-blue-500 ml-0.5"></span></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr x-show="adminCvFiltered.length === 0">
                                    <td colspan="10" class="text-center text-muted-foreground py-10 text-xs">No conversions yet</td>
                                </tr>
                                <template x-for="v in adminCvPaged" :key="v.id">
                                    <tr :class="{ 'conv-new-row': adminConv.newConvIds[v.id], 'border-b border-border hover:bg-secondary/20': true }" class="transition-colors duration-700">
                                        <td class="px-3 py-1.5 text-muted-foreground whitespace-nowrap" x-text="adminConvRelTime(v.created_at)"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-foreground" x-text="v.slug || '—'"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-foreground" x-text="v.subid || '—'" :title="v.subid"></td>
                                        <td class="px-3 py-1.5"><span class="inline-flex items-center gap-1"><span class="country-flag shrink-0" :class="'country-flag-' + (v.country||'').toLowerCase()" :title="v.country"></span><span class="font-mono text-[10px]" x-text="v.country || '—'"></span></span></td>
                                        <td class="px-3 py-1.5"><span x-show="v.device === 'wap'" class="text-blue-500"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg></span><span x-show="v.device !== 'wap'" class="text-muted-foreground"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg></span></td>
                                        <td class="px-3 py-1.5 text-muted-foreground" x-text="v.network || '—'"></td>
                                        <td class="px-3 py-1.5 font-semibold text-emerald-600" x-text="v.payout > 0 ? '$' + Number(v.payout).toFixed(2) : '—'"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-muted-foreground" x-text="v.ip || '—'"></td>
                                        <td class="px-3 py-1.5 font-mono text-[10px] text-muted-foreground max-w-[100px] truncate cursor-pointer hover:text-foreground"
                                            @click="copyVal(v.clickid)" :title="v.clickid"
                                            x-text="v.clickid ? v.clickid.substring(0,12)+'…' : '—'"></td>
                                        <td class="px-3 py-1.5">
                                            <span :class="{
                                                'status-approved': v.status === 'approved',
                                                'status-pending':  v.status === 'pending',
                                                'status-rejected': v.status === 'rejected',
                                                'status-default':  !['approved','pending','rejected'].includes(v.status)
                                            }" class="status-badge" x-text="v.status"></span>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                    <div x-show="adminCvTotalPages > 1" class="px-3 py-2.5 border-t border-border flex items-center justify-between gap-2">
                        <span class="text-[11px] text-muted-foreground">
                            <span x-text="(adminConv.cvPage-1)*adminConv.perPage+1"></span>–<span x-text="Math.min(adminConv.cvPage*adminConv.perPage, adminCvFiltered.length)"></span>
                            <span class="text-muted-foreground/60"> of </span><span x-text="adminCvFiltered.length"></span>
                        </span>
                        <div class="flex items-center gap-1">
                            <button @click="setAdminConversionPage(1)" :disabled="adminConv.cvPage===1" class="pg-btn">«</button>
                            <button @click="changeAdminConversionPage(-1)" :disabled="adminConv.cvPage===1" class="pg-btn">‹</button>
                            <span class="pg-btn active pointer-events-none" x-text="adminConv.cvPage + ' / ' + adminCvTotalPages"></span>
                            <button @click="changeAdminConversionPage(1)" :disabled="adminConv.cvPage>=adminCvTotalPages" class="pg-btn">›</button>
                            <button @click="setAdminConversionPage(adminCvTotalPages)" :disabled="adminConv.cvPage>=adminCvTotalPages" class="pg-btn">»</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ══ Stats ══ -->
        <div x-show="adminConv.subTab === 'stats'" class="space-y-4"
             x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">

            <!-- Date range controls -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                        </svg>
                        <h2 class="sl-card-title">Conversion Stats</h2>
                    </div>
                    <div class="sl-card-header-right">
                        <div class="flex flex-wrap items-center gap-2">
                            <select x-model="convStats.datePreset" @change="applyDatePreset()" class="input h-7 text-[11px] w-36">
                                <option value="today">Today</option>
                                <option value="yesterday">Yesterday</option>
                                <option value="7d">Last 7 days</option>
                                <option value="14d">Last 14 days</option>
                                <option value="30d">Last 30 days</option>
                                <option value="this_month">This month</option>
                                <option value="last_month">Last month</option>
                                <option value="custom">Custom</option>
                            </select>
                            <template x-if="convStats.datePreset === 'custom'">
                                <div class="flex items-center gap-2">
                                    <input type="date" x-model="convStats.dateFrom" class="input h-7 text-[11px] w-32">
                                    <span class="text-[11px] text-muted-foreground">—</span>
                                    <input type="date" x-model="convStats.dateTo" class="input h-7 text-[11px] w-32">
                                    <button @click="loadConvStats()" :disabled="convStats.loading"
                                        class="btn btn-primary btn-sm text-[11px] px-3 flex items-center gap-1.5">
                                        <div x-show="convStats.loading" class="spinner w-3.5 h-3.5"></div>
                                        <span x-show="!convStats.loading">Show</span>
                                    </button>
                                </div>
                            </template>
                            <div x-show="convStats.loading && convStats.datePreset !== 'custom'" class="spinner w-3.5 h-3.5"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Empty state -->
            <div x-show="!convStats.loading && !convStats.data.daily.length" class="sl-card">
                <div class="flex flex-col items-center justify-center py-16 text-center">
                    <svg class="w-10 h-10 text-muted-foreground/30 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                    </svg>
                    <p class="text-sm text-muted-foreground font-medium">Select a date range and click Show</p>
                    <p class="text-xs text-muted-foreground/60 mt-1">Click and conversion data will appear here</p>
                </div>
            </div>

            <!-- Content (shown after data loaded) -->
            <template x-if="convStats.data.daily.length > 0">
                <div class="space-y-4">

                    <!-- Summary cards -->
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <!-- Total Clicks -->
                        <div class="stat-card stat-card-blue">
                            <div class="stat-card-label">Total Clicks</div>
                            <div class="stat-card-value" x-text="Number(convStats.data.total_clicks).toLocaleString()">0</div>
                            <div class="stat-card-sub">Within the selected date range</div>
                        </div>
                        <!-- Conversions -->
                        <div class="stat-card stat-card-emerald">
                            <div class="stat-card-label">Conversions</div>
                            <div class="stat-card-value" x-text="Number(convStats.data.total_conv).toLocaleString()">0</div>
                            <div class="stat-card-sub">Total conversions</div>
                        </div>
                        <!-- Revenue -->
                        <div class="stat-card stat-card-amber">
                            <div class="stat-card-label">Revenue</div>
                            <div class="stat-card-value" x-text="'$' + Number(convStats.data.total_rev).toFixed(2)">$0.00</div>
                            <div class="stat-card-sub">Total payout</div>
                        </div>
                        <!-- Conv. Rate -->
                        <div class="stat-card stat-card-violet">
                            <div class="stat-card-label">Conv. Rate</div>
                            <div class="stat-card-value" x-text="convStats.data.cr + '%'">0%</div>
                            <div class="stat-card-sub">Clicks to conversions</div>
                        </div>
                    </div>

                    <!-- Daily Table -->
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <div class="sl-card-header-left">
                                <h2 class="sl-card-title">Daily Breakdown</h2>
                                <span class="sl-card-count" x-text="convStats.data.daily.length + ' days'"></span>
                            </div>
                        </div>
                        <div class="overflow-x-auto">
                            <div class="tbl-wrap">
                            <table class="tbl w-full table-fixed" style="font-variant-numeric:tabular-nums;font-size:11px">
                                <colgroup>
                                    <col style="width:100px"><!-- Date -->
                                    <col style="width:72px"><!-- Clicks -->
                                    <col style="width:72px"><!-- Conv -->
                                    <col style="width:92px"><!-- Payout -->
                                    <col style="width:88px"><!-- Approved -->
                                    <col style="width:80px"><!-- Pending -->
                                    <col style="width:80px"><!-- Rejected -->
                                    <col style="width:56px"><!-- CR -->
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th scope="col">Date</th>
                                        <th scope="col" class="text-right">Clicks</th>
                                        <th scope="col" class="text-right">Conv</th>
                                        <th scope="col" class="text-right">Payout</th>
                                        <th scope="col" class="text-right">Approved</th>
                                        <th scope="col" class="text-right">Pending</th>
                                        <th scope="col" class="text-right">Rejected</th>
                                        <th scope="col" class="text-right">CR</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template x-for="(row, ri) in adminDailySorted" :key="row.date">
                                        <tr class="hover:bg-secondary/20 border-b border-border/50"
                                            :class="row.conversions > 0 ? 'font-medium' : 'text-muted-foreground'">
                                            <td class="px-3 py-1.5 font-mono font-semibold" style="font-size:10px" x-text="row.date"></td>
                                            <td class="px-3 py-1.5 text-right" :class="row.clicks > 0 ? 'text-sky-600 font-semibold' : ''" x-text="row.clicks > 0 ? Number(row.clicks).toLocaleString() : '—'"></td>
                                            <td class="px-3 py-1.5 text-right" x-text="row.conversions > 0 ? Number(row.conversions).toLocaleString() : '—'"></td>
                                            <td class="px-3 py-1.5 text-right" :class="row.payout > 0 ? 'font-bold text-emerald-700' : ''" x-text="row.payout > 0 ? '$' + Number(row.payout).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-1.5 text-right text-emerald-600" x-text="row.approved > 0 ? '$' + Number(row.approved).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-1.5 text-right text-amber-600" x-text="row.pending > 0 ? '$' + Number(row.pending).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-1.5 text-right text-red-400" x-text="row.rejected > 0 ? '$' + Number(row.rejected).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-1.5 text-right" x-text="row.clicks > 0 ? (row.conversions / row.clicks * 100).toFixed(1) + '%' : '—'"></td>
                                        </tr>
                                    </template>
                                </tbody>
                                <tfoot>
                                    <tr class="analytics-report-total-row">
                                        <td class="px-3 py-2 font-semibold" style="font-size:11px">Total</td>
                                        <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_clicks).toLocaleString()"></td>
                                        <td class="px-3 py-2 text-right font-semibold" x-text="Number(convStats.data.total_conv).toLocaleString()"></td>
                                        <td class="px-3 py-2 text-right font-bold" style="font-size:13px" x-text="'$' + Number(convStats.data.total_rev).toFixed(2)"></td>
                                        <td colspan="3"></td>
                                        <td class="px-3 py-2 text-right text-muted-foreground" x-text="convStats.data.cr + '%'"></td>
                                    </tr>
                                </tfoot>
                            </table>
                            </div>
                        </div>
                    </div>

                    <!-- Breakdown grid -->
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">

                        <!-- By Country -->
                        <div class="sl-card">
                            <div class="sl-card-header">
                                <div class="sl-card-header-left">
                                    <h2 class="sl-card-title">Top Countries</h2>
                                    <span class="sl-card-count" x-show="convStats.data.by_country.length > 0" x-text="convStats.data.by_country.length"></span>
                                </div>
                            </div>
                            <div x-show="convStats.data.by_country.length === 0" class="py-8 text-center text-xs text-muted-foreground">No data</div>
                            <div x-show="convStats.data.by_country.length > 0">
                                <div class="overflow-x-auto">
                                <div class="tbl-wrap">
                                <table class="tbl w-full table-fixed" style="font-variant-numeric:tabular-nums;font-size:11px">
                                    <colgroup>
                                        <col>
                                        <col style="width:96px">
                                        <col style="width:80px">
                                    </colgroup>
                                    <thead>
                                        <tr>
                                            <th scope="col">Country</th>
                                            <th scope="col" class="text-right">Clicks</th>
                                            <th scope="col" class="text-right">%</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <template x-for="(row, i) in csCountryPaged" :key="i">
                                            <tr class="border-b border-border/50 hover:bg-secondary/20">
                                                <td class="px-3 py-1.5 font-mono font-semibold" style="font-size:10px" x-text="row.country || '—'"></td>
                                                <td class="px-3 py-1.5 text-right font-medium" x-text="Number(row.n).toLocaleString()"></td>
                                                <td class="px-3 py-1.5 text-right text-muted-foreground"
                                                    x-text="convStats.data.total_clicks > 0 ? (row.n / convStats.data.total_clicks * 100).toFixed(1) + '%' : '—'"></td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                                </div>
                                </div>
                                <div x-show="csCountryTotalPages > 1" class="px-3 py-2 border-t border-border flex items-center justify-between gap-2 text-[11px]">
                                    <span class="text-muted-foreground" x-text="((convStats.countryPage-1)*convStats.statsPerPage+1)+'-'+Math.min(convStats.countryPage*convStats.statsPerPage,convStats.data.by_country.length)+' / '+convStats.data.by_country.length"></span>
                                    <div class="flex items-center gap-1">
                                        <button @click="convStats.countryPage=1" :disabled="convStats.countryPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">«</button>
                                        <button @click="convStats.countryPage--" :disabled="convStats.countryPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">‹</button>
                                        <span class="px-1 text-muted-foreground" x-text="convStats.countryPage+' / '+csCountryTotalPages"></span>
                                        <button @click="convStats.countryPage++" :disabled="convStats.countryPage>=csCountryTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">›</button>
                                        <button @click="convStats.countryPage=csCountryTotalPages" :disabled="convStats.countryPage>=csCountryTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">»</button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- By Network -->
                        <div class="sl-card">
                            <div class="sl-card-header">
                                <div class="sl-card-header-left">
                                    <h2 class="sl-card-title">Top Network</h2>
                                    <span class="sl-card-count" x-show="convStats.data.by_network.length > 0" x-text="convStats.data.by_network.length"></span>
                                </div>
                            </div>
                            <div x-show="convStats.data.by_network.length === 0" class="py-8 text-center text-xs text-muted-foreground">No data</div>
                            <div x-show="convStats.data.by_network.length > 0">
                                <div class="overflow-x-auto">
                                <div class="tbl-wrap">
                                <table class="tbl w-full table-fixed" style="font-variant-numeric:tabular-nums;font-size:11px">
                                    <colgroup>
                                        <col>
                                        <col style="width:96px">
                                        <col style="width:80px">
                                    </colgroup>
                                    <thead>
                                        <tr>
                                            <th scope="col">Network</th>
                                            <th scope="col" class="text-right">Clicks</th>
                                            <th scope="col" class="text-right">%</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <template x-for="(row, i) in csNetworkPaged" :key="i">
                                            <tr class="border-b border-border/50 hover:bg-secondary/20">
                                                <td class="px-3 py-1.5 font-medium" x-text="row.network || '—'"></td>
                                                <td class="px-3 py-1.5 text-right" x-text="Number(row.n).toLocaleString()"></td>
                                                <td class="px-3 py-1.5 text-right text-muted-foreground"
                                                    x-text="convStats.data.total_clicks > 0 ? (row.n / convStats.data.total_clicks * 100).toFixed(1) + '%' : '—'"></td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                                </div>
                                </div>
                                <div x-show="csNetworkTotalPages > 1" class="px-3 py-2 border-t border-border flex items-center justify-between gap-2 text-[11px]">
                                    <span class="text-muted-foreground" x-text="((convStats.networkPage-1)*convStats.statsPerPage+1)+'-'+Math.min(convStats.networkPage*convStats.statsPerPage,convStats.data.by_network.length)+' / '+convStats.data.by_network.length"></span>
                                    <div class="flex items-center gap-1">
                                        <button @click="convStats.networkPage=1" :disabled="convStats.networkPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">«</button>
                                        <button @click="convStats.networkPage--" :disabled="convStats.networkPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">‹</button>
                                        <span class="px-1 text-muted-foreground" x-text="convStats.networkPage+' / '+csNetworkTotalPages"></span>
                                        <button @click="convStats.networkPage++" :disabled="convStats.networkPage>=csNetworkTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">›</button>
                                        <button @click="convStats.networkPage=csNetworkTotalPages" :disabled="convStats.networkPage>=csNetworkTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">»</button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- By Status (conversions) -->
                        <div class="sl-card" x-show="convStats.data.by_status.length > 0">
                            <div class="sl-card-header">
                                <div class="sl-card-header-left">
                                    <h2 class="sl-card-title">Conversion Status</h2>
                                </div>
                            </div>
                            <div class="overflow-x-auto">
                                <div class="tbl-wrap">
                                <table class="tbl w-full" style="font-variant-numeric:tabular-nums;font-size:11px">
                                    <colgroup>
                                        <col>
                                        <col style="width:80px">
                                        <col style="width:96px">
                                    </colgroup>
                                    <thead>
                                        <tr>
                                            <th scope="col">Status</th>
                                            <th scope="col" class="text-right">Count</th>
                                            <th scope="col" class="text-right">Revenue</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <template x-for="(row, i) in convStats.data.by_status" :key="i">
                                            <tr class="border-b border-border/50 hover:bg-secondary/20">
                                                <td class="px-3 py-1.5">
                                                    <span :class="{
                                                        'status-approved': row.status === 'approved',
                                                        'status-pending':  row.status === 'pending',
                                                        'status-rejected': row.status === 'rejected',
                                                        'status-default':  !['approved','pending','rejected'].includes(row.status)
                                                    }" class="status-badge" x-text="row.status"></span>
                                                </td>
                                                <td class="px-3 py-1.5 text-right font-medium" x-text="Number(row.n).toLocaleString()"></td>
                                                <td class="px-3 py-1.5 text-right font-semibold text-emerald-600"
                                                    x-text="row.rev > 0 ? '$' + Number(row.rev).toFixed(2) : '—'"></td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                                </div>
                            </div>
                        </div>

                        <!-- By Slug / Offer -->
                        <div class="sl-card" x-show="convStats.data.by_slug.length > 0">
                            <div class="sl-card-header">
                                <div class="sl-card-header-left">
                                    <h2 class="sl-card-title">Top Slug / Offer</h2>
                                    <span class="sl-card-count" x-text="convStats.data.by_slug.length"></span>
                                </div>
                            </div>
                            <div class="overflow-x-auto">
                                <div class="tbl-wrap">
                                <table class="tbl w-full" style="font-variant-numeric:tabular-nums;font-size:11px">
                                    <colgroup>
                                        <col>
                                        <col style="width:96px">
                                        <col style="width:96px">
                                    </colgroup>
                                    <thead>
                                        <tr>
                                            <th scope="col">Slug</th>
                                            <th scope="col" class="text-right">Conversions</th>
                                            <th scope="col" class="text-right">Revenue</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <template x-for="(row, i) in convStats.data.by_slug" :key="i">
                                            <tr class="border-b border-border/50 hover:bg-secondary/20">
                                                <td class="px-3 py-1.5 font-mono font-semibold" style="font-size:10px" x-text="row.slug || '—'"></td>
                                                <td class="px-3 py-1.5 text-right font-medium" x-text="Number(row.n).toLocaleString()"></td>
                                                <td class="px-3 py-1.5 text-right font-semibold text-emerald-600"
                                                    x-text="row.rev > 0 ? '$' + Number(row.rev).toFixed(2) : '—'"></td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                                </div>
                            </div>
                        </div>

                    </div><!-- /breakdown grid -->

                    <!-- Payout by User (full width) -->
                    <div class="sl-card">
                        <div class="sl-card-header">
                            <div class="sl-card-header-left">
                                <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                                </svg>
                                <h2 class="sl-card-title">Total Payout per User</h2>
                                <span class="sl-card-count" x-text="convStats.data.by_user.length + ' users'"></span>
                            </div>
                            <div class="sl-card-header-right">
                                <span class="text-[11px] text-muted-foreground"
                                    x-text="convStats.dateFrom + ' to ' + convStats.dateTo"></span>
                            </div>
                        </div>
                        <div class="overflow-x-auto">
                            <div class="tbl-wrap">
                            <table class="tbl w-full table-fixed" style="font-variant-numeric:tabular-nums;font-size:11px">
                                <colgroup>
                                    <col style="width:32px"><!-- # -->
                                    <col><!-- User: auto -->
                                    <col style="width:80px"><!-- Conversions -->
                                    <col style="width:96px"><!-- Total Payout -->
                                    <col style="width:88px"><!-- Approved -->
                                    <col style="width:80px"><!-- Pending -->
                                    <col style="width:80px"><!-- Rejected -->
                                    <col style="width:120px"><!-- % of Total -->
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th scope="col">#</th>
                                        <th scope="col">User</th>
                                        <th scope="col" class="text-right">Conversions</th>
                                        <th scope="col" class="text-right">Total Payout</th>
                                        <th scope="col" class="text-right text-emerald-600">Approved</th>
                                        <th scope="col" class="text-right text-amber-600">Pending</th>
                                        <th scope="col" class="text-right text-red-500">Rejected</th>
                                        <th scope="col" class="text-right">% of Total</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template x-for="(row, i) in csUserPaged" :key="row.user_id">
                                        <tr class="border-b border-border/50 hover:bg-secondary/20">
                                            <td class="px-3 py-2 text-muted-foreground text-center" x-text="(convStats.userPage-1)*convStats.statsPerPage+i+1"></td>
                                            <td class="px-3 py-2">
                                                <div class="flex items-center gap-2">
                                                    <div class="w-6 h-6 rounded-full bg-secondary flex items-center justify-center flex-shrink-0">
                                                        <span class="font-bold text-muted-foreground uppercase" style="font-size:9px"
                                                            x-text="(row.username || '?').charAt(0)"></span>
                                                    </div>
                                                    <div>
                                                        <div class="font-semibold text-foreground" x-text="row.username || '—'"></div>
                                                        <div class="text-muted-foreground" style="font-size:10px" x-text="'ID: ' + row.user_id"></div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td class="px-3 py-2 text-right font-medium" x-text="Number(row.conv_count).toLocaleString()"></td>
                                            <td class="px-3 py-2 text-right">
                                                <span class="font-bold text-foreground" style="font-size:13px"
                                                    x-text="'$' + Number(row.total_payout).toFixed(2)"></span>
                                            </td>
                                            <td class="px-3 py-2 text-right font-semibold text-emerald-600"
                                                x-text="row.approved_payout > 0 ? '$' + Number(row.approved_payout).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-2 text-right font-medium text-amber-600"
                                                x-text="row.pending_payout > 0 ? '$' + Number(row.pending_payout).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-2 text-right text-red-400"
                                                x-text="row.rejected_payout > 0 ? '$' + Number(row.rejected_payout).toFixed(2) : '—'"></td>
                                            <td class="px-3 py-2 text-right">
                                                <div class="flex items-center justify-end gap-2">
                                                    <div class="w-16 bg-secondary rounded-full h-1.5 overflow-hidden">
                                                        <div class="h-full rounded-full metric-share-fill"
                                                            :style="'width:' + (convStats.data.total_rev > 0 ? Math.min(100,(row.total_payout/convStats.data.total_rev*100)).toFixed(1) : 0) + '%'">
                                                        </div>
                                                    </div>
                                                    <span class="text-muted-foreground w-10 text-right"
                                                        x-text="convStats.data.total_rev > 0 ? (row.total_payout/convStats.data.total_rev*100).toFixed(1)+'%' : '—'"></span>
                                                </div>
                                            </td>
                                        </tr>
                                    </template>
                                </tbody>
                                <tfoot x-show="convStats.data.by_user.length > 1">
                                    <tr class="analytics-report-total-row">
                                        <td colspan="2" class="px-3 py-2 font-semibold" style="font-size:11px">Total</td>
                                        <td class="px-3 py-2 text-right font-semibold"
                                            x-text="Number(convStats.data.total_conv).toLocaleString()"></td>
                                        <td class="px-3 py-2 text-right font-bold" style="font-size:13px"
                                            x-text="'$' + Number(convStats.data.total_rev).toFixed(2)"></td>
                                        <td class="px-3 py-2 text-right font-semibold text-emerald-600"
                                            x-text="sumUserPayout('approved_payout')"></td>
                                        <td class="px-3 py-2 text-right font-medium text-amber-600"
                                            x-text="sumUserPayout('pending_payout')"></td>
                                        <td class="px-3 py-2 text-right text-red-400"
                                            x-text="sumUserPayout('rejected_payout')"></td>
                                        <td class="px-3 py-2 text-right text-muted-foreground" style="font-size:11px">100%</td>
                                    </tr>
                                </tfoot>
                            </table>
                            </div>
                        </div>
                        <div x-show="csUserTotalPages > 1" class="px-3 py-2 border-t border-border flex items-center justify-between gap-2 text-[11px]">
                            <span class="text-muted-foreground" x-text="((convStats.userPage-1)*convStats.statsPerPage+1)+'-'+Math.min(convStats.userPage*convStats.statsPerPage,convStats.data.by_user.length)+' / '+convStats.data.by_user.length+' users'"></span>
                            <div class="flex items-center gap-1">
                                <button @click="convStats.userPage=1" :disabled="convStats.userPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">«</button>
                                <button @click="convStats.userPage--" :disabled="convStats.userPage===1" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">‹</button>
                                <span class="px-1 text-muted-foreground" x-text="convStats.userPage+' / '+csUserTotalPages"></span>
                                <button @click="convStats.userPage++" :disabled="convStats.userPage>=csUserTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">›</button>
                                <button @click="convStats.userPage=csUserTotalPages" :disabled="convStats.userPage>=csUserTotalPages" class="btn btn-ghost btn-sm px-1.5 py-0.5 disabled:opacity-30">»</button>
                            </div>
                        </div>
                    </div>

                </div>
            </template>

        </div>
        <!-- /Stats -->

        <!-- ══ TAB: Subid ══ -->
        <div x-show="adminConv.subTab === 'subid'" class="space-y-4"
             x-transition:enter="fade-enter" x-transition:enter-start="fade-enter-start" x-transition:enter-end="fade-enter-end">

            <!-- Date range controls -->
            <div class="sl-card">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <svg aria-hidden="true" class="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h8"/>
                        </svg>
                        <h2 class="sl-card-title">Performance by User</h2>
                        <span class="sl-card-count" x-show="convStats.data.by_subid.length > 0" x-text="convStats.data.by_subid.length + ' rows'"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <div class="flex flex-wrap items-center gap-2">
                            <select x-model="convStats.datePreset" @change="applyDatePreset()" class="input h-7 text-[11px] w-36">
                                <option value="today">Today</option>
                                <option value="yesterday">Yesterday</option>
                                <option value="7d">Last 7 days</option>
                                <option value="14d">Last 14 days</option>
                                <option value="30d">Last 30 days</option>
                                <option value="this_month">This month</option>
                                <option value="last_month">Last month</option>
                                <option value="custom">Custom</option>
                            </select>
                            <template x-if="convStats.datePreset === 'custom'">
                                <div class="flex items-center gap-2">
                                    <input type="date" x-model="convStats.dateFrom" class="input h-7 text-[11px] w-32">
                                    <span class="text-[11px] text-muted-foreground">—</span>
                                    <input type="date" x-model="convStats.dateTo" class="input h-7 text-[11px] w-32">
                                    <button @click="loadConvStats()" :disabled="convStats.loading"
                                        class="btn btn-primary btn-sm text-[11px] px-3 flex items-center gap-1.5">
                                        <div x-show="convStats.loading" class="spinner w-3.5 h-3.5"></div>
                                        <span x-show="!convStats.loading">Show</span>
                                    </button>
                                </div>
                            </template>
                            <div x-show="convStats.loading && convStats.datePreset !== 'custom'" class="spinner w-3.5 h-3.5"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Empty state -->
            <div x-show="!convStats.loading && !convStats.data.by_subid.length" class="sl-card">
                <div class="flex flex-col items-center justify-center py-16 text-center">
                    <svg class="w-10 h-10 text-muted-foreground/30 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6h16M4 10h16M4 14h8"/>
                    </svg>
                    <p class="text-sm text-muted-foreground font-medium">Select a date range and click Show</p>
                    <p class="text-xs text-muted-foreground/60 mt-1">Per-user subid data will appear here</p>
                </div>
            </div>

            <!-- Table card -->
            <div class="sl-card" x-show="convStats.data.by_subid.length > 0">
                <div class="sl-card-header">
                    <div class="sl-card-header-left">
                        <span class="text-[11px] text-muted-foreground"
                            x-text="convStats.dateFrom + ' to ' + convStats.dateTo"></span>
                    </div>
                    <div class="sl-card-header-right">
                        <button @click="toggleSubidExpandAll()"
                            class="btn btn-outline btn-sm text-[11px] px-2.5"
                            x-text="convStats.subidExpandAll ? 'Collapse All' : 'Expand All'">
                        </button>
                        <div class="relative">
                            <svg class="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0"/></svg>
                            <input type="text" x-model="convStats.subidSearch" placeholder="Search user / subid…"
                                class="input text-[11px] pl-6 h-7 w-44">
                        </div>
                    </div>
                </div>

                <!-- Empty search -->
                <div x-show="convSubidGrouped.length === 0" class="py-8 text-center text-xs text-muted-foreground">
                    No matching data
                </div>

                <!-- Grouped rows -->
                <template x-for="group in convSubidGrouped" :key="group.user_id">
                    <div>
                        <!-- User header -->
                        <div @click="toggleSubidGroup(group.user_id)"
                            class="flex items-center justify-between gap-4 px-3.5 py-2 bg-secondary/60 border-b border-border cursor-pointer select-none transition-colors hover:bg-secondary">
                            <div class="flex items-center gap-2 min-w-0">
                                <svg :class="{ 'rotate-90': convStats.subidExpanded[group.user_id] }"
                                    class="w-3 h-3 text-muted-foreground shrink-0 transition-transform duration-150"
                                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                                <div class="w-5 h-5 rounded-full bg-secondary flex items-center justify-center shrink-0">
                                    <span class="text-[9px] font-bold text-muted-foreground uppercase" x-text="(group.username||'?').charAt(0)"></span>
                                </div>
                                <span class="text-xs font-semibold font-mono text-foreground truncate" x-text="group.username"></span>
                                <span class="text-[10px] text-muted-foreground shrink-0" x-text="'ID ' + group.user_id"></span>
                                <span class="chip chip-muted text-[10px] px-1.5 py-0.5 shrink-0" x-text="group.rows.length + ' subid'"></span>
                            </div>
                            <div class="flex items-center gap-5 text-[11px] shrink-0">
                                <span class="text-muted-foreground">
                                    <span class="font-semibold text-sky-600" x-text="Number(group.total_clicks).toLocaleString()"></span> clicks
                                </span>
                                <span class="text-muted-foreground">
                                    <span class="font-semibold text-foreground" x-text="Number(group.total_conv).toLocaleString()"></span> conv
                                </span>
                                <span class="font-bold text-emerald-700" x-text="'$' + Number(group.total_payout).toFixed(2)"></span>
                            </div>
                        </div>

                        <!-- Subid rows -->
                        <div x-show="convStats.subidExpanded[group.user_id]">
                            <table class="tbl analytics-subid-table w-full table-fixed" style="font-variant-numeric:tabular-nums;font-size:11px">
                                <colgroup>
                                    <col><!-- Subid: auto -->
                                    <col style="width:72px"><!-- Clicks -->
                                    <col style="width:80px"><!-- Conversions -->
                                    <col style="width:92px"><!-- Total Payout -->
                                    <col style="width:88px"><!-- Approved -->
                                    <col style="width:80px"><!-- Pending -->
                                    <col style="width:80px"><!-- Rejected -->
                                    <col style="width:56px"><!-- CR -->
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th @click="toggleSubidSort('subid')" @keydown.enter="toggleSubidSort('subid')" tabindex="0" scope="col" class="sortable cursor-pointer select-none">
                                            Subid
                                            <span x-show="convStats.subidSort==='subid'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('click_count')" @keydown.enter="toggleSubidSort('click_count')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Clicks
                                            <span x-show="convStats.subidSort==='click_count'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('conv_count')" @keydown.enter="toggleSubidSort('conv_count')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Conv
                                            <span x-show="convStats.subidSort==='conv_count'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('total_payout')" @keydown.enter="toggleSubidSort('total_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Payout
                                            <span x-show="convStats.subidSort==='total_payout'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('approved_payout')" @keydown.enter="toggleSubidSort('approved_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Approved
                                            <span x-show="convStats.subidSort==='approved_payout'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('pending_payout')" @keydown.enter="toggleSubidSort('pending_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Pending
                                            <span x-show="convStats.subidSort==='pending_payout'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th @click="toggleSubidSort('rejected_payout')" @keydown.enter="toggleSubidSort('rejected_payout')" tabindex="0" scope="col" class="sortable cursor-pointer select-none text-right">
                                            Rejected
                                            <span x-show="convStats.subidSort==='rejected_payout'"
                                                  x-text="convStats.subidSortDir==='asc'?'↑':'↓'"
                                                  class="text-blue-500 ml-0.5"></span>
                                        </th>
                                        <th scope="col" class="text-right">CR</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template x-for="(row, ri) in group.rows"
                                              :key="group.user_id + '::' + (row.subid || '__empty__') + '::' + ri">
                                        <tr class="hover:bg-secondary/20">
                                            <td>
                                                <span x-show="row.subid" @click="copyVal(row.subid)" :title="'Copy: ' + row.subid"
                                                    class="analytics-subid-token"
                                                    x-text="(row.subid || '').length > 32 ? (row.subid || '').substring(0,32)+'…' : (row.subid || '')"></span>
                                                <span x-show="!row.subid" class="italic text-muted-foreground/70" style="font-size:11px">— (empty)</span>
                                            </td>
                                            <td class="text-right font-semibold text-sky-600" x-text="Number(row.click_count || 0).toLocaleString()"></td>
                                            <td class="text-right font-semibold text-foreground" x-text="Number(row.conv_count || 0).toLocaleString()"></td>
                                            <td class="text-right font-bold text-emerald-700" x-text="'$' + Number(row.total_payout || 0).toFixed(2)"></td>
                                            <td class="text-right font-semibold text-emerald-600" x-text="(row.approved_payout || 0) > 0 ? '$' + Number(row.approved_payout).toFixed(2) : '—'"></td>
                                            <td class="text-right text-amber-600" x-text="(row.pending_payout || 0) > 0 ? '$' + Number(row.pending_payout).toFixed(2) : '—'"></td>
                                            <td class="text-right text-red-500" x-text="(row.rejected_payout || 0) > 0 ? '$' + Number(row.rejected_payout).toFixed(2) : '—'"></td>
                                            <td class="text-right text-muted-foreground" x-text="(row.click_count || 0) > 0 ? ((row.conv_count || 0)/row.click_count*100).toFixed(1)+'%' : '—'"></td>
                                        </tr>
                                    </template>
                                    <!-- subtotal -->
                                    <tr x-show="group.rows.length > 1" class="analytics-subid-subtotal-row">
                                        <td class="font-semibold text-muted-foreground">Subtotal</td>
                                        <td class="text-right font-semibold text-sky-600" x-text="Number(group.total_clicks || 0).toLocaleString()"></td>
                                        <td class="text-right font-semibold text-foreground" x-text="Number(group.total_conv || 0).toLocaleString()"></td>
                                        <td class="text-right font-bold text-emerald-700" x-text="'$' + Number(group.total_payout || 0).toFixed(2)"></td>
                                        <td class="text-right font-semibold text-emerald-600" x-text="'$' + Number(group.approved_payout || 0).toFixed(2)"></td>
                                        <td class="text-right text-amber-600" x-text="'$' + Number(group.pending_payout || 0).toFixed(2)"></td>
                                        <td class="text-right text-red-500" x-text="'$' + Number(group.rejected_payout || 0).toFixed(2)"></td>
                                        <td class="text-right text-muted-foreground" x-text="(group.total_clicks || 0) > 0 ? ((group.total_conv || 0)/group.total_clicks*100).toFixed(1)+'%' : '—'"></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </template>
            </div>

        </div>
        <!-- /TAB: Subid -->

    </div>
    <!-- /TAB: Conversion -->


</main>

<!-- ══════════════════════════════════════════════════════
     CONFIRM MODAL
══════════════════════════════════════════════════════ -->
<div x-show="confirmModal.show" x-cloak
    x-transition:enter="transition ease-out duration-200"
    x-transition:enter-start="opacity-0"
    x-transition:enter-end="opacity-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100"
    x-transition:leave-end="opacity-0"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div x-show="confirmModal.show"
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0 scale-95"
        x-transition:enter-end="opacity-100 scale-100"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100 scale-100"
        x-transition:leave-end="opacity-0 scale-95"
        class="card w-full max-w-sm p-5">
        <!-- Icon -->
        <div class="flex items-center gap-3 mb-3">
            <div class="w-9 h-9 rounded-full bg-destructive/10 flex items-center justify-center shrink-0">
                <svg class="w-5 h-5 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                </svg>
            </div>
            <div>
                <p class="text-sm font-semibold" x-text="confirmModal.title"></p>
                <p class="text-xs text-muted-foreground mt-0.5" x-text="confirmModal.message"></p>
            </div>
        </div>
        <!-- Buttons -->
        <div class="flex items-center justify-end gap-2 mt-4">
            <button @click="resolveConfirm(false)"
                class="btn btn-outline btn-sm">Cancel</button>
            <button @click="resolveConfirm(true)"
                class="btn btn-sm bg-destructive text-destructive-foreground hover:bg-destructive/90">
                <span x-text="confirmModal.okLabel || 'Delete'"></span>
            </button>
        </div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     RESET PASSWORD MODAL
══════════════════════════════════════════════════════ -->
<div x-show="resetPwModal.show" x-cloak
    x-transition:enter="transition ease-out duration-200"
    x-transition:enter-start="opacity-0"
    x-transition:enter-end="opacity-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100"
    x-transition:leave-end="opacity-0"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div x-show="resetPwModal.show"
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0 scale-95"
        x-transition:enter-end="opacity-100 scale-100"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100 scale-100"
        x-transition:leave-end="opacity-0 scale-95"
        class="card w-full max-w-sm p-5">
        <div class="flex items-center gap-3 mb-4">
            <div class="w-9 h-9 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
                <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                </svg>
            </div>
            <div>
                <p class="text-sm font-semibold">Reset Password</p>
                <p class="text-xs text-muted-foreground font-mono" x-text="resetPwModal.username"></p>
            </div>
        </div>
        <div class="relative mb-4">
            <input x-model="resetPwModal.password"
                :type="resetPwModal.showPw ? 'text' : 'password'"
                placeholder="New password (min. 5 characters)"
                class="input pr-8 w-full" autocomplete="new-password">
            <button type="button" @click="toggleResetPasswordVisibility()"
                aria-label="Toggle password visibility" :aria-pressed="resetPwModal.showPw.toString()"
                class="input-icon-btn">
                <svg x-show="!resetPwModal.showPw" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                <svg x-show="resetPwModal.showPw" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
            </button>
        </div>
        <div class="flex items-center justify-end gap-2">
            <button @click="closeResetPasswordModal()" class="btn btn-outline btn-sm">Cancel</button>
            <button @click="submitResetPw()" :disabled="resetPwModal.loading || !resetPwModal.password"
                class="btn btn-default btn-sm flex items-center gap-1.5 disabled:opacity-50">
                <div x-show="resetPwModal.loading" class="spinner spinner-light w-3 h-3"></div>
                <svg x-show="!resetPwModal.loading" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                <span x-text="resetPwModal.loading ? 'Saving…' : 'Save'"></span>
            </button>
        </div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     SYNC CLOUDFLARE MODAL
══════════════════════════════════════════════════════ -->
<div x-show="syncModal.show" x-cloak
    x-transition:enter="transition ease-out duration-200"
    x-transition:enter-start="opacity-0"
    x-transition:enter-end="opacity-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100"
    x-transition:leave-end="opacity-0"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div x-show="syncModal.show"
        x-transition:enter="transition ease-out duration-200"
        x-transition:enter-start="opacity-0 scale-95"
        x-transition:enter-end="opacity-100 scale-100"
        x-transition:leave="transition ease-in duration-150"
        x-transition:leave-start="opacity-100 scale-100"
        x-transition:leave-end="opacity-0 scale-95"
        class="card w-full max-w-lg p-5">
        <!-- Header -->
        <div class="flex items-center gap-3 mb-4">
            <div class="w-9 h-9 rounded-full bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center shrink-0">
                <svg class="w-5 h-5 text-orange-500" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M16.5 8.25a4.5 4.5 0 00-8.71-1.5H7a3.5 3.5 0 000 7h9a3 3 0 000-6c-.17 0-.34.01-.5.03z"/>
                </svg>
            </div>
            <div>
                <p class="text-sm font-semibold">Sync Cloudflare</p>
                <p class="text-xs text-muted-foreground font-mono" x-text="syncModal.domain"></p>
            </div>
        </div>
        <!-- Nameserver alert (if a new zone was created) -->
        <div x-show="syncModal.zone_created && syncModal.nameservers.length > 0"
            class="notice-box notice-box-amber mb-3" x-data="{ open: false }">
            <button type="button" @click="open = !open" class="text-xs font-semibold text-amber-700 dark:text-amber-400 flex items-center justify-between w-full text-left gap-1.5">
                <span>‼ Update Nameservers at the Registrar</span>
                <svg class="w-3 h-3 shrink-0 transition-transform" :class="open && 'rotate-180'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
            </button>
            <div x-show="open" x-transition class="mt-1">
                <template x-for="ns in syncModal.nameservers" :key="ns">
                    <p class="text-xs font-mono text-amber-800 dark:text-amber-300" x-text="ns"></p>
                </template>
            </div>
        </div>
        <!-- Log -->
        <div aria-live="polite" aria-label="Sync log" class="space-y-1 max-h-64 overflow-y-auto pr-1 text-xs">
            <template x-for="(log, i) in syncModal.logs" :key="i">
                <div class="flex items-start gap-1.5 py-0.5">
                    <!-- icon per type -->
                    <span x-show="log.type === 'success'" class="text-green-500 mt-px shrink-0">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                    </span>
                    <span x-show="log.type === 'error'" class="text-red-500 mt-px shrink-0">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/></svg>
                    </span>
                    <span x-show="log.type === 'warning'" class="text-yellow-500 mt-px shrink-0">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                    </span>
                    <span x-show="log.type === 'info'" class="text-blue-400 mt-px shrink-0">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    </span>
                    <span x-show="log.type === 'step'" class="text-primary mt-px shrink-0">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7"/></svg>
                    </span>
                    <span :class="{
                        'text-green-700 dark:text-green-400': log.type === 'success',
                        'text-red-600   dark:text-red-400':   log.type === 'error',
                        'text-yellow-700 dark:text-yellow-400': log.type === 'warning',
                        'text-muted-foreground':              log.type === 'info',
                        'font-semibold text-foreground':      log.type === 'step',
                    }" x-text="log.message"></span>
                </div>
            </template>
        </div>
        <!-- Footer -->
        <div class="flex justify-end mt-4">
            <button @click="closeSyncModal()" class="btn btn-outline btn-sm">Close</button>
        </div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     TOAST
══════════════════════════════════════════════════════ -->
<div id="toast" x-show="toast.show" x-cloak
    role="status" aria-live="polite" aria-atomic="true"
    x-transition:enter="transition ease-out duration-250"
    x-transition:enter-start="opacity-0 translate-y-4 scale-95"
    x-transition:enter-end="opacity-100 translate-y-0 scale-100"
    x-transition:leave="transition ease-in duration-150"
    x-transition:leave-start="opacity-100 translate-y-0 scale-100"
    x-transition:leave-end="opacity-0 translate-y-3 scale-95"
    :class="{
        'toast-success': toast.type === 'success',
        'toast-error':   toast.type === 'error',
        'toast-info':    toast.type === 'info'
    }">

    <!-- Progress bar countdown -->
    <div class="toast-progress" :style="toastProgressStyle()"></div>

    <!-- Body -->
    <div class="toast-body">
        <!-- Icon -->
        <div class="shrink-0 mt-px">
            <svg x-show="toast.type==='success'" class="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
            </svg>
            <svg x-show="toast.type==='error'" class="w-4 h-4 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            <svg x-show="toast.type==='info'" class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
        </div>

        <!-- Text -->
        <div class="flex-1 min-w-0">
            <p class="text-sm font-semibold text-foreground leading-tight" x-text="toast.title"></p>
            <p x-show="toast.message" class="text-xs text-muted-foreground mt-0.5 leading-relaxed" x-text="toast.message"></p>
        </div>

        <!-- Dismiss button -->
        <button type="button" @click="dismissToast()"
            aria-label="Close"
            class="icon-action-btn -mt-0.5 -mr-1">
            <svg aria-hidden="true" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/>
            </svg>
        </button>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════
     ALPINE APP
══════════════════════════════════════════════════════ -->
<script<?php echo $nonceAttr; ?>>
document.addEventListener('alpine:init', function () {
    Alpine.data('app', app);
});

function app() {
    return {
        Math:            window.Math,
        Number:          window.Number,
        /* ── UI State ── */
        mainTab:         'add',
        showSettings:    true,
        showDnsSection:  false,
        showCfSection:   false,
        useCf:           true,
        domains:         [],
        domainsLoading:  false,
        deletingId:      null,
        syncingCfId:     null,
        syncModal:       { show: false, logs: [], domain: '', nameservers: [], zone_created: false },
        _cfPollTimer:    null,
        _dashVersion:    null,
        _pausePolling:   false,
        _bc:             null,
        cfStatusUpdating: false,
        domainPage:      1,
        domainPerPage:   15,
        settingsTab:     'cloudflare',
        showCpanelToken: false,
        showCfToken:     false,
        saveConfig:      true,
        savingConfig:    false,
        csrfToken:       <?php echo json_encode($csrfToken); ?>,
        isConnected:     false,
        isLoading:       false,
        testingCpanel:   false,
        testingCf:       false,
        cpanelTestResult: '',
        cpanelTestOk:    false,
        cfTestResult:    '',
        cfTestOk:        false,
        currentStatus:   '',
        lastSuccess:     false,
        lastDomain:      '',
        nameservers:     [],
        zoneCreated:     false,
        nsSource:        'cloudflare',  // 'cloudflare' | 'cpanel' — from add_domain response
        nsDetectKey:     '',            // 'config'|'env'|'dns-main'|'dns-host'|'guess'|'none'
        nsDetectLabel:   '',            // human-readable detection method
        logs:            [],
        history:         [],
        errors:          {},
        toast: { show: false, type: 'info', title: '', message: '', duration: 4500 },
        _toastTimer: null,
        confirmModal: { show: false, title: '', message: '', okLabel: 'Delete', resolve: () => {} },

        /* ── User Management ── */
        cpanelUsers:     [],
        usersPage:       1,
        usersPerPage:    15,
        usersLoading:    false,
        userCreate:      { username: '', password: '', showPw: false },
        userCreateLoading: false,
        userCreateMsg:   '',
        userCreateOk:    false,
        deletingUser:    null,
        resetPwModal:    { show: false, username: '', password: '', showPw: false, loading: false },

        /* ── System Config ── */
        sys: {
            loading: false, saving: false,
            saveMsg: '', saveOk: false,
            db_ok: false, db_info: '', apcu_ok: false, apcu_hit_ratio_percent: 0, curl_ok: false,
            queue_depth: 0, queue_failed_depth: 0, queue_worker_ok: false, queue_worker_stale: false, queue_worker_running: false,
            php_ver: '',
            has_ixg: false, has_tinyurl: false, has_gsb: false, has_postback_secret: false,
            ixg_url: '',
            recv_url: <?php echo json_encode($dashboardRecvUrl, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP); ?>,
            sl_url: <?php echo json_encode($dashboardUserUrlPattern, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP); ?>,
            sl_url_warnings: <?php echo json_encode($dashboardWildcardWarnings, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP); ?>,
        },
        apiKeys: { ixg_secret: '', ixg_url: '', tinyurl_key: '', gsb_key: '' },

        /* ── Admin Analytics ── */
        adminAnalyticsDays:    30,
        adminAnalyticsLoading: false,
        adminAnalyticsChart:   null,
        _analyticsReqId:       0,
        adminAnalyticsUserFilter: '',
        adminAnalytics: { total: 0, daily: [], by_country: [], by_device: [], by_network: [], by_link: [], users: [] },

        /* ── Admin Conversion ── */
        adminConv: {
            subTab: 'clicks',
            clicks: [], conversions: [],
            stats: { clicks_24h: 0, conversions_24h: 0, revenue_24h: 0, cr: 0 },
            loading: false, live: false, _pollTimer: null,
            perPage: 50,
            clPage: 1, clSearch: '', clSort: 'created_at', clSortDir: 'desc',
            cvPage: 1, cvSearch: '', cvSort: 'created_at', cvSortDir: 'desc',
            freshIds: {}, newConvIds: {}, newConvCount: 0,
        },

        /* ── Conv Stats (Statistik tab) ── */
        convStats: {
            loading: false,
            error: '',
            datePreset: 'today',
            dateFrom: '',
            dateTo: '',
            data: { total_clicks: 0, total_conv: 0, total_rev: 0, cr: 0, daily: [], by_country: [], by_network: [], by_status: [], by_slug: [], by_user: [], by_subid: [] },
            countryPage: 1, networkPage: 1, userPage: 1, statsPerPage: 10,
            subidSearch: '',
            subidExpandAll: false,
            subidExpanded: {},
            subidSort: 'total_payout',
            subidSortDir: 'desc',
            chart: null,
            _reqId: 0,
        },

        /* ── Smartlink ── */
        smartlinks:        [],
        smartlinksLoading: false,
        slForm:         { id: null, countries: ['all'], device: 'all', network: 'iMonetizeit', networkPreset: 'iMonetizeit', url: '' },
        slCountrySearch: '',
        slLoading: false,
        slMsg:     '',
        slOk:      false,
        deletingSlId: null,
        slCountries: [
            {code:'all',name:'All Country'},
            {code:'ID',name:'Indonesia'},{code:'MY',name:'Malaysia'},{code:'TH',name:'Thailand'},
            {code:'PH',name:'Philippines'},{code:'VN',name:'Vietnam'},{code:'SG',name:'Singapore'},
            {code:'MM',name:'Myanmar'},{code:'KH',name:'Cambodia'},{code:'LA',name:'Laos'},
            {code:'BD',name:'Bangladesh'},{code:'IN',name:'India'},{code:'PK',name:'Pakistan'},
            {code:'LK',name:'Sri Lanka'},{code:'NP',name:'Nepal'},
            {code:'US',name:'United States'},{code:'CA',name:'Canada'},
            {code:'GB',name:'United Kingdom'},{code:'AU',name:'Australia'},{code:'NZ',name:'New Zealand'},
            {code:'DE',name:'Germany'},{code:'FR',name:'France'},{code:'IT',name:'Italy'},
            {code:'ES',name:'Spain'},{code:'NL',name:'Netherlands'},{code:'PL',name:'Poland'},
            {code:'RU',name:'Russia'},{code:'UA',name:'Ukraine'},{code:'TR',name:'Turkey'},
            {code:'RO',name:'Romania'},{code:'CZ',name:'Czech Republic'},{code:'HU',name:'Hungary'},
            {code:'SE',name:'Sweden'},{code:'NO',name:'Norway'},{code:'DK',name:'Denmark'},
            {code:'FI',name:'Finland'},{code:'PT',name:'Portugal'},{code:'GR',name:'Greece'},
            {code:'AT',name:'Austria'},{code:'CH',name:'Switzerland'},{code:'BE',name:'Belgium'},
            {code:'SK',name:'Slovakia'},{code:'BG',name:'Bulgaria'},{code:'RS',name:'Serbia'},
            {code:'HR',name:'Croatia'},{code:'SI',name:'Slovenia'},{code:'LT',name:'Lithuania'},
            {code:'LV',name:'Latvia'},{code:'EE',name:'Estonia'},{code:'MK',name:'North Macedonia'},
            {code:'BR',name:'Brazil'},{code:'MX',name:'Mexico'},{code:'AR',name:'Argentina'},
            {code:'CO',name:'Colombia'},{code:'CL',name:'Chile'},{code:'PE',name:'Peru'},
            {code:'VE',name:'Venezuela'},{code:'EC',name:'Ecuador'},{code:'BO',name:'Bolivia'},
            {code:'PY',name:'Paraguay'},{code:'UY',name:'Uruguay'},
            {code:'JP',name:'Japan'},{code:'KR',name:'South Korea'},{code:'CN',name:'China'},
            {code:'HK',name:'Hong Kong'},{code:'TW',name:'Taiwan'},
            {code:'SA',name:'Saudi Arabia'},{code:'AE',name:'UAE'},{code:'KW',name:'Kuwait'},
            {code:'QA',name:'Qatar'},{code:'IQ',name:'Iraq'},{code:'JO',name:'Jordan'},
            {code:'EG',name:'Egypt'},{code:'MA',name:'Morocco'},{code:'DZ',name:'Algeria'},
            {code:'TN',name:'Tunisia'},{code:'LY',name:'Libya'},
            {code:'NG',name:'Nigeria'},{code:'ZA',name:'South Africa'},{code:'KE',name:'Kenya'},
            {code:'GH',name:'Ghana'},{code:'TZ',name:'Tanzania'},{code:'UG',name:'Uganda'},
            {code:'ET',name:'Ethiopia'},{code:'SN',name:'Senegal'},{code:'CI',name:"Cote d'Ivoire"},
            {code:'ZW',name:'Zimbabwe'},{code:'ZM',name:'Zambia'},{code:'MZ',name:'Mozambique'},
        ],

        /* ── Config ── */
        config: {
            cpanel_host:  '',
            cpanel_port:  '2083',
            cpanel_user:  '',
            cpanel_token: '',
            server_ip:    '',
            base_dir:     'public_html',
            wildcard_dir: '',
            cf_token:      '',
            cf_account_id: '',
            cf_zone_id:    '',
            cf_proxied:    'true',
        },

        /* ── Form ── */
        form: {
            domain:        '',
            subdomain:     '',
            docroot:       '',   // auto-generated
            // DNS zone template; all records enabled by default.
            add_dns_a:     true,
            add_www:       true,
            add_wildcard:  true,
            add_mx_null:   true,
            add_spf:       true,
            add_dmarc:     true,
            skip_existing: true,
            // Cloudflare Security and Speed; all options enabled by default.
            cf_under_attack: false, // Under Attack — emergency only, manual opt-in
            cf_pageshield:   true,   // Client-side Security
            cf_bot_fight:    true,   // Bot Fight Mode
            cf_leaked_creds: true,   // Leaked Credentials Mitigation
            cf_waf:          true,   // WAF Managed Rules
            cf_always_online: true,  // Serve cache during origin outage
            cf_cache_aggressive: true, // Aggressive cache level for static assets
            cf_browser_cache_ttl: true, // Browser cache TTL 4h
            cf_speed_minify: true,   // Auto Minify CSS/JS/HTML
            cf_speed_rocket: true,   // Rocket Loader
            cf_speed_hints:  true,   // Early Hints (HTTP 103)
            cf_speed_http2:  true,   // HTTP/2 + HTTP/3 + 0-RTT
            cf_speed_brotli: true    // Brotli Compression
        },

        /* ── Init ── */
        init() {
            const saved = <?php echo json_encode($savedConfig, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP); ?>;
            if (saved && Object.keys(saved).length > 0) {
                Object.assign(this.config, saved);
                this.showSettings = false;
                this.isConnected  = true;
            }

            <?php if ($cpanelTokenStored && !$cpanelFromEnv) : ?>
            this.config.cpanel_token = '****';
            <?php endif; ?>
            <?php if ($cfTokenFromEnv !== '') : ?>
            this.config.cf_token = <?php echo json_encode($cfTokenFromEnv, JSON_HEX_TAG | JSON_HEX_QUOT | JSON_HEX_AMP); ?>;
            <?php elseif ($cfTokenStored) : ?>
            this.config.cf_token = '****';
            <?php endif; ?>

            // When cPanel settings come from the environment, treat the connection as ready.
            <?php if ($cpanelFromEnv) : ?>
            this.isConnected  = true;
            this.showSettings = Object.keys(saved || {}).length === 0; // Keep Settings open only when the Cloudflare token is still missing.
            <?php endif; ?>
            // Keep both sections collapsed by default; open them manually from the header.
            this.showDnsSection = false;
            this.showCfSection  = false;

            // Domain list is now inline in the Add tab — load on init and start CF poll.
            this.loadDomains();
            this._startCfPoll();

            // BroadcastChannel: instant cross-tab sync on same device
            if (typeof BroadcastChannel !== 'undefined') {
                this._bc = new BroadcastChannel('tp_panel_v1');
                this._bc.onmessage = (ev) => {
                    const type = ev.data?.type;
                    if (type === 'domains')     this.loadDomains();
                    else if (type === 'config') this.loadSystemStatus(true);
                    else if (type === 'smartlinks') this.loadSmartlinks();
                };
            }
            // Version polling: cross-device sync (3s cheap check)
            setInterval(async () => {
                if (this._pausePolling) return;
                try {
                    const r = await this.callApi('get_dashboard_version', {});
                    if (!r || !r.success) return;
                    if (this._dashVersion !== null && r.version !== this._dashVersion) {
                        this.loadDomains();
                    }
                    this._dashVersion = r.version;
                } catch(e) {}
            }, 3000);

            this.$watch('mainTab', tab => {
                if (tab === 'add') {
                    this._startCfPoll();
                } else {
                    this._stopCfPoll();
                }
                if (tab === 'users' && this.cpanelUsers.length === 0) {
                    this.loadUsers();
                }
                if (tab === 'smartlink' && this.smartlinks.length === 0) {
                    this.loadSmartlinks();
                }
                if (tab === 'analytics') {
                    if (!this.adminAnalytics.total) this.loadAdminAnalytics();
                    else this.$nextTick(() => this.renderAdminChart());
                } else {
                    // Destroy the chart when leaving the tab so no RAF callbacks remain pending.
                    if (this.adminAnalyticsChart) { this.adminAnalyticsChart.destroy(); this.adminAnalyticsChart = null; }
                }
                if (tab === 'conversion') {
                    this.startAdminConvPoll();
                } else {
                    this.stopAdminConvPoll();
                }
            });
            // Default date range for Conv Stats (last 30 days)
            const _today = new Date();
            const _pad = n => String(n).padStart(2, '0');
            const _fmt = d => `${d.getFullYear()}-${_pad(d.getMonth()+1)}-${_pad(d.getDate())}`;
            this.convStats.dateTo   = _fmt(_today);
            this.convStats.dateFrom = _fmt(_today);

            window.addEventListener('beforeunload', () => this._stopCfPoll());

            // ── CF config auto-sync ────────────────────────────────
            // Debounced auto-save: whenever any Cloudflare field on the
            // settings form changes, push the new values to the server
            // so config.json, .env (CF_TOKEN) and the admin's app_users
            // row all stay in lock-step with the UI.
            this.$nextTick(() => { this._cfAutoSaveReady = true; });
            const cfAutoKeys = ['cf_token', 'cf_account_id', 'cf_zone_id', 'cf_proxied'];
            for (const key of cfAutoKeys) {
                this.$watch('config.' + key, () => this._scheduleCfAutoSave());
            }
        },

        /* ── CF auto-sync state ── */
        _cfAutoSaveReady:  false,
        _cfAutoSaveTimer:  null,
        cfAutoSaveStatus:  '',   // ''|'pending'|'saving'|'saved'|'error'

        _scheduleCfAutoSave() {
            if (!this._cfAutoSaveReady) return;
            // NOTE: A masked '****' token is fine here. The backend
            // preserves the stored token when it receives '****' so
            // changing cf_account_id / cf_zone_id / cf_proxied alone
            // still syncs without clobbering the real CF_TOKEN.
            this.cfAutoSaveStatus = 'pending';
            if (this._cfAutoSaveTimer) clearTimeout(this._cfAutoSaveTimer);
            this._cfAutoSaveTimer = setTimeout(() => this._runCfAutoSave(), 700);
        },

        async _runCfAutoSave() {
            this._cfAutoSaveTimer = null;
            this.cfAutoSaveStatus = 'saving';
            try {
                const r = await this.callApi('save_config', {});
                if (r && r.success) {
                    this.cfAutoSaveStatus = 'saved';
                    setTimeout(() => { if (this.cfAutoSaveStatus === 'saved') this.cfAutoSaveStatus = ''; }, 2000);
                } else {
                    this.cfAutoSaveStatus = 'error';
                }
            } catch (e) {
                this.cfAutoSaveStatus = 'error';
            }
        },

        async handleLogout() {
            const ok = await this.showConfirm('Logout', 'Are you sure you want to leave the dashboard?', 'Logout');
            if (!ok) {
                return;
            }

            this.doLogout();
        },

        openMainTab(tab) {
            this.mainTab = tab;

            if (tab === 'analytics') {
                this.loadAdminAnalytics();
                return;
            }

            if (tab === 'conversion') {
                this.startAdminConvPoll();
                return;
            }

            if (tab === 'system') {
                this.loadSystemStatus();
            }
        },

        trimFormDomainStart() {
            this.form.domain = this.form.domain.trimStart();
        },

        normalizeFormDomain() {
            this.form.domain = this.form.domain.trim().toLowerCase().replace(/^www\./, '');
        },

        resetNameserverPreview() {
            this.nameservers = [];
            this.lastDomain = '';
            this.zoneCreated = false;
            this.nsSource = 'cloudflare';
            this.nsDetectKey = '';
            this.nsDetectLabel = '';
        },

        sanitizeNewUsername() {
            this.userCreate.username = this.userCreate.username.toLowerCase().replace(/[^a-z0-9_]/g, '');
        },

        toggleUserCreatePassword() {
            this.userCreate.showPw = !this.userCreate.showPw;
        },

        syncSmartlinkNetworkPreset() {
            this.slForm.network = this.slForm.networkPreset !== 'custom' ? this.slForm.networkPreset : '';
        },

        setAdminConvTab(tab) {
            this.adminConv.subTab = tab;
            if (tab === 'conversions') {
                this.adminConv.newConvCount = 0;
            }

            if (tab === 'stats' && !this.convStats.data.daily.length) {
                this.loadConvStats();
            }

            if (tab === 'subid' && !this.convStats.data.by_subid.length) {
                this.loadConvStats();
            }
        },

        resetAdminClickPage() {
            this.adminConv.clPage = 1;
        },

        setAdminClickPage(page) {
            this.adminConv.clPage = Math.min(this.adminClTotalPages, Math.max(1, page));
        },

        changeAdminClickPage(delta) {
            this.setAdminClickPage(this.adminConv.clPage + delta);
        },

        resetAdminConversionPage() {
            this.adminConv.cvPage = 1;
        },

        setAdminConversionPage(page) {
            this.adminConv.cvPage = Math.min(this.adminCvTotalPages, Math.max(1, page));
        },

        changeAdminConversionPage(delta) {
            this.setAdminConversionPage(this.adminConv.cvPage + delta);
        },

        toggleSubidExpandAll() {
            this.convStats.subidExpandAll = !this.convStats.subidExpandAll;
            this.convSubidGrouped.forEach(group => {
                this.convStats.subidExpanded[group.user_id] = this.convStats.subidExpandAll;
            });
        },

        toggleSubidGroup(userId) {
            this.convStats.subidExpanded[userId] = !this.convStats.subidExpanded[userId];
        },

        get domainPaginationLabel() {
            return this.domains.length + ' domains · Page ' + this.domainPage + ' / ' + Math.ceil(this.domains.length / this.domainPerPage);
        },

        get nonSystemCpanelUserCount() {
            return this.cpanelUsers.filter(user => !['service', 'cpanel'].includes(user.type)).length;
        },
        get usersFiltered() {
            return this.cpanelUsers.filter(u => !['service', 'cpanel'].includes(u.type));
        },
        get usersTotalPages() {
            return Math.max(1, Math.ceil(this.usersFiltered.length / this.usersPerPage));
        },
        get usersPaged() {
            const s = (this.usersPage - 1) * this.usersPerPage;
            return this.usersFiltered.slice(s, s + this.usersPerPage);
        },

        sumUserPayout(field) {
            const total = this.convStats.data.by_user.reduce((sum, row) => sum + this.Number(row[field] ?? 0), 0);

            return '$' + total.toFixed(2);
        },

        /* ── CF Status Auto-Polling ── */
        _startCfPoll() {
            this._stopCfPoll();
            this.refreshCfStatus();
            this._cfPollTimer = setInterval(() => { if (!this._pausePolling) this.refreshCfStatus(); }, 30000);
        },
        _stopCfPoll() {
            if (this._cfPollTimer !== null) {
                clearInterval(this._cfPollTimer);
                this._cfPollTimer = null;
            }
        },
        async refreshCfStatus() {
            if (!this.domains.length || !this.config.cf_token?.trim()) return;
            const needsCheck = this.domains.filter(d => d.cf_status !== 'active' && d.cf_status !== 'unconfigured');
            if (!needsCheck.length) {
                this._stopCfPoll();
                return;
            }
            this.cfStatusUpdating = true;
            try {
                const r = await this.callApi('refresh_cf_status', {
                    domains: needsCheck.map(d => ({ id: d.id, domain: d.domain, sub_domain: d.sub_domain ?? '' }))
                });
                if (r.success && r.statuses) {
                    for (const d of this.domains) {
                        if (r.statuses[d.id] !== undefined && d.cf_status !== r.statuses[d.id]) {
                            d.cf_status = r.statuses[d.id];
                            if (r.statuses[d.id] === 'active') d.sub_domain = 'GLOBAL';
                        }
                    }
                }
            } catch(e) { /* silent - do not show errors for background polling */ }
            this.cfStatusUpdating = false;
        },

        /* ── DNS toggle helpers ── */
        _dnsFields: ['add_dns_a','add_www','add_wildcard','add_mx_null','add_spf','add_dmarc'],
        _cfFields:  ['cf_under_attack','cf_pageshield','cf_bot_fight','cf_leaked_creds','cf_waf',
                     'cf_always_online','cf_cache_aggressive','cf_browser_cache_ttl',
                     'cf_speed_minify','cf_speed_rocket','cf_speed_hints',
                     'cf_speed_http2','cf_speed_brotli'],

        allDnsChecked() { return this._dnsFields.every(f => this.form[f]); },
        toggleAllDns()  {
            const v = !this.allDnsChecked();
            this._dnsFields.forEach(f => { this.form[f] = v; });
        },

        allCfChecked()  { return this._cfFields.every(f => this.form[f]); },
        toggleAllCf()   {
            const v = !this.allCfChecked();
            this._cfFields.forEach(f => { this.form[f] = v; });
        },

        /* ── Helpers ── */
        updateSubdomain() {
            // Build the subdomain prefix from the registrable name and replace dots with underscores.
            const d = this.form.domain
                .replace(/^www\./, '')
                .replace(/\.[^.]+$/, '')
                .replace(/\./g, '_');
            this.form.subdomain = d;
            // The docroot follows {base_dir}, so all domains can land in one folder.
            this.form.docroot = this.config.base_dir || 'public_html';
        },

        validate() {
            this.errors = {};

            // ── Normalize the domain ──
            this.form.domain = this.form.domain.trim().toLowerCase().replace(/^www\./, '');

            const d = this.form.domain;
            // RFC 1035 label regex: each label is 1-63 characters, letters/numbers/hyphens only.
            const labelRe  = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/;
            const domainRe = /^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

            if (!d) {
                this.errors.domain = 'Domain name is required';
            } else if (d.length > 253) {
                this.errors.domain = 'Domain is too long (max. 253 characters)';
            } else if (!domainRe.test(d)) {
                this.errors.domain = 'Invalid domain format — use a format like example.com';
            } else {
                // Validate each label individually.
                const labels = d.split('.');
                const badLabel = labels.find(l => !labelRe.test(l));
                if (badLabel) {
                    this.errors.domain = `Invalid label "${badLabel}" (letters, numbers, and hyphens only)`;
                } else if (this.domainDuplicate) {
                    this.errors.domain = 'This domain is already in the list';
                }
            }

            // ── cPanel configuration ──
            if (!<?php echo $cpanelFromEnv ? 'true' : 'false'; ?> && (!this.config.cpanel_host || !this.config.cpanel_user || !this.config.cpanel_token)) {
                this.showToast('error', 'Configuration Incomplete', 'Fill in the cPanel configuration first');
                this.showSettings = true;
                return false;
            }

            // ── Server IP (only when not provided via env) ──
            <?php if (!$cpanelFromEnv) : ?>
            if (!this.config.server_ip) {
                this.showToast('error', 'Configuration Incomplete', 'Set the server IP in Settings first');
                this.showSettings = true;
                return false;
            }
            <?php endif; ?>

            return Object.keys(this.errors).length === 0;
        },

        addLog(type, message) {
            const now  = new Date();
            const time = now.toLocaleTimeString('id-ID', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
            this.logs.push({ type, message, time });
            this.$nextTick(() => {
                const el = this.$el.querySelector('.scroll-logs');
                if (el) el.scrollTop = el.scrollHeight;
            });
        },

        clearLogs() {
            this.logs          = [];
            this.currentStatus = '';
            this.lastSuccess   = false;
        },

        /* ── System Config methods ── */
        async refreshCsrfToken() {
            const res = await fetch('/?ajax=csrf_token', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Cache-Control': 'no-store'
                },
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const payload = await res.json();
            if (!res.ok || !payload.success || !payload.csrf_token) {
                throw new Error(payload.message || 'Unable to refresh CSRF token');
            }
            this.csrfToken = payload.csrf_token;
            return this.csrfToken;
        },

        async fetchJsonWithCsrfRetry(url, body, retryOnCsrf = true, retries503 = 3) {
            const bodyStr = JSON.stringify(body);
            let res, payload;
            for (let attempt = 0; attempt <= retries503; attempt++) {
                res = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-store'
                    },
                    credentials: 'same-origin',
                    cache: 'no-store',
                    body: bodyStr
                });
                // Retry on 503 (worker exhausted on shared hosting) with backoff
                if (res.status === 503 && attempt < retries503) {
                    await new Promise(r => setTimeout(r, 400 * (attempt + 1) + Math.random() * 200));
                    continue;
                }
                break;
            }

            payload = await res.json().catch(() => ({}));

            if (res.status === 403 && payload.message === 'Invalid CSRF token' && retryOnCsrf) {
                await this.refreshCsrfToken();
                return this.fetchJsonWithCsrfRetry(url, { ...body, csrf_token: this.csrfToken }, false);
            }

            if (!res.ok) {
                throw new Error(payload.message || `HTTP ${res.status}`);
            }

            return payload;
        },

        async post(action, payload = {}) {
            return this.fetchJsonWithCsrfRetry('/', { action, csrf_token: this.csrfToken, ...payload });
        },

        doLogout() {
            const logoutForm = document.getElementById('logoutForm');
            if (logoutForm) {
                logoutForm.submit();
            }
        },

        async loadSystemStatus(preserveEnteredSecrets = false) {
            const visibleApiKeys = preserveEnteredSecrets
                ? {
                    ixg_secret: this.apiKeys.ixg_secret,
                    tinyurl_key: this.apiKeys.tinyurl_key,
                    gsb_key: this.apiKeys.gsb_key,
                }
                : null;
            this.sys.loading = true;
            try {
                const r = await this.post('get_system_status');
                if (r.success) {
                    Object.assign(this.sys, r);
                    this.apiKeys.ixg_secret  = preserveEnteredSecrets && visibleApiKeys !== null && visibleApiKeys.ixg_secret !== ''
                        ? visibleApiKeys.ixg_secret
                        : (r.ixg_secret || '');
                    this.apiKeys.ixg_url     = r.ixg_url     || '';
                    this.apiKeys.tinyurl_key = preserveEnteredSecrets && visibleApiKeys !== null && visibleApiKeys.tinyurl_key !== ''
                        ? visibleApiKeys.tinyurl_key
                        : (r.tinyurl_key || '');
                    this.apiKeys.gsb_key     = preserveEnteredSecrets && visibleApiKeys !== null && visibleApiKeys.gsb_key !== ''
                        ? visibleApiKeys.gsb_key
                        : (r.gsb_key || '');
                }
            } catch(e) {}
            this.sys.loading = false;
        },

        async saveApiKeys() {
            this.sys.saving = true;
            this.sys.saveMsg = '';
            try {
                const r = await this.post('save_api_keys', {
                    ixg_secret:  this.apiKeys.ixg_secret,
                    ixg_url:     this.apiKeys.ixg_url,
                    tinyurl_key: this.apiKeys.tinyurl_key,
                    gsb_key:     this.apiKeys.gsb_key,
                });
                this.sys.saveOk  = r.success;
                if (r.success) {
                    await this.loadSystemStatus(true);
                    this.sys.saveMsg = 'Saved to .env. Kept visible in this tab until refresh.';
                    setTimeout(() => this.sys.saveMsg = '', 4000);
                } else {
                    this.sys.saveMsg = r.message || 'Failed';
                }
            } catch(e) { this.sys.saveMsg = 'Error: ' + e.message; this.sys.saveOk = false; }
            this.sys.saving = false;
        },

        /* ── Admin Analytics computed ── */
        get adminClFiltered() {
            const s = (this.adminConv.clSearch || '').toLowerCase();
            let rows = this.adminConv.clicks;
            if (s) rows = rows.filter(c => (c.slug||'').toLowerCase().includes(s) || (c.subid||'').toLowerCase().includes(s) || (c.country||'').toLowerCase().includes(s) || (c.network||'').toLowerCase().includes(s) || (c.ip||'').toLowerCase().includes(s));
            const k = this.adminConv.clSort, d = this.adminConv.clSortDir === 'asc' ? 1 : -1;
            return [...rows].sort((a,b) => (a[k]??'') < (b[k]??'') ? -d : (a[k]??'') > (b[k]??'') ? d : 0);
        },
        get adminClPaged() { const s=(this.adminConv.clPage-1)*this.adminConv.perPage; return this.adminClFiltered.slice(s,s+this.adminConv.perPage); },
        get adminClTotalPages() { return Math.max(1, Math.ceil(this.adminClFiltered.length/this.adminConv.perPage)); },
        get adminCvFiltered() {
            const s = (this.adminConv.cvSearch || '').toLowerCase();
            let rows = this.adminConv.conversions;
            rows = rows.filter(v => (v.username && v.username !== '—') && v.subid && v.network && v.payout > 0 && v.slug);
            if (s) rows = rows.filter(v => (v.slug||'').toLowerCase().includes(s) || (v.subid||'').toLowerCase().includes(s) || (v.country||'').toLowerCase().includes(s) || (v.network||'').toLowerCase().includes(s) || (v.status||'').toLowerCase().includes(s) || (v.clickid||'').toLowerCase().includes(s));
            const k = this.adminConv.cvSort, d = this.adminConv.cvSortDir === 'asc' ? 1 : -1;
            return [...rows].sort((a,b) => (a[k]??'') < (b[k]??'') ? -d : (a[k]??'') > (b[k]??'') ? d : 0);
        },
        get adminCvPaged() { const s=(this.adminConv.cvPage-1)*this.adminConv.perPage; return this.adminCvFiltered.slice(s,s+this.adminConv.perPage); },
        get adminCvTotalPages() { return Math.max(1, Math.ceil(this.adminCvFiltered.length/this.adminConv.perPage)); },

        /* ── Conv Stats pagination ── */
        get csCountryPaged() { const s=(this.convStats.countryPage-1)*this.convStats.statsPerPage; return (this.convStats.data.by_country||[]).slice(s,s+this.convStats.statsPerPage); },
        get csCountryTotalPages() { return Math.max(1,Math.ceil((this.convStats.data.by_country||[]).length/this.convStats.statsPerPage)); },
        get csNetworkPaged() { const s=(this.convStats.networkPage-1)*this.convStats.statsPerPage; return (this.convStats.data.by_network||[]).slice(s,s+this.convStats.statsPerPage); },
        get csNetworkTotalPages() { return Math.max(1,Math.ceil((this.convStats.data.by_network||[]).length/this.convStats.statsPerPage)); },
        get csUserPaged() { const s=(this.convStats.userPage-1)*this.convStats.statsPerPage; return (this.convStats.data.by_user||[]).slice(s,s+this.convStats.statsPerPage); },
        get csUserTotalPages() { return Math.max(1,Math.ceil((this.convStats.data.by_user||[]).length/this.convStats.statsPerPage)); },

        /* ── Conv Stats: subid grouped by user ──
         * Returns an array of { user_id, username, rows[], <per-user totals> }.
         * Search matches against username, subid, or the literal "empty" /
         * "(empty)" keyword so users can find blank-subid rows.
         * Per-user rows are sorted using convStats.subidSort/subidSortDir.
         */
        get adminDailySorted() {
            const rows = this.convStats.data.daily || [];
            return [...rows].sort((a, b) => b.date.localeCompare(a.date));
        },

        get convSubidGrouped() {
            const toNum = v => {
                const n = Number(v);
                return Number.isFinite(n) ? n : 0;
            };
            const q = (this.convStats.subidSearch || '').trim().toLowerCase();
            const matchesEmpty = q === 'empty' || q === '(empty)' || q === '—';
            const raw = Array.isArray(this.convStats.data.by_subid) ? this.convStats.data.by_subid : [];
            const filtered = raw.filter(r => {
                if (!q) return true;
                const subidStr = (r.subid || '').toLowerCase();
                const userStr  = (r.username || '').toLowerCase();
                if (matchesEmpty && subidStr === '') return true;
                return userStr.includes(q) || subidStr.includes(q);
            });

            const map = Object.create(null);
            filtered.forEach(r => {
                const uid = r.user_id;
                if (!map[uid]) {
                    map[uid] = {
                        user_id:         uid,
                        username:        r.username || '',
                        total_clicks:    0,
                        total_conv:      0,
                        total_payout:    0,
                        approved_payout: 0,
                        pending_payout:  0,
                        rejected_payout: 0,
                        rows:            [],
                    };
                }
                const g = map[uid];
                g.total_clicks    += toNum(r.click_count);
                g.total_conv      += toNum(r.conv_count);
                g.total_payout    += toNum(r.total_payout);
                g.approved_payout += toNum(r.approved_payout);
                g.pending_payout  += toNum(r.pending_payout);
                g.rejected_payout += toNum(r.rejected_payout);
                g.rows.push(r);
            });

            // Sort each user's rows by the selected column.
            const sortKey = this.convStats.subidSort || 'total_payout';
            const dir     = this.convStats.subidSortDir === 'asc' ? 1 : -1;
            Object.values(map).forEach(g => {
                g.rows.sort((a, b) => {
                    if (sortKey === 'subid') {
                        const av = (a.subid || '').toLowerCase();
                        const bv = (b.subid || '').toLowerCase();
                        if (av === bv) return 0;
                        return av < bv ? -dir : dir;
                    }
                    const av = toNum(a[sortKey]);
                    const bv = toNum(b[sortKey]);
                    if (av === bv) return 0;
                    return av < bv ? -dir : dir;
                });
            });

            // Sort user groups by total payout, then total clicks.
            return Object.values(map).sort((a, b) => {
                if (b.total_payout !== a.total_payout) return b.total_payout - a.total_payout;
                return b.total_clicks - a.total_clicks;
            });
        },

        /* Cycle sort on subid table columns (applies to every user group). */
        toggleSubidSort(key) {
            if (this.convStats.subidSort === key) {
                this.convStats.subidSortDir = this.convStats.subidSortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.convStats.subidSort    = key;
                this.convStats.subidSortDir = 'desc';
            }
        },

        /* ── Admin Analytics methods ── */
        async loadAdminAnalytics() {
            // Guard against concurrent calls from the watcher and direct tab clicks.
            if (this.adminAnalyticsLoading) return;
            this.adminAnalyticsLoading = true;
            // Only the latest request is allowed to render the chart.
            const reqId = ++this._analyticsReqId;
            try {
                const r = await this.post('admin_get_analytics', { days: this.adminAnalyticsDays, user_id: this.adminAnalyticsUserFilter || 0 });
                if (r.success && reqId === this._analyticsReqId) {
                    this.adminAnalytics = r;
                    setTimeout(() => this.renderAdminChart(), 80);
                }
            } catch(e) {}
            finally { this.adminAnalyticsLoading = false; }
        },

        renderAdminChart() {
            if (this.mainTab !== 'analytics') return;
            // Get the canvas; if it is not mounted anymore, stop here.
            const canvas = document.getElementById('adminAnalyticsChart');
            if (!canvas || !window.Chart) return;
            // If the canvas still has no dimensions because the tab is hidden, stop.
            if (!canvas.getBoundingClientRect().width) return;
            // Destroy the previous chart cleanly so the canvas can be reused.
            if (this.adminAnalyticsChart) {
                this.adminAnalyticsChart.destroy();
                this.adminAnalyticsChart = null;
            }
            // Make sure no orphaned chart instance still points at this canvas.
            const orphan = window.Chart && window.Chart.getChart(canvas);
            if (orphan) orphan.destroy();
            if (!this.adminAnalytics.daily?.length) return;
            // Replace the canvas so stale RAF callbacks cannot access the same node.
            const parent = canvas.parentNode;
            const fresh = document.createElement('canvas');
            fresh.id = 'adminAnalyticsChart';
            parent.replaceChild(fresh, canvas);
            // Build the chart only if the tab is still active after the DOM update.
            if (this.mainTab !== 'analytics') return;
            try {
                const labels = this.adminAnalytics.daily.map(d => { const dt = new Date(d.date+'T00:00:00'); return dt.toLocaleDateString('id-ID', {day:'numeric',month:'short'}); });
                const data   = this.adminAnalytics.daily.map(d => d.hits);
                this.adminAnalyticsChart = new Chart(fresh, {
                    type: 'line',
                    data: { labels, datasets: [{ label:'Clicks', data, borderColor:'hsl(240,5.9%,18%)', backgroundColor:'hsla(240,5.9%,10%,0.06)', borderWidth:1.5, tension:0.35, fill:true, pointRadius: data.length>30?0:3, pointHoverRadius:4, pointBackgroundColor:'hsl(240,5.9%,18%)' }] },
                    options: {
                        animation: false,
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend:{display:false}, tooltip:{callbacks:{label:c=>' '+c.parsed.y.toLocaleString()+' clicks'}} },
                        scales: {
                            x: { grid:{display:false}, ticks:{font:{size:10},maxTicksLimit:10,color:'#9ca3af'} },
                            y: { beginAtZero:true, grid:{color:'hsla(240,6%,10%,.06)'}, ticks:{font:{size:10},color:'#9ca3af',precision:0} }
                        }
                    }
                });
            } catch(e) { console.warn('[renderAdminChart]', e); }
        },

        adminClSortBy(k) { if (this.adminConv.clSort===k) this.adminConv.clSortDir = this.adminConv.clSortDir==='asc'?'desc':'asc'; else { this.adminConv.clSort=k; this.adminConv.clSortDir='desc'; } this.adminConv.clPage=1; },
        adminCvSortBy(k) { if (this.adminConv.cvSort===k) this.adminConv.cvSortDir = this.adminConv.cvSortDir==='asc'?'desc':'asc'; else { this.adminConv.cvSort=k; this.adminConv.cvSortDir='desc'; } this.adminConv.cvPage=1; },

        adminConvRelTime(ts) {
            if (!ts) return '—';
            const d = new Date(ts.replace(' ','T'));
            const s = Math.floor((Date.now()-d.getTime())/1000);
            if (s < 0)    return 'just now';
            if (s < 60)   return s+'s ago';
            if (s < 3600) return Math.floor(s/60)+'m ago';
            if (s < 86400) return Math.floor(s/3600)+'h ago';
            return Math.floor(s/86400)+'d ago';
        },

        async loadAdminLiveFeed() {
            this.adminConv.loading = true;
            try {
                const lastCl = this.adminConv.clicks[0]?.id || 0;
                const lastCv = this.adminConv.conversions[0]?.id || 0;
                const r = await this.post('admin_get_live_feed', { after_click: lastCl, after_conv: lastCv });
                if (r.success) {
                    if (r.clicks?.length) {
                        const fresh = {};
                        r.clicks.forEach(c => { fresh[c.id] = true; });
                        this.adminConv.freshIds = fresh;
                        this.adminConv.clicks = [...r.clicks, ...this.adminConv.clicks].slice(0, 200);
                        setTimeout(() => { this.adminConv.freshIds = {}; }, 2000);
                    }
                    if (r.conversions?.length) {
                        const newIds = {};
                        r.conversions.forEach(v => { newIds[v.id] = true; });
                        this.adminConv.newConvIds = { ...this.adminConv.newConvIds, ...newIds };
                        this.adminConv.newConvCount += r.conversions.length;
                        this.adminConv.conversions = [...r.conversions, ...this.adminConv.conversions].slice(0, 200);
                        setTimeout(() => { r.conversions.forEach(v => { delete this.adminConv.newConvIds[v.id]; }); }, 5000);
                    }
                    if (r.stats) this.adminConv.stats = r.stats;
                }
            } catch(e) {}
            finally { this.adminConv.loading = false; }
        },

        startAdminConvPoll() {
            if (this.adminConv.live) return;
            this.adminConv.live = true;
            this.loadAdminLiveFeed();
            this.adminConv._pollTimer = setInterval(() => { if (!this._pausePolling) this.loadAdminLiveFeed(); }, 5000);
        },

        stopAdminConvPoll() {
            this.adminConv.live = false;
            if (this.adminConv._pollTimer) { clearInterval(this.adminConv._pollTimer); this.adminConv._pollTimer = null; }
        },

        applyDatePreset() {
            const _pad = n => String(n).padStart(2, '0');
            const _fmt = d => d.getFullYear() + '-' + _pad(d.getMonth()+1) + '-' + _pad(d.getDate());
            const now = new Date();
            const p = this.convStats.datePreset;
            if (p === 'custom') return;
            if (p === 'today') {
                this.convStats.dateFrom = _fmt(now);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'yesterday') {
                const y = new Date(now); y.setDate(y.getDate() - 1);
                this.convStats.dateFrom = _fmt(y);
                this.convStats.dateTo   = _fmt(y);
            } else if (p === '7d') {
                const d = new Date(now); d.setDate(d.getDate() - 6);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === '14d') {
                const d = new Date(now); d.setDate(d.getDate() - 13);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === '30d') {
                const d = new Date(now); d.setDate(d.getDate() - 29);
                this.convStats.dateFrom = _fmt(d);
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'this_month') {
                this.convStats.dateFrom = _fmt(new Date(now.getFullYear(), now.getMonth(), 1));
                this.convStats.dateTo   = _fmt(now);
            } else if (p === 'last_month') {
                const first = new Date(now.getFullYear(), now.getMonth() - 1, 1);
                const last  = new Date(now.getFullYear(), now.getMonth(), 0);
                this.convStats.dateFrom = _fmt(first);
                this.convStats.dateTo   = _fmt(last);
            }
            this.loadConvStats();
        },

        async loadConvStats() {
            if (this.convStats.loading) return;
            this.convStats.loading = true;
            this.convStats.error   = '';
            const reqId = ++this.convStats._reqId;
            try {
                const r = await this.post('admin_get_conv_stats', {
                    date_from: this.convStats.dateFrom,
                    date_to:   this.convStats.dateTo,
                });
                if (reqId !== this.convStats._reqId) return;
                if (r.success) {
                    // Normalize the response so every array used by the UI
                    // always exists (empty fallbacks) and every numeric field
                    // is a proper Number (not a string coming from PDO).
                    this.convStats.data = {
                        total_clicks: Number(r.total_clicks || 0),
                        total_conv:   Number(r.total_conv   || 0),
                        total_rev:    Number(r.total_rev    || 0),
                        cr:           Number(r.cr           || 0),
                        daily:        Array.isArray(r.daily)      ? r.daily      : [],
                        by_country:   Array.isArray(r.by_country) ? r.by_country : [],
                        by_network:   Array.isArray(r.by_network) ? r.by_network : [],
                        by_status:    Array.isArray(r.by_status)  ? r.by_status  : [],
                        by_slug:      Array.isArray(r.by_slug)    ? r.by_slug    : [],
                        by_user:      Array.isArray(r.by_user)    ? r.by_user    : [],
                        by_subid:     (Array.isArray(r.by_subid) ? r.by_subid : []).map(row => ({
                            user_id:         Number(row.user_id || 0),
                            username:        row.username || '',
                            subid:           row.subid || '',
                            click_count:     Number(row.click_count     || 0),
                            conv_count:      Number(row.conv_count      || 0),
                            total_payout:    Number(row.total_payout    || 0),
                            approved_payout: Number(row.approved_payout || 0),
                            pending_payout:  Number(row.pending_payout  || 0),
                            rejected_payout: Number(row.rejected_payout || 0),
                        })),
                    };
                    // Reset pagination & expand state on new data load.
                    this.convStats.countryPage    = 1;
                    this.convStats.networkPage    = 1;
                    this.convStats.userPage       = 1;
                    this.convStats.subidExpanded  = {};
                    this.convStats.subidExpandAll = false;
                    setTimeout(() => this.renderConvStatsChart(), 80);
                } else {
                    this.convStats.error = r.message || 'Failed to load conversion stats';
                }
            } catch (e) {
                this.convStats.error = 'Connection error: ' + (e?.message || e);
            }
            finally { this.convStats.loading = false; }
        },

        renderConvStatsChart() {
            if (this.mainTab !== 'conversion' || this.adminConv.subTab !== 'stats') return;
            const canvas = document.getElementById('convStatsChart');
            if (!canvas || !window.Chart) return;
            if (this.convStats.chart) { this.convStats.chart.destroy(); this.convStats.chart = null; }
            const orphan = window.Chart.getChart && window.Chart.getChart(canvas);
            if (orphan) orphan.destroy();
            if (!this.convStats.data.daily?.length) return;
            const parent = canvas.parentNode;
            const fresh = document.createElement('canvas');
            fresh.id = 'convStatsChart';
            parent.replaceChild(fresh, canvas);
            try {
                const labels = this.convStats.data.daily.map(d => {
                    const dt = new Date(d.date + 'T00:00:00');
                    return dt.toLocaleDateString('id-ID', { day: 'numeric', month: 'short' });
                });
                this.convStats.chart = new Chart(fresh, {
                    type: 'bar',
                    data: {
                        labels,
                        datasets: [
                            {
                                label: 'Clicks',
                                data: this.convStats.data.daily.map(d => d.clicks),
                                backgroundColor: 'hsla(217,91%,60%,.2)',
                                borderColor: 'hsl(217,91%,55%)',
                                borderWidth: 1.5,
                                borderRadius: 3,
                                yAxisID: 'y',
                                order: 1,
                            },
                            {
                                label: 'Conversions',
                                data: this.convStats.data.daily.map(d => d.conversions),
                                backgroundColor: 'hsla(142,71%,45%,.2)',
                                borderColor: 'hsl(142,71%,40%)',
                                borderWidth: 1.5,
                                borderRadius: 3,
                                yAxisID: 'y2',
                                order: 2,
                            },
                        ],
                    },
                    options: {
                        animation: false,
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: { mode: 'index', intersect: false },
                        plugins: {
                            legend: { display: true, position: 'top', labels: { font: { size: 11 }, usePointStyle: true, boxWidth: 8 } },
                            tooltip: { callbacks: { label: c => ' ' + c.dataset.label + ': ' + c.parsed.y.toLocaleString() } },
                        },
                        scales: {
                            x: { grid: { display: false }, ticks: { font: { size: 10 }, maxTicksLimit: 12, color: '#9ca3af' } },
                            y: {
                                beginAtZero: true,
                                position: 'left',
                                grid: { color: 'hsla(240,6%,10%,.06)' },
                                ticks: { font: { size: 10 }, color: 'hsl(217,80%,50%)', precision: 0 },
                                title: { display: true, text: 'Clicks', font: { size: 10 }, color: 'hsl(217,80%,50%)' },
                            },
                            y2: {
                                beginAtZero: true,
                                position: 'right',
                                grid: { drawOnChartArea: false },
                                ticks: { font: { size: 10 }, color: 'hsl(142,60%,38%)', precision: 0 },
                                title: { display: true, text: 'Conversions', font: { size: 10 }, color: 'hsl(142,60%,38%)' },
                            },
                        },
                    },
                });
            } catch(e) { console.warn('[renderConvStatsChart]', e); }
        },

        copyVal(text, btn = null) {
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {
                if (!btn) return;
                const orig = btn.innerHTML;
                btn.disabled = true;
                btn.innerHTML = '<div class="spinner w-3 h-3" style="margin:auto"></div>';
                setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; }, 400);
            }).catch(() => {});
        },

        showToast(type, title, message = '', duration = 4500) {
            // Cancel the previous timer if one is still active.
            if (this._toastTimer) clearTimeout(this._toastTimer);

            this.toast = { show: false, type, title, message, duration };
            // Wait one frame so the progress bar animation can restart.
            this.$nextTick(() => {
                this.toast.show = true;
                this._toastTimer = setTimeout(() => {
                    this.toast.show = false;
                }, duration);
            });
        },

        /* Confirm dialog replacing window.confirm() - returns Promise<boolean> */
        showConfirm(title, message, okLabel = 'Delete') {
            return new Promise(resolve => {
                this.confirmModal = { show: true, title, message, okLabel, resolve };
            });
        },

        resolveConfirm(accepted) {
            const resolve = this.confirmModal.resolve;
            this.confirmModal.show = false;
            if (typeof resolve === 'function') {
                resolve(accepted);
            }
        },

        toggleResetPasswordVisibility() {
            this.resetPwModal.showPw = !this.resetPwModal.showPw;
        },

        closeResetPasswordModal() {
            this.resetPwModal.show = false;
        },

        closeSyncModal() {
            this.syncModal.show = false;
        },

        toastProgressStyle() {
            return 'animation-duration: ' + this.toast.duration + 'ms';
        },

        dismissToast() {
            this.toast.show = false;
        },

        /* ── API Calls ── */
        async callApi(action, data) {
            return this.fetchJsonWithCsrfRetry('handler.php', {
                action,
                csrf_token: this.csrfToken,
                config: this.config,
                data,
            });
        },

        async testCpanel() {
            if (!<?php echo $cpanelFromEnv ? 'true' : 'false'; ?> && (!this.config.cpanel_host || !this.config.cpanel_user || !this.config.cpanel_token)) {
                this.showToast('error', 'Missing Fields', 'Enter the cPanel host, username, and token');
                this.cpanelTestResult = '';
                this.cpanelTestOk = false;
                return;
            }
            this.testingCpanel    = true;
            this.cpanelTestResult = '';
            try {
                const r = await this.callApi('test_cpanel', {});
                this.cpanelTestOk     = r.success;
                this.cpanelTestResult = r.success ? `✓ ${r.message}` : `✗ ${r.message}`;
                if (r.success) {
                    this.isConnected = true;
                    this.showToast('success', 'cPanel Connected', r.message, 3000);
                } else {
                    this.showToast('error', 'cPanel Connection Failed', r.message);
                }
            } catch(e) {
                this.cpanelTestResult = '✗ Connection failed';
                this.cpanelTestOk     = false;
                this.showToast('error', 'Error', e.message);
            }
            this.testingCpanel = false;
        },

        async testCloudflare() {
            if (!this.config.cf_token) {
                this.showToast('error', 'Missing Token', 'Enter the Cloudflare API token first');
                this.cfTestResult = '';
                this.cfTestOk = false;
                return;
            }
            this.testingCf    = true;
            this.cfTestResult = '';
            try {
                const r = await this.callApi('test_cloudflare', {});
                this.cfTestOk     = r.success;
                this.cfTestResult = r.success ? `✓ ${r.message}` : `✗ ${r.message}`;
                if (r.success) {
                    this.showToast('success', 'Cloudflare Connected', r.message, 3000);
                } else {
                    this.showToast('error', 'Cloudflare Token Failed', r.message);
                }
            } catch(e) {
                this.cfTestResult = '✗ Connection failed';
                this.cfTestOk     = false;
                this.showToast('error', 'Error', e.message);
            }
            this.testingCf = false;
        },

        async saveConfiguration() {
            if (this.savingConfig) return;
            this.savingConfig = true;
            try {
                const r = await this.callApi('save_config', {});
                if (r.success) {
                    this.showToast('success', 'Configuration Saved', 'Settings were saved to the server');
                    this.isConnected = true;
                    this._bc?.postMessage({ type: 'config' });
                } else {
                    this.showToast('error', 'Save Failed', r.message);
                }
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            } finally {
                this.savingConfig = false;
            }
        },

        async addDomain() {
            if (!this.validate()) return;

            this.isLoading    = true;
            this.currentStatus = 'Processing...';
            this.lastSuccess   = false;
            this.clearLogs();

            const cf = this.useCf;
            const domainData = {
                domain:        this.form.domain,
                domain_id:     'admin',
                wildcard_dir:  this.config.wildcard_dir || '',
                // DNS zone template
                add_dns_a:       cf && this.form.add_dns_a,
                add_www:         cf && this.form.add_www,
                add_wildcard:    cf && this.form.add_wildcard,
                add_mx_null:     cf && this.form.add_mx_null,
                add_spf:         cf && this.form.add_spf,
                add_dmarc:       cf && this.form.add_dmarc,
                skip_existing:   this.form.skip_existing,
                // Cloudflare Security & Speed
                cf_under_attack: cf && this.form.cf_under_attack,
                cf_pageshield: cf && this.form.cf_pageshield,
                cf_bot_fight: cf && this.form.cf_bot_fight,
                cf_leaked_creds: cf && this.form.cf_leaked_creds,
                cf_waf: cf && this.form.cf_waf,
                cf_always_online: cf && this.form.cf_always_online,
                cf_cache_aggressive: cf && this.form.cf_cache_aggressive,
                cf_browser_cache_ttl: cf && this.form.cf_browser_cache_ttl,
                cf_speed_minify: cf && this.form.cf_speed_minify,
                cf_speed_rocket: cf && this.form.cf_speed_rocket,
                cf_speed_hints: cf && this.form.cf_speed_hints,
                cf_speed_http2: cf && this.form.cf_speed_http2,
                cf_speed_brotli: cf && this.form.cf_speed_brotli
            };

            this.addLog('step', `Starting process for domain: ${this.form.domain}`);
            this._pausePolling = true;

            try {
                const r = await this.callApi('add_domain', domainData);

                if (r.logs && r.logs.length) {
                    for (const log of r.logs) this.addLog(log.type, log.message);
                }

                if (r.success) {
                    this.lastSuccess   = true;
                    this.lastDomain    = r.domain || this.form.domain;
                    this.nameservers   = r.nameservers || [];
                    this.zoneCreated   = r.zone_created || false;
                    this.nsSource      = r.ns_source || 'cloudflare';
                    this.nsDetectKey   = r.ns_detect_key   || '';
                    this.nsDetectLabel = r.ns_detect_label || '';
                    this.currentStatus = `Domain ${this.form.domain} was added successfully!`;
                    this.showToast('success', 'Domain Added', `${this.form.domain} is now active`);
                    this._bc?.postMessage({ type: 'domains' });

                    // Reload the domain list so the CF badge reflects the latest state.
                    if (this.domains.length > 0) this.loadDomains();

                    this.form.domain = this.form.subdomain = this.form.docroot = '';
                    // Auto-clear the log after 60 seconds, but keep the nameserver panel until dismissal.
                    setTimeout(() => { this.clearLogs(); this.currentStatus = ''; }, 60000);
                } else {
                    this.lastSuccess   = false;
                    this.currentStatus = r.message || 'Failed to add the domain';
                    this.showToast('error', 'Failed', r.message || 'Something went wrong');
                }
            } catch(e) {
                this.addLog('error', `Error: ${e.message}`);
                this.currentStatus = 'A connection error occurred';
                this.showToast('error', 'Connection Error', e.message);
            } finally {
                this._pausePolling = false;
            }

            this.isLoading = false;
        },

        /* ── Computed ── */
        get domainDuplicate() {
            const d = this.form.domain.trim().toLowerCase().replace(/^www\./, '');
            return d.length > 0 && this.domains.some(x => x.domain.toLowerCase() === d);
        },

        /* ── Domain List ── */
        get pagedDomains() {
            const s = (this.domainPage - 1) * this.domainPerPage;
            return this.domains.slice(s, s + this.domainPerPage);
        },

        async loadDomains() {
            this.domainsLoading = true;
            this.domainPage = 1;
            try {
                const r = await this.callApi('list_domains', {});
                if (r.success) this.domains = r.domains || [];
            } catch(e) {
                this.showToast('error', 'Failed to Load', e.message);
            }
            this.domainsLoading = false;
        },

        async syncCloudflare(d) {
            this.syncingCfId = d.id;
            try {
                const r = await this.callApi('sync_cloudflare', { domain: d.domain });
                this.syncModal = {
                    show:         true,
                    logs:         r.logs || [],
                    domain:       d.domain,
                    nameservers:  r.nameservers  || [],
                    zone_created: r.zone_created || false,
                };
                // Reload the list so the Cloudflare status reflects the direct API response.
                await this.loadDomains();
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            }
            this.syncingCfId = null;
        },

        /* ── Smartlink CRUD ── */
        async loadSmartlinks() {
            this.smartlinksLoading = true;
            try {
                const r = await this.callApi('list_smartlinks', {});
                if (r.success) this.smartlinks = r.smartlinks || [];
                else this.showToast('error', 'Failed to Load Smartlinks', r.message);
            } catch(e) { this.showToast('error', 'Error', e.message); }
            this.smartlinksLoading = false;
        },

        /* ── Smartlink country helpers ── */
        get slFilteredCountries() {
            const q = this.slCountrySearch.toLowerCase();
            if (!q) return this.slCountries;
            return this.slCountries.filter(c =>
                c.name.toLowerCase().includes(q) || c.code.toLowerCase().includes(q)
            );
        },
        slToggleCountry(code) {
            if (code === 'all') {
                this.slForm.countries = ['all'];
            } else {
                let arr = this.slForm.countries.filter(c => c !== 'all');
                if (arr.includes(code)) {
                    arr = arr.filter(c => c !== code);
                    if (arr.length === 0) arr = ['all'];
                } else {
                    arr.push(code);
                }
                this.slForm.countries = arr;
            }
        },
        slRemoveCountry(code) {
            this.slForm.countries = this.slForm.countries.filter(c => c !== code);
            if (this.slForm.countries.length === 0) this.slForm.countries = ['all'];
        },
        slParseCountries(str) {
            if (!str || str === 'all') return ['ALL'];
            return str.split(',').map(c => c.trim().toUpperCase()).filter(Boolean);
        },

        async saveSmartlink() {
            this.slMsg = ''; this.slOk = false;
            const url = this.slForm.url.trim();
            if (!url) { this.slMsg = '✗ URL is required'; return; }
            if (!/^https?:\/\/.+/.test(url)) { this.slMsg = '✗ Invalid URL (must start with http/https)'; return; }
            if (!this.slForm.countries.length) { this.slMsg = '✗ Select at least one country'; return; }
            this.slLoading = true;
            const action = this.slForm.id ? 'update_smartlink' : 'create_smartlink';
            try {
                const r = await this.callApi(action, {
                    id:      this.slForm.id,
                    country: this.slForm.countries.join(',') || 'all',
                    device:  this.slForm.device,
                    network: this.slForm.network,
                    url,
                });
                this.slOk  = r.success;
                this.slMsg = (r.success ? '✓ ' : '✗ ') + r.message;
                if (r.success) {
                    this.showToast('success', this.slForm.id ? 'Smartlink Updated' : 'Smartlink Saved', r.message, 3000);
                    this.resetSlForm();
                    await this.loadSmartlinks();
                    this._bc?.postMessage({ type: 'smartlinks' });
                } else {
                    this.showToast('error', 'Failed', r.message);
                }
            } catch(e) {
                this.slMsg = '✗ ' + e.message;
                this.showToast('error', 'Error', e.message);
            }
            this.slLoading = false;
        },

        editSmartlink(sl) {
            const preset = ['iMonetizeit','Lospollos','Trafee'].includes(sl.network) ? sl.network : 'custom';
            const countries = (!sl.country || sl.country === 'all')
                ? ['all']
                : sl.country.split(',').map(c => c.trim().toUpperCase()).filter(Boolean);
            this.slForm = { id: sl.id, countries, device: sl.device, network: sl.network, networkPreset: preset, url: sl.url };
            this.slCountrySearch = '';
            this.slMsg = ''; this.slOk = false;
        },

        resetSlForm() {
            this.slForm = { id: null, countries: ['all'], device: 'all', network: 'iMonetizeit', networkPreset: 'iMonetizeit', url: '' };

            this.slCountrySearch = '';
            this.slMsg = ''; this.slOk = false;
        },

        async deleteSmartlink(id) {
            const ok = await this.showConfirm('Delete Smartlink', 'This smartlink will be deleted permanently.', 'Delete');
            if (!ok) return;
            this.deletingSlId = id;
            try {
                const r = await this.callApi('delete_smartlink', { id });
                if (r.success) {
                    this.smartlinks = this.smartlinks.filter(s => s.id !== id);
                    if (this.slForm.id === id) this.resetSlForm();
                    this.showToast('success', 'Deleted', r.message, 3000);
                    this._bc?.postMessage({ type: 'smartlinks' });
                } else {
                    this.showToast('error', 'Delete Failed', r.message);
                }
            } catch(e) { this.showToast('error', 'Error', e.message); }
            this.deletingSlId = null;
        },

        /* ── User CRUD ── */
        async loadUsers() {
            this.usersLoading = true;
            try {
                const r = await this.callApi('list_cpanel_users', {});
                if (r.success) { this.cpanelUsers = r.users || []; this.usersPage = 1; }
                else this.showToast('error', 'Failed to Load Users', r.message);
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            }
            this.usersLoading = false;
        },

        async createCpanelUser() {
            this.userCreateMsg = '';
            this.userCreateOk  = false;
            const u = this.userCreate.username.trim();
            const p = this.userCreate.password;
            if (!u || !p) { this.userCreateMsg = '✗ Username and password are required'; return; }
            if (!/^[a-z][a-z0-9_]{1,31}$/.test(u)) { this.userCreateMsg = '✗ Invalid username'; return; }
            if (p.length < 5) { this.userCreateMsg = '✗ Password must be at least 5 characters'; return; }
            this.userCreateLoading = true;
            try {
                const r = await this.callApi('create_cpanel_user', { username: u, password: p });
                this.userCreateOk  = r.success;
                this.userCreateMsg = (r.success ? '✓ ' : '✗ ') + r.message;
                if (r.success) {
                    this.showToast('success', 'User Created', r.message, 3500);
                    this.userCreate.username = this.userCreate.password = '';
                    await this.loadUsers();
                } else {
                    this.showToast('error', 'Failed', r.message);
                }
            } catch(e) {
                this.userCreateMsg = '✗ ' + e.message;
                this.showToast('error', 'Error', e.message);
            }
            this.userCreateLoading = false;
        },

        openResetPw(username) {
            this.resetPwModal = { show: true, username, password: '', showPw: false, loading: false };
        },

        async submitResetPw() {
            const p = this.resetPwModal.password;
            if (p.length < 5) { this.showToast('error', 'Validation', 'Password must be at least 5 characters'); return; }
            this.resetPwModal.loading = true;
            try {
                const r = await this.callApi('reset_cpanel_password', {
                    username: this.resetPwModal.username,
                    password: p,
                });
                if (r.success) {
                    this.showToast('success', 'Password Reset', r.message, 3500);
                    this.resetPwModal.show = false;
                } else {
                    this.showToast('error', 'Reset Failed', r.message);
                }
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            }
            this.resetPwModal.loading = false;
        },

        async deleteCpanelUser(username) {
            const ok = await this.showConfirm(
                'Delete User',
                `User "${username}" will be deleted permanently. This action cannot be undone.`,
                'Delete'
            );
            if (!ok) return;
            this.deletingUser = username;
            try {
                const r = await this.callApi('delete_cpanel_user', { username });
                if (r.success) {
                    this.cpanelUsers = this.cpanelUsers.filter(u => u.username !== username);
                    this.showToast('success', 'User Deleted', r.message, 3500);
                } else {
                    this.showToast('error', 'Delete Failed', r.message);
                }
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            }
            this.deletingUser = null;
        },

        async deleteDomain(d) {
            const ok = await this.showConfirm(
                `Delete Domain`,
                `"${d.domain}" will be deleted from cPanel, Cloudflare, and the database. This action cannot be undone.`,
                'Delete'
            );
            if (!ok) return;
            this.deletingId = d.id;
            try {
                const r = await this.callApi('delete_domain', {
                    id:     d.id,
                    domain: d.domain,
                });
                if (r.success) {
                    this.domains = this.domains.filter(x => x.id !== d.id);
                    this.showToast('success', 'Domain Deleted', `${d.domain} was removed from cPanel, Cloudflare, and the database`);
                    this._bc?.postMessage({ type: 'domains' });
                } else {
                    // If any step fails, keep the domain in the list.
                    const errMsgs = (r.logs || [])
                        .filter(l => l.type === 'error')
                        .map(l => l.message)
                        .join(' | ');
                    this.showToast('error', 'Delete Failed', errMsgs.substring(0, 150) || r.message || 'Something went wrong');
                }
            } catch(e) {
                this.showToast('error', 'Error', e.message);
            }
            this.deletingId = null;
        }
    };
}
</script>

<!-- PWA Service Worker Registration -->
<script<?php echo $nonceAttr; ?>>
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .catch(err => console.warn('SW register failed:', err));
    });
}
</script>
<script<?php echo $nonceAttr; ?>>document.querySelectorAll('img').forEach(i => i.addEventListener('contextmenu', e => e.preventDefault()));document.addEventListener('contextmenu', e => { if (e.target.tagName === 'IMG') { e.preventDefault(); } });</script>
</body>
</html>
