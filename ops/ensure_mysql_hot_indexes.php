<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function ensureIndexExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

function ensureIndexDb(): PDO
{
    $host = trim((string) getenv('DB_HOST'));
    $user = trim((string) getenv('DB_USER'));
    $pass = (string) getenv('DB_PASS');
    $name = trim((string) getenv('DB_NAME'));

    if ($user === '' || $name === '') {
        throw new RuntimeException('DB_HOST/DB_USER/DB_NAME must be configured for MySQL index patching.');
    }

    $dsn = 'mysql:host=' . ($host !== '' ? $host : 'localhost') . ';dbname=' . $name . ';charset=utf8mb4';

    return new PDO($dsn, $user, $pass, tp_mysql_pdo_options());
}

function ensureTableExists(PDO $pdo, string $schema, string $table): bool
{
    $statement = $pdo->prepare(
        'SELECT 1
         FROM information_schema.tables
         WHERE table_schema = ? AND table_name = ?
         LIMIT 1'
    );
    $statement->execute([$schema, $table]);

    return (bool) $statement->fetchColumn();
}

function ensureIndexExists(PDO $pdo, string $schema, string $table, string $index): bool
{
    $statement = $pdo->prepare(
        'SELECT 1
         FROM information_schema.statistics
         WHERE table_schema = ? AND table_name = ? AND index_name = ?
         LIMIT 1'
    );
    $statement->execute([$schema, $table, $index]);

    return (bool) $statement->fetchColumn();
}

if (PHP_SAPI !== 'cli') {
    ensureIndexExit('This script must be run from the command line.', 2);
}

$jsonOutput = in_array('--json', $argv ?? [], true);
$result = [
    'success' => true,
    'applied' => [],
    'skipped' => [],
    'failed' => [],
];

$indexDefinitions = [
    ['table' => 'short_links', 'index' => 'idx_active', 'ddl' => 'ALTER TABLE `short_links` ADD INDEX `idx_active` (`active`)'],
    ['table' => 'short_links', 'index' => 'idx_user_id', 'ddl' => 'ALTER TABLE `short_links` ADD INDEX `idx_user_id` (`user_id`)'],
    ['table' => 'short_links', 'index' => 'idx_user_active', 'ddl' => 'ALTER TABLE `short_links` ADD INDEX `idx_user_active` (`user_id`, `active`)'],
    ['table' => 'short_links', 'index' => 'idx_smartlink_network', 'ddl' => 'ALTER TABLE `short_links` ADD INDEX `idx_smartlink_network` (`smartlink_network`)'],
    ['table' => 'link_hits', 'index' => 'idx_lh_linkid', 'ddl' => 'ALTER TABLE `link_hits` ADD INDEX `idx_lh_linkid` (`link_id`)'],
    ['table' => 'postbacks', 'index' => 'idx_pb_active_event', 'ddl' => 'ALTER TABLE `postbacks` ADD INDEX `idx_pb_active_event` (`active`, `event`, `slug`)'],
    ['table' => 'clicks', 'index' => 'idx_cl_clickid_slug', 'ddl' => 'ALTER TABLE `clicks` ADD INDEX `idx_cl_clickid_slug` (`clickid`(100), `slug`)'],
    ['table' => 'clicks', 'index' => 'idx_cl_slug_created', 'ddl' => 'ALTER TABLE `clicks` ADD INDEX `idx_cl_slug_created` (`slug`, `created_at`)'],
    ['table' => 'clicks', 'index' => 'idx_cl_user_created', 'ddl' => 'ALTER TABLE `clicks` ADD INDEX `idx_cl_user_created` (`user_id`, `created_at`)'],
    ['table' => 'conversions', 'index' => 'idx_cv_slug', 'ddl' => 'ALTER TABLE `conversions` ADD INDEX `idx_cv_slug` (`slug`)'],
    ['table' => 'conversions', 'index' => 'idx_cv_status', 'ddl' => 'ALTER TABLE `conversions` ADD INDEX `idx_cv_status` (`status`)'],
    ['table' => 'conversions', 'index' => 'idx_cv_slug_created', 'ddl' => 'ALTER TABLE `conversions` ADD INDEX `idx_cv_slug_created` (`slug`, `created_at`)'],
    ['table' => 'conversions', 'index' => 'idx_cv_user_created', 'ddl' => 'ALTER TABLE `conversions` ADD INDEX `idx_cv_user_created` (`user_id`, `created_at`)'],
    ['table' => 'redirect_decision_audit_log', 'index' => 'idx_redirect_decision_audit_log_created', 'ddl' => 'ALTER TABLE `redirect_decision_audit_log` ADD INDEX `idx_redirect_decision_audit_log_created` (`created_at_unix`)'],
    ['table' => 'redirect_decision_audit_log', 'index' => 'idx_redirect_decision_audit_log_slug', 'ddl' => 'ALTER TABLE `redirect_decision_audit_log` ADD INDEX `idx_redirect_decision_audit_log_slug` (`slug`)'],
    ['table' => 'redirect_decision_audit_log', 'index' => 'idx_redirect_decision_audit_log_decision', 'ddl' => 'ALTER TABLE `redirect_decision_audit_log` ADD INDEX `idx_redirect_decision_audit_log_decision` (`decision`)'],
    ['table' => 'redirect_decision_audit_log', 'index' => 'idx_redirect_decision_audit_log_slug_created', 'ddl' => 'ALTER TABLE `redirect_decision_audit_log` ADD INDEX `idx_redirect_decision_audit_log_slug_created` (`slug`, `created_at_unix`)'],
];

try {
    $pdo = ensureIndexDb();
    $schema = trim((string) getenv('DB_NAME'));

    $checkedTables = [];
    foreach ($indexDefinitions as $definition) {
        $table = $definition['table'];
        $index = $definition['index'];

        if (!isset($checkedTables[$table])) {
            $checkedTables[$table] = ensureTableExists($pdo, $schema, $table);
        }
        if (!$checkedTables[$table]) {
            $result['skipped'][] = $table . '.' . $index . ' (table not yet created)';
            continue;
        }

        if (ensureIndexExists($pdo, $schema, $table, $index)) {
            $result['skipped'][] = $table . '.' . $index;
            continue;
        }

        try {
            $pdo->exec($definition['ddl']);
            $result['applied'][] = $table . '.' . $index;
        } catch (Throwable $e) {
            $result['success'] = false;
            $result['failed'][] = [
                'index' => $table . '.' . $index,
                'error' => $e->getMessage(),
            ];
        }
    }
} catch (Throwable $e) {
    $result['success'] = false;
    $result['failed'][] = [
        'index' => 'connection',
        'error' => $e->getMessage(),
    ];
}

if ($jsonOutput) {
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL;
    exit($result['success'] ? 0 : 1);
}

foreach ($result['applied'] as $item) {
    fwrite(STDOUT, '[applied] ' . $item . PHP_EOL);
}
foreach ($result['skipped'] as $item) {
    fwrite(STDOUT, '[skipped] ' . $item . PHP_EOL);
}
foreach ($result['failed'] as $item) {
    $label = $item['index'];
    $error = $item['error'];
    fwrite(STDERR, '[failed] ' . $label . ' - ' . $error . PHP_EOL);
}

ensureIndexExit(
    sprintf(
        'MySQL hot-index patch finished: %d applied, %d skipped, %d failed.',
        count($result['applied']),
        count($result['skipped']),
        count($result['failed'])
    ),
    $result['success'] ? 0 : 1
);
