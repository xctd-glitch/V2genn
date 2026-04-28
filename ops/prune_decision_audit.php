<?php

declare(strict_types=1);

/**
 * prune_decision_audit.php — Retention cron for RedirectDecision audit log.
 *
 * What it does
 * ────────────
 * Deletes rows from `redirect_decision_audit_log` older than N days (default
 * 90) and buckets from `redirect_decision_metrics` older than N days
 * (default 180). Runs in batches of 1000 rows to keep locks short so the
 * redirect hot-path never blocks on a prune.
 *
 * Why it exists
 * ─────────────
 * The audit log grows unbounded with every redirect. On a busy link that is
 * ~1 row per visitor per minute — easily millions of rows per month. Without
 * pruning the table eventually fills the disk.
 *
 * Usage
 * ─────
 *   php ops/prune_decision_audit.php                 # default 90d / 180d
 *   php ops/prune_decision_audit.php --audit=30      # keep 30 days of audit
 *   php ops/prune_decision_audit.php --metrics=90    # keep 90 days of metrics
 *   php ops/prune_decision_audit.php --dry-run       # report, no delete
 *
 * Cron (cPanel example — see ops/cpanel-cron.example.txt):
 *   7 4 * * * {PHP_BIN} {APP_ROOT}/ops/prune_decision_audit.php >/dev/null 2>&1
 *
 * Env overrides
 * ─────────────
 *   DECISION_AUDIT_RETENTION_DAYS    (default 90)
 *   DECISION_METRICS_RETENTION_DAYS  (default 180)
 */

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function pruneExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

function pruneDb(): ?PDO
{
    $host = trim((string) getenv('DB_HOST'));
    $user = trim((string) getenv('DB_USER'));
    $pass = trim((string) getenv('DB_PASS'));
    $name = trim((string) getenv('DB_NAME'));

    if ($user === '' || $name === '') {
        return null;
    }

    try {
        return new PDO(
            'mysql:host=' . ($host !== '' ? $host : 'localhost') . ';dbname=' . $name . ';charset=utf8mb4',
            $user,
            $pass,
            tp_mysql_pdo_options()
        );
    } catch (Throwable $e) {
        return null;
    }
}

/** @param array<int, string> $argv */
function pruneParseIntArg(array $argv, string $flag, int $default): int
{
    foreach ($argv as $arg) {
        if (str_starts_with($arg, $flag . '=')) {
            $val = (int) substr($arg, strlen($flag) + 1);
            if ($val > 0) {
                return $val;
            }
        }
    }

    return $default;
}

$dryRun = in_array('--dry-run', $argv, true);

$auditDays = pruneParseIntArg(
    $argv,
    '--audit',
    max(1, (int) (getenv('DECISION_AUDIT_RETENTION_DAYS') ?: 90))
);
$metricsDays = pruneParseIntArg(
    $argv,
    '--metrics',
    max(1, (int) (getenv('DECISION_METRICS_RETENTION_DAYS') ?: 180))
);

$now = time();
$auditCutoff   = $now - ($auditDays * 86400);
$metricsCutoff = $now - ($metricsDays * 86400);

$db = pruneDb();
if ($db === null) {
    pruneExit('[prune] db unavailable — nothing to do', 0);
}

$totalAudit   = 0;
$totalMetrics = 0;

// ── 1. Prune audit log in batches ──────────────────────────────
try {
    if ($dryRun) {
        $stmt = $db->prepare(
            'SELECT COUNT(*) FROM redirect_decision_audit_log WHERE created_at_unix < ?'
        );
        $stmt->execute([$auditCutoff]);
        $totalAudit = (int) $stmt->fetchColumn();
    } else {
        // Batch delete to keep per-statement locks tiny.
        $batchSize = 1000;
        while (true) {
            $del = $db->prepare(
                'DELETE FROM redirect_decision_audit_log
                 WHERE created_at_unix < ?
                 LIMIT ' . $batchSize
            );
            $del->execute([$auditCutoff]);
            $affected = $del->rowCount();
            $totalAudit += $affected;
            if ($affected < $batchSize) {
                break;
            }
            usleep(50_000); // 50ms breathing room between batches
        }
    }
} catch (Throwable $e) {
    fwrite(STDERR, '[prune] audit log prune failed: ' . $e->getMessage() . PHP_EOL);
}

// ── 2. Prune metrics buckets ───────────────────────────────────
try {
    if ($dryRun) {
        $stmt = $db->prepare(
            'SELECT COUNT(*) FROM redirect_decision_metrics WHERE bucket_unix < ?'
        );
        $stmt->execute([$metricsCutoff]);
        $totalMetrics = (int) $stmt->fetchColumn();
    } else {
        $del = $db->prepare('DELETE FROM redirect_decision_metrics WHERE bucket_unix < ?');
        $del->execute([$metricsCutoff]);
        $totalMetrics = $del->rowCount();
    }
} catch (Throwable $e) {
    // Table may not exist yet on older installs — skip silently.
}

// ── 3. Optionally prune network profile cache too ──────────────
try {
    if (!$dryRun) {
        $del = $db->prepare(
            'DELETE FROM redirect_network_profile_cache WHERE expires_at_unix < ?'
        );
        $del->execute([$now]);
    }
} catch (Throwable $e) {
    // Non-fatal.
}

$mode = $dryRun ? 'DRY-RUN' : 'applied';
pruneExit(sprintf(
    '[prune] %s audit=%d metrics=%d (keep audit=%dd metrics=%dd)',
    $mode,
    $totalAudit,
    $totalMetrics,
    $auditDays,
    $metricsDays
), 0);
