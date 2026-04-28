<?php

declare(strict_types=1);

/**
 * metrics_report.php — Plain-text metrics exporter.
 *
 * Outputs Prometheus/text-exposition style counters so external tooling
 * (cron → log, cURL → alerting webhook, monitoring stack scrape) can
 * consume health signals without touching the admin UI.
 *
 * Usage
 * ─────
 *   # CLI — pipe into log or push to webhook
 *   php ops/metrics_report.php
 *   php ops/metrics_report.php --json     # machine-readable JSON
 *
 *   # HTTP — serve behind admin-only guard (or restrict IP at proxy)
 *   GET /metrics?format=json
 *   GET /healthz?format=json
 *   GET /metrics.php?format=json
 *
 * Cron example (every 5 minutes, append to log file):
 *   *​/5 * * * * {PHP_BIN} {APP_ROOT}/ops/metrics_report.php >> /tmp/taaw2_metrics.log 2>&1
 *
 * Security
 * ────────
 * When accessed via HTTP this script checks the METRICS_TOKEN env var.
 * If set, the caller must pass ?token=<value> or the script returns 403.
 * In CLI mode (php-cli) the check is skipped.
 */

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

$isCli = (PHP_SAPI === 'cli');

// ── HTTP authentication guard ──────────────────────────────────
if (!$isCli) {
    $token = trim((string) getenv('METRICS_TOKEN'));
    if ($token !== '') {
        $provided = trim((string) ($_GET['token'] ?? ''));
        if (!hash_equals($token, $provided)) {
            http_response_code(403);
            header('Content-Type: text/plain');
            exit('forbidden');
        }
    }
}

// ── Collect metrics ────────────────────────────────────────────
$metrics = [];
$now     = time();

$metrics['timestamp'] = $now;
$metrics['datetime']  = gmdate('Y-m-d\TH:i:s\Z', $now);

// APCu counters
$metrics['apcu_enabled'] = tp_apcu_enabled() ? 1 : 0;
if (function_exists('tp_apcu_fetch')) {
    $rdErrors = tp_apcu_fetch('redirect_decision_errors');
    $metrics['redirect_decision_errors'] = is_int($rdErrors) ? $rdErrors : 0;
} else {
    $metrics['redirect_decision_errors'] = -1; // -1 = APCu unavailable
}

// APCu info (memory)
if (function_exists('apcu_sma_info')) {
    $sma = @apcu_sma_info(true);
    if (is_array($sma)) {
        $metrics['apcu_avail_mem']  = $sma['avail_mem'] ?? 0;
        $metrics['apcu_num_seg']    = $sma['num_seg'] ?? 0;
        $metrics['apcu_seg_size']   = $sma['seg_size'] ?? 0;
    }
}
if (function_exists('apcu_cache_info')) {
    $ci = @apcu_cache_info(true);
    if (is_array($ci)) {
        $metrics['apcu_num_entries'] = $ci['num_entries'] ?? 0;
        $metrics['apcu_num_hits']    = $ci['num_hits'] ?? 0;
        $metrics['apcu_num_misses']  = $ci['num_misses'] ?? 0;
        $metrics['apcu_expunges']    = $ci['expunges'] ?? 0;
        $hits = (int) $metrics['apcu_num_hits'];
        $misses = (int) $metrics['apcu_num_misses'];
        $requests = $hits + $misses;
        $metrics['apcu_hit_ratio_percent'] = $requests > 0
            ? (int) round(($hits / $requests) * 100)
            : 0;
    }
}

// Postback queue depth
$queueDir = trim((string) getenv('POSTBACK_QUEUE_DIR'));
if ($queueDir === '') {
    $queueDir = dirname(__DIR__) . '/data/postback_queue';
}
$workerStaleAfter = max(60, (int) (getenv('POSTBACK_WORKER_STALE_AFTER') ?: 900));
$queueHealth = tp_postback_queue_health($queueDir, $now, $workerStaleAfter);
$metrics['postback_queue_depth'] = (int) $queueHealth['queue_depth'];
$metrics['postback_queue_oldest_age_seconds'] = (int) $queueHealth['queue_oldest_age_seconds'];
$metrics['postback_failed_depth'] = (int) $queueHealth['failed_depth'];
$metrics['postback_failed_oldest_age_seconds'] = (int) $queueHealth['failed_oldest_age_seconds'];
$metrics['postback_spill_files'] = (int) $queueHealth['spill_files'];
$metrics['postback_worker_running'] = !empty($queueHealth['worker_running']) ? 1 : 0;
$metrics['postback_worker_ok'] = !empty($queueHealth['worker_ok']) ? 1 : 0;
$metrics['postback_worker_stale'] = !empty($queueHealth['worker_stale']) ? 1 : 0;
$metrics['postback_worker_last_started_at'] = (int) $queueHealth['worker_last_started_at'];
$metrics['postback_worker_last_finished_at'] = (int) $queueHealth['worker_last_finished_at'];
$metrics['postback_worker_last_exit_code'] = (int) $queueHealth['worker_last_exit_code'];

// Disk cache dir size (ogimg)
$ogimgCacheDir = dirname(__DIR__) . '/data/ogimg_cache';
$ogimgCacheFiles = 0;
if (is_dir($ogimgCacheDir)) {
    $ogimgCacheFiles = max(0, iterator_count(new FilesystemIterator($ogimgCacheDir, FilesystemIterator::SKIP_DOTS)));
}
$metrics['ogimg_disk_cache_files'] = $ogimgCacheFiles;

// DB connectivity quick check
$dbOk = false;
$host = trim((string) getenv('DB_HOST'));
$user = trim((string) getenv('DB_USER'));
$pass = trim((string) getenv('DB_PASS'));
$name = trim((string) getenv('DB_NAME'));
if ($user !== '' && $name !== '') {
    try {
        $pdo = new PDO(
            'mysql:host=' . ($host !== '' ? $host : 'localhost') . ';dbname=' . $name . ';charset=utf8mb4',
            $user,
            $pass,
            tp_mysql_pdo_options()
        );
        $dbOk = true;

        // Audit log row count (InnoDB approximate — avoids full-table COUNT(*) scan)
        try {
            $r = $pdo->prepare(
                "SELECT TABLE_ROWS FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'redirect_decision_audit_log'"
            );
            $r->execute();
            $approx = $r->fetchColumn();
            $metrics['audit_log_rows'] = $approx !== false ? (int) $approx : -1;
        } catch (Throwable) {
            $metrics['audit_log_rows'] = -1;
        }

        // Clicks last 24h
        try {
            $r = $pdo->prepare('SELECT COUNT(*) FROM clicks WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)');
            $r->execute();
            $metrics['clicks_24h'] = (int) $r->fetchColumn();
        } catch (Throwable) {
            $metrics['clicks_24h'] = -1;
        }

        // Conversions last 24h
        try {
            $r = $pdo->prepare('SELECT COUNT(*) FROM conversions WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)');
            $r->execute();
            $metrics['conversions_24h'] = (int) $r->fetchColumn();
        } catch (Throwable) {
            $metrics['conversions_24h'] = -1;
        }
    } catch (Throwable) {
        $dbOk = false;
    }
}
$metrics['db_ok'] = $dbOk ? 1 : 0;

// ── Output ─────────────────────────────────────────────────────
$format = $isCli
    ? (in_array('--json', $argv ?? [], true) ? 'json' : 'text')
    : ($_GET['format'] ?? 'text');

if ($format === 'json') {
    if (!$isCli) {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
    }
    echo json_encode($metrics, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL;
    exit(0);
}

// Default: text exposition (Prometheus-compatible where applicable)
if (!$isCli) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
}

foreach ($metrics as $key => $val) {
    if ($key === 'datetime') {
        echo "# {$val}\n";
        continue;
    }
    if (is_bool($val)) {
        $val = $val ? 1 : 0;
    }
    echo "taaw2_{$key} {$val}\n";
}
