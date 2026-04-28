<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function postbackWorkerExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

function postbackWorkerEnvString(string $key, string $default = ''): string
{
    $value = getenv($key);
    if ($value === false) {
        return $default;
    }

    return trim((string) $value);
}

function postbackWorkerEnvInt(string $key, int $default): int
{
    $value = postbackWorkerEnvString($key);
    if ($value === '' || preg_match('/^-?\d+$/', $value) !== 1) {
        return $default;
    }

    return (int) $value;
}

function postbackWorkerQueueDirectory(): string
{
    $configured = postbackWorkerEnvString('POSTBACK_QUEUE_DIR');
    if ($configured !== '') {
        return rtrim($configured, "/\\");
    }

    return dirname(__DIR__) . '/data/postback_queue';
}

function postbackWorkerQueueFile(string $queueDirectory): string
{
    return $queueDirectory . '/queue.ndjson';
}

function postbackWorkerFailedFile(string $queueDirectory): string
{
    return $queueDirectory . '/failed.ndjson';
}

/** @param array<string, mixed> $status */
function postbackWorkerWriteStatus(string $queueDirectory, array $status): void
{
    try {
        postbackWorkerEnsureDirectory($queueDirectory);
        $payload = json_encode($status, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if ($payload === false) {
            return;
        }

        file_put_contents(tp_postback_queue_status_file($queueDirectory), $payload . PHP_EOL, LOCK_EX);
    } catch (Throwable) {
    }
}

function postbackWorkerEnsureDirectory(string $path): void
{
    if (is_dir($path)) {
        return;
    }

    if (!mkdir($path, 0775, true) && !is_dir($path)) {
        throw new RuntimeException('Failed to create postback queue directory.');
    }
}

function postbackWorkerSnapshotQueueFile(string $queueFile): string
{
    $queueHandle = fopen($queueFile, 'c+b');
    if ($queueHandle === false) {
        throw new RuntimeException('Failed to open the postback queue file.');
    }

    if (!flock($queueHandle, LOCK_EX)) {
        fclose($queueHandle);
        throw new RuntimeException('Failed to lock the postback queue file.');
    }

    clearstatcache(true, $queueFile);
    $stats = fstat($queueHandle);
    $queueSize = is_array($stats) ? (int) ($stats['size'] ?? 0) : 0;
    if ($queueSize <= 0) {
        flock($queueHandle, LOCK_UN);
        fclose($queueHandle);

        return '';
    }

    $snapshotFile = dirname($queueFile) . '/queue.processing.' . gmdate('YmdHis') . '.' . getmypid() . '.ndjson';
    $snapshotHandle = fopen($snapshotFile, 'wb');
    if ($snapshotHandle === false) {
        flock($queueHandle, LOCK_UN);
        fclose($queueHandle);
        throw new RuntimeException('Failed to create the postback processing snapshot.');
    }

    rewind($queueHandle);
    if (stream_copy_to_stream($queueHandle, $snapshotHandle) === false) {
        fclose($snapshotHandle);
        @unlink($snapshotFile);
        flock($queueHandle, LOCK_UN);
        fclose($queueHandle);
        throw new RuntimeException('Failed to copy the postback queue snapshot.');
    }

    fflush($snapshotHandle);
    fclose($snapshotHandle);
    ftruncate($queueHandle, 0);
    rewind($queueHandle);
    flock($queueHandle, LOCK_UN);
    fclose($queueHandle);

    return $snapshotFile;
}

/** @param array<int, array<string, mixed>> $records */
function postbackWorkerAppendRecords(string $path, array $records): void
{
    if ($records === []) {
        return;
    }

    $payload = '';
    foreach ($records as $record) {
        $encoded = json_encode($record, JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            continue;
        }

        $payload .= $encoded . PHP_EOL;
    }

    if ($payload === '') {
        return;
    }

    if (file_put_contents($path, $payload, FILE_APPEND | LOCK_EX) === false) {
        throw new RuntimeException('Failed to append postback queue records.');
    }
}

function postbackWorkerRestoreSnapshot(string $queueFile, string $snapshotFile): void
{
    if (!is_file($snapshotFile)) {
        return;
    }

    $payload = file_get_contents($snapshotFile);
    if (!is_string($payload) || $payload === '') {
        return;
    }

    if (file_put_contents($queueFile, $payload, FILE_APPEND | LOCK_EX) === false) {
        throw new RuntimeException('Failed to restore the postback queue snapshot.');
    }
}

function postbackWorkerMergeSpillFiles(string $queueDirectory, string $queueFile): int
{
    $spillFiles = glob($queueDirectory . '/spill_*.ndjson');
    if (!is_array($spillFiles) || $spillFiles === []) {
        return 0;
    }

    $merged = 0;
    $queueHandle = fopen($queueFile, 'ab');
    if ($queueHandle === false) {
        return 0;
    }

    if (!flock($queueHandle, LOCK_EX)) {
        fclose($queueHandle);
        return 0;
    }

    foreach ($spillFiles as $spillFile) {
        // Atomically claim the spill file before reading to avoid race with a
        // concurrent web worker that may still be appending to the same PID file.
        $claimedFile = $spillFile . '.claimed.' . getmypid();
        if (!@rename($spillFile, $claimedFile)) {
            continue;
        }

        $content = file_get_contents($claimedFile);
        if (is_string($content) && $content !== '') {
            fwrite($queueHandle, $content);
            $merged++;
        }

        @unlink($claimedFile);
    }

    flock($queueHandle, LOCK_UN);
    fclose($queueHandle);

    return $merged;
}

function postbackWorkerPruneFailedFile(string $failedFile, int $retentionDays): int
{
    if (!is_file($failedFile)) {
        return 0;
    }

    $cutoff = time() - ($retentionDays * 86400);
    $kept = [];
    $pruned = 0;

    $handle = fopen($failedFile, 'rb');
    if ($handle === false) {
        return 0;
    }

    while (($line = fgets($handle)) !== false) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }

        $decoded = json_decode($line, true);
        if (!is_array($decoded)) {
            $pruned++;
            continue;
        }

        // Use failed_at if present, fall back to created_at.
        $timestamp = (int) ($decoded['failed_at'] ?? $decoded['created_at'] ?? 0);
        if ($timestamp > 0 && $timestamp < $cutoff) {
            $pruned++;
            continue;
        }

        $kept[] = $line;
    }

    fclose($handle);

    if ($pruned === 0) {
        return 0;
    }

    if ($kept === []) {
        @unlink($failedFile);
    } else {
        file_put_contents($failedFile, implode(PHP_EOL, $kept) . PHP_EOL, LOCK_EX);
    }

    return $pruned;
}

function postbackWorkerCreateHandle(string $url, int $timeout, int $connectTimeout): \CurlHandle|false
{
    $handle = curl_init($url);
    if ($handle === false) {
        return false;
    }

    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $connectTimeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'PostbackQueueWorker/1.0',
    ]);

    return $handle;
}

/**
 * @param array<int, string> $urls
 * @return array<string, mixed>
 */
function postbackWorkerDispatchSequential(array $urls, int $timeout, int $connectTimeout): array
{
    $delivered = 0;
    $failures = [];

    foreach ($urls as $url) {
        $handle = postbackWorkerCreateHandle($url, $timeout, $connectTimeout);
        if ($handle === false) {
            $failures[] = $url;
            continue;
        }

        curl_exec($handle);
        $httpCode = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
        $curlError = curl_errno($handle);
        if ($curlError === 0 && $httpCode >= 200 && $httpCode < 400) {
            $delivered++;
        } else {
            $failures[] = $url;
        }

        curl_close($handle);
    }

    return [
        'delivered' => $delivered,
        'failures' => $failures,
    ];
}

/**
 * @param array<int, string> $urls
 * @return array<string, mixed>
 */
function postbackWorkerDispatch(array $urls, int $timeout, int $connectTimeout): array
{
    if ($urls === []) {
        return ['delivered' => 0, 'failures' => []];
    }

    if (!function_exists('curl_multi_init')) {
        return postbackWorkerDispatchSequential($urls, $timeout, $connectTimeout);
    }

    $multiHandle = curl_multi_init();

    $handles = [];
    foreach ($urls as $url) {
        $handle = postbackWorkerCreateHandle($url, $timeout, $connectTimeout);
        if ($handle === false) {
            $handles[] = ['handle' => false, 'url' => $url];
            continue;
        }

        $handles[] = ['handle' => $handle, 'url' => $url];
        curl_multi_add_handle($multiHandle, $handle);
    }

    $running = 0;
    do {
        $status = curl_multi_exec($multiHandle, $running);
        if ($status !== CURLM_OK) {
            break;
        }

        if ($running > 0) {
            $selected = curl_multi_select($multiHandle, 1.0);
            if ($selected === -1) {
                usleep(10000);
            }
        }
    } while ($running > 0);

    $delivered = 0;
    $failures = [];
    foreach ($handles as $item) {
        if ($item['handle'] === false) {
            $failures[] = $item['url'];
            continue;
        }

        $handle = $item['handle'];
        $httpCode = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
        $curlError = curl_errno($handle);
        if ($curlError === 0 && $httpCode >= 200 && $httpCode < 400) {
            $delivered++;
        } else {
            $failures[] = $item['url'];
        }

        curl_multi_remove_handle($multiHandle, $handle);
        curl_close($handle);
    }

    curl_multi_close($multiHandle);

    return [
        'delivered' => $delivered,
        'failures' => $failures,
    ];
}

/**
 * @param array<string, mixed> $record
 * @return array<string, mixed>|null
 */
function postbackWorkerNormalizeRecord(array $record): ?array
{
    $rawUrls = $record['urls'] ?? null;
    if (!is_array($rawUrls)) {
        return null;
    }

    $urls = [];
    $seen = [];
    foreach ($rawUrls as $url) {
        if (!is_string($url) || $url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            continue;
        }

        if (isset($seen[$url])) {
            continue;
        }

        $seen[$url] = true;
        $urls[] = $url;
    }

    if ($urls === []) {
        return null;
    }

    $createdAt = max(0, (int) ($record['created_at'] ?? 0));
    $attempts = max(0, (int) ($record['attempts'] ?? 0));
    $availableAt = max(0, (int) ($record['available_at'] ?? $createdAt));
    if ($createdAt === 0) {
        $createdAt = time();
    }

    if ($availableAt === 0) {
        $availableAt = $createdAt;
    }

    return [
        'created_at' => $createdAt,
        'available_at' => $availableAt,
        'attempts' => $attempts,
        'urls' => $urls,
    ];
}

if (PHP_SAPI !== 'cli') {
    postbackWorkerExit('This script must be run from the command line.', 2);
}

$queueDirectory = postbackWorkerQueueDirectory();

if (!function_exists('curl_init')) {
    postbackWorkerWriteStatus($queueDirectory, [
        'running' => false,
        'last_started_at' => time(),
        'last_finished_at' => time(),
        'last_exit_code' => 2,
        'last_message' => 'cURL extension is not available.',
    ]);
    postbackWorkerExit('cURL extension is not available.', 2);
}

$queueFile = postbackWorkerQueueFile($queueDirectory);
$failedFile = postbackWorkerFailedFile($queueDirectory);
$recordLimit = max(1, postbackWorkerEnvInt('POSTBACK_QUEUE_BATCH_SIZE', 500));
$timeout = max(1, postbackWorkerEnvInt('POSTBACK_QUEUE_TIMEOUT', 5));
$connectTimeout = max(1, postbackWorkerEnvInt('POSTBACK_QUEUE_CONNECT_TIMEOUT', 3));
$maxAttempts = max(1, postbackWorkerEnvInt('POSTBACK_QUEUE_MAX_ATTEMPTS', 5));
$baseRetryDelay = max(15, postbackWorkerEnvInt('POSTBACK_QUEUE_RETRY_DELAY', 60));
$failedRetentionDays = max(1, postbackWorkerEnvInt('POSTBACK_FAILED_RETENTION_DAYS', 30));
$runStartedAt = time();

try {
    postbackWorkerEnsureDirectory($queueDirectory);
    postbackWorkerWriteStatus($queueDirectory, [
        'running' => true,
        'last_started_at' => $runStartedAt,
        'last_finished_at' => 0,
        'last_exit_code' => -1,
        'last_message' => 'Processing postback queue.',
    ]);

    // Merge any spillover files written under lock contention into the main queue.
    $mergedSpillFiles = postbackWorkerMergeSpillFiles($queueDirectory, $queueFile);

    if (!is_file($queueFile)) {
        postbackWorkerWriteStatus($queueDirectory, [
            'running' => false,
            'last_started_at' => $runStartedAt,
            'last_finished_at' => time(),
            'last_exit_code' => 0,
            'last_message' => 'No queued postbacks.',
            'merged_spill_files' => $mergedSpillFiles,
            'queue_depth_after' => 0,
            'failed_depth_after' => is_file($failedFile) ? tp_count_non_empty_lines($failedFile) : 0,
        ]);
        postbackWorkerExit('No queued postbacks.', 0);
    }

    $snapshotFile = postbackWorkerSnapshotQueueFile($queueFile);
    if ($snapshotFile === '') {
        postbackWorkerWriteStatus($queueDirectory, [
            'running' => false,
            'last_started_at' => $runStartedAt,
            'last_finished_at' => time(),
            'last_exit_code' => 0,
            'last_message' => 'No queued postbacks.',
            'merged_spill_files' => $mergedSpillFiles,
            'queue_depth_after' => 0,
            'failed_depth_after' => is_file($failedFile) ? tp_count_non_empty_lines($failedFile) : 0,
        ]);
        postbackWorkerExit('No queued postbacks.', 0);
    }

    $requeueRecords = [];
    $failedRecords = [];
    $processedRecords = 0;
    $deliveredUrls = 0;
    $droppedRecords = 0;
    $now = time();

    $snapshot = fopen($snapshotFile, 'rb');
    if ($snapshot === false) {
        throw new RuntimeException('Failed to open the postback processing snapshot.');
    }

    while (($line = fgets($snapshot)) !== false) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }

        $decoded = json_decode($line, true);
        if (!is_array($decoded)) {
            $droppedRecords++;
            continue;
        }

        $record = postbackWorkerNormalizeRecord($decoded);
        if ($record === null) {
            $droppedRecords++;
            continue;
        }

        if ($processedRecords >= $recordLimit) {
            $requeueRecords[] = $record;
            continue;
        }

        $processedRecords++;
        if ($record['available_at'] > $now) {
            $requeueRecords[] = $record;
            continue;
        }

        $result = postbackWorkerDispatch($record['urls'], $timeout, $connectTimeout);
        $deliveredUrls += (int) ($result['delivered'] ?? 0);
        $failedUrls = $result['failures'] ?? [];
        if (!is_array($failedUrls) || $failedUrls === []) {
            continue;
        }

        $nextAttempts = $record['attempts'] + 1;
        $retryRecord = [
            'created_at' => $record['created_at'],
            'available_at' => $now + min(3600, $baseRetryDelay * (2 ** min($record['attempts'], 5))),
            'attempts' => $nextAttempts,
            'urls' => array_values($failedUrls),
        ];

        if ($nextAttempts >= $maxAttempts) {
            $retryRecord['failed_at'] = $now;
            $failedRecords[] = $retryRecord;
        } else {
            $requeueRecords[] = $retryRecord;
        }
    }

    fclose($snapshot);
    @unlink($snapshotFile);
    postbackWorkerAppendRecords($queueFile, $requeueRecords);
    postbackWorkerAppendRecords($failedFile, $failedRecords);
    postbackWorkerPruneFailedFile($failedFile, $failedRetentionDays);

    $queueHealth = tp_postback_queue_health($queueDirectory, time());
    postbackWorkerWriteStatus($queueDirectory, [
        'running' => false,
        'last_started_at' => $runStartedAt,
        'last_finished_at' => time(),
        'last_exit_code' => 0,
        'last_message' => sprintf(
            'Processed %d record(s), delivered %d URL(s), requeued %d record(s), dropped %d record(s).',
            $processedRecords,
            $deliveredUrls,
            count($requeueRecords),
            $droppedRecords
        ),
        'processed_records' => $processedRecords,
        'delivered_urls' => $deliveredUrls,
        'requeued_records' => count($requeueRecords),
        'failed_records_written' => count($failedRecords),
        'dropped_records' => $droppedRecords,
        'merged_spill_files' => $mergedSpillFiles,
        'queue_depth_after' => (int) $queueHealth['queue_depth'],
        'failed_depth_after' => (int) $queueHealth['failed_depth'],
    ]);
} catch (Throwable $e) {
    if (isset($snapshot) && is_resource($snapshot)) {
        fclose($snapshot);
    }

    $restoreNotice = '';
    if (isset($snapshotFile) && is_string($snapshotFile) && $snapshotFile !== '' && is_file($snapshotFile)) {
        try {
            if ($queueFile !== '') {
                postbackWorkerRestoreSnapshot($queueFile, $snapshotFile);
            }
            @unlink($snapshotFile);
        } catch (Throwable $restoreError) {
            $restoreNotice = ' Snapshot left at ' . $snapshotFile . '.';
        }
    }

    postbackWorkerWriteStatus($queueDirectory, [
        'running' => false,
        'last_started_at' => $runStartedAt,
        'last_finished_at' => time(),
        'last_exit_code' => 1,
        'last_message' => $e->getMessage() . $restoreNotice,
    ]);
    postbackWorkerExit($e->getMessage() . $restoreNotice, 1);
}

postbackWorkerExit(
    sprintf(
        'Processed %d record(s), delivered %d URL(s), requeued %d record(s), dropped %d record(s).',
        $processedRecords,
        $deliveredUrls,
        count($requeueRecords),
        $droppedRecords
    ),
    0
);
