<?php

declare(strict_types=1);

if (!function_exists('tp_random_bytes')) {
    function tp_random_bytes(int $length): string
    {
        if (!function_exists('random_bytes')) {
            throw new RuntimeException('random_bytes is unavailable.');
        }

        $bytes = call_user_func('random_bytes', $length);
        if (!is_string($bytes)) {
            throw new RuntimeException('random_bytes returned an invalid value.');
        }

        return $bytes;
    }
}

if (!function_exists('tp_random_int')) {
    function tp_random_int(int $min, int $max): int
    {
        if (!function_exists('random_int')) {
            throw new RuntimeException('random_int is unavailable.');
        }

        $value = call_user_func('random_int', $min, $max);
        if (!is_int($value)) {
            throw new RuntimeException('random_int returned an invalid value.');
        }

        return $value;
    }
}

if (!function_exists('tp_pdo_mysql_attr')) {
    function tp_pdo_mysql_attr(string $name): ?int
    {
        $constantName = 'PDO::' . $name;
        if (!defined($constantName)) {
            return null;
        }

        $value = constant($constantName);

        return is_int($value) ? $value : null;
    }
}

if (!function_exists('tp_mysql_pdo_options')) {
    /**
     * @param array<int, mixed> $extraOptions
     * @return array<int, mixed>
     */
    function tp_mysql_pdo_options(array $extraOptions = []): array
    {
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];

        $multiStatementsAttr = tp_pdo_mysql_attr('MYSQL_ATTR_MULTI_STATEMENTS');
        if ($multiStatementsAttr !== null) {
            $options[$multiStatementsAttr] = false;
        }

        foreach ($extraOptions as $option => $value) {
            if (!is_int($option)) {
                continue;
            }

            $options[$option] = $value;
        }

        return $options;
    }
}

if (!function_exists('tp_sqlite_pdo_options')) {
    /**
     * @param array<int, mixed> $extraOptions
     * @return array<int, mixed>
     */
    function tp_sqlite_pdo_options(array $extraOptions = []): array
    {
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];

        foreach ($extraOptions as $option => $value) {
            if (!is_int($option)) {
                continue;
            }

            $options[$option] = $value;
        }

        return $options;
    }
}

if (!function_exists('tp_apply_env_values')) {
    /** @param array<string, string> $values */
    function tp_apply_env_values(array $values, bool $overwrite = false): void
    {
        foreach ($values as $key => $value) {
            if (!is_string($key) || $key === '' || !is_string($value)) {
                continue;
            }

            if (!$overwrite && getenv($key) !== false) {
                continue;
            }

            putenv($key . '=' . $value);
            $_ENV[$key] = $value;
        }
    }
}

if (!function_exists('tp_load_env_file')) {
    /** @return array<string, string> */
    function tp_load_env_file(string $envFile, bool $overwrite = false): array
    {
        static $cache = [];

        if ($envFile === '' || !is_file($envFile)) {
            return [];
        }

        $fingerprint = '0:0';
        $stats = stat($envFile);
        if (is_array($stats)) {
            $fingerprint = (int) ($stats['mtime'] ?? 0) . ':' . (int) ($stats['size'] ?? 0);
        }

        $cached = $cache[$envFile] ?? null;
        if (
            is_array($cached)
            && ($cached['fingerprint'] ?? null) === $fingerprint
            && is_array($cached['values'] ?? null)
        ) {
            $values = $cached['values'];
            tp_apply_env_values($values, $overwrite);

            return $values;
        }

        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return [];
        }

        $values = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
                continue;
            }

            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if ($key === '') {
                continue;
            }

            $values[$key] = $value;
        }

        $cache[$envFile] = [
            'fingerprint' => $fingerprint,
            'values' => $values,
        ];

        tp_apply_env_values($values, $overwrite);

        return $values;
    }
}

if (!function_exists('tp_apcu_fetch')) {
    function tp_apcu_fetch(string $key, ?bool &$success = null): mixed
    {
        $success = false;
        if (!function_exists('apcu_fetch')) {
            return false;
        }

        $fetch = 'apcu_fetch';

        return $fetch($key, $success);
    }
}

if (!function_exists('tp_apcu_enabled')) {
    function tp_apcu_enabled(): bool
    {
        if (!function_exists('apcu_enabled')) {
            return false;
        }

        $enabled = 'apcu_enabled';

        return (bool) $enabled();
    }
}

if (!function_exists('tp_apcu_store')) {
    function tp_apcu_store(string $key, mixed $value, int $ttl = 0): bool
    {
        if (!function_exists('apcu_store')) {
            return false;
        }

        $store = 'apcu_store';

        return (bool) $store($key, $value, $ttl);
    }
}

if (!function_exists('tp_apcu_add')) {
    function tp_apcu_add(string $key, mixed $value, int $ttl = 0): bool
    {
        if (!function_exists('apcu_add')) {
            return false;
        }

        $add = 'apcu_add';

        return (bool) $add($key, $value, $ttl);
    }
}

if (!function_exists('tp_apcu_inc')) {
    function tp_apcu_inc(string $key, int $step = 1): int|false
    {
        if (!function_exists('apcu_inc')) {
            return false;
        }

        $increment = 'apcu_inc';
        $value = $increment($key, $step);

        return is_int($value) ? $value : false;
    }
}

if (!function_exists('tp_apcu_cas')) {
    function tp_apcu_cas(string $key, int $old, int $new): bool
    {
        if (!function_exists('apcu_cas')) {
            return false;
        }

        $cas = 'apcu_cas';

        return (bool) $cas($key, $old, $new);
    }
}

if (!function_exists('tp_apcu_delete')) {
    function tp_apcu_delete(string $key): bool
    {
        if (!function_exists('apcu_delete')) {
            return false;
        }

        $delete = 'apcu_delete';

        return (bool) $delete($key);
    }
}

// Shared helper: update KEY=value pairs in a .env file (idempotent).
// - Empty value is ignored (left untouched).
// - The sentinel '****' is also ignored (legacy masked field).
// - Missing keys are appended at the end.
// - Also updates the current process env (putenv + $_ENV) so in-flight
//   code picks up the change immediately.
if (!function_exists('tp_env_file_set')) {
    /** @param array<string, string> $newValues */
    function tp_env_file_set(string $envFile, array $newValues): bool
    {
        $lines = file_exists($envFile) ? file($envFile, FILE_IGNORE_NEW_LINES) : [];
        if ($lines === false) {
            return false;
        }

        $out   = [];
        $found = [];

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#' || strpos($trimmed, '=') === false) {
                $out[] = $line;
                continue;
            }

            [$key] = explode('=', $trimmed, 2);
            $key = trim($key);
            if (!array_key_exists($key, $newValues)) {
                $out[] = $line;
                continue;
            }

            $value = $newValues[$key];
            if ($value === '' || $value === '****') {
                $out[]       = $line;
                $found[$key] = true;
                continue;
            }

            $out[]       = "{$key}={$value}";
            $found[$key] = true;
        }

        foreach ($newValues as $key => $value) {
            if (isset($found[$key]) || $value === '' || $value === '****') {
                continue;
            }
            $out[] = "{$key}={$value}";
        }

        $ok = file_put_contents($envFile, implode("\n", $out) . "\n") !== false;

        // Propagate to the running process immediately.
        if ($ok) {
            foreach ($newValues as $key => $value) {
                if ($value === '' || $value === '****') {
                    continue;
                }
                putenv($key . '=' . $value);
                $_ENV[$key] = $value;
            }
        }

        return $ok;
    }
}

if (!function_exists('tp_count_non_empty_lines')) {
    function tp_count_non_empty_lines(string $filePath): int
    {
        if ($filePath === '' || !is_file($filePath) || !is_readable($filePath)) {
            return 0;
        }

        $handle = fopen($filePath, 'rb');
        if (!is_resource($handle)) {
            return 0;
        }

        $count = 0;

        try {
            while (($line = fgets($handle)) !== false) {
                if (trim($line) === '') {
                    continue;
                }

                $count++;
            }
        } finally {
            fclose($handle);
        }

        return $count;
    }
}

if (!function_exists('tp_postback_queue_status_file')) {
    function tp_postback_queue_status_file(string $queueDirectory): string
    {
        return rtrim($queueDirectory, "/\\") . '/worker_status.json';
    }
}

if (!function_exists('tp_postback_queue_file_metrics')) {
    /** @return array<string, int> */
    function tp_postback_queue_file_metrics(string $filePath, int $nowUnix): array
    {
        if ($filePath === '' || !is_file($filePath) || !is_readable($filePath)) {
            return [
                'depth' => 0,
                'oldest_created_at' => 0,
                'oldest_age_seconds' => 0,
            ];
        }

        $handle = fopen($filePath, 'rb');
        if (!is_resource($handle)) {
            return [
                'depth' => 0,
                'oldest_created_at' => 0,
                'oldest_age_seconds' => 0,
            ];
        }

        $depth = 0;
        $oldestCreatedAt = 0;

        try {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }

                $depth++;

                $decoded = json_decode($line, true);
                if (!is_array($decoded)) {
                    continue;
                }

                $createdAt = (int) ($decoded['created_at'] ?? 0);
                if ($createdAt <= 0) {
                    continue;
                }

                if ($oldestCreatedAt === 0 || $createdAt < $oldestCreatedAt) {
                    $oldestCreatedAt = $createdAt;
                }
            }
        } finally {
            fclose($handle);
        }

        return [
            'depth' => $depth,
            'oldest_created_at' => $oldestCreatedAt,
            'oldest_age_seconds' => $oldestCreatedAt > 0 ? max(0, $nowUnix - $oldestCreatedAt) : 0,
        ];
    }
}

if (!function_exists('tp_postback_queue_health')) {
    /** @return array<string, mixed> */
    function tp_postback_queue_health(string $queueDirectory, ?int $nowUnix = null, int $workerStaleAfter = 900): array
    {
        $queueDirectory = rtrim($queueDirectory, "/\\");
        $nowUnix = $nowUnix ?? time();
        if ($nowUnix <= 0) {
            $nowUnix = time();
        }

        $queueMetrics = tp_postback_queue_file_metrics($queueDirectory . '/queue.ndjson', $nowUnix);
        $failedMetrics = tp_postback_queue_file_metrics($queueDirectory . '/failed.ndjson', $nowUnix);

        $spillFiles = glob($queueDirectory . '/spill_*.ndjson');
        $spillCount = is_array($spillFiles) ? count($spillFiles) : 0;

        $status = [];
        $statusFile = tp_postback_queue_status_file($queueDirectory);
        if (is_file($statusFile) && is_readable($statusFile)) {
            $decoded = json_decode((string) file_get_contents($statusFile), true);
            if (is_array($decoded)) {
                $status = $decoded;
            }
        }

        $lastStartedAt = max(0, (int) ($status['last_started_at'] ?? 0));
        $lastFinishedAt = max(0, (int) ($status['last_finished_at'] ?? 0));
        $lastExitCode = (int) ($status['last_exit_code'] ?? -1);
        $running = !empty($status['running']);
        $workerStale = !$running
            && $queueMetrics['depth'] > 0
            && ($lastFinishedAt <= 0 || ($nowUnix - $lastFinishedAt) > max(60, $workerStaleAfter));
        $workerOk = !$running && $lastFinishedAt > 0 && $lastExitCode === 0;

        return [
            'queue_depth' => $queueMetrics['depth'],
            'queue_oldest_created_at' => $queueMetrics['oldest_created_at'],
            'queue_oldest_age_seconds' => $queueMetrics['oldest_age_seconds'],
            'failed_depth' => $failedMetrics['depth'],
            'failed_oldest_created_at' => $failedMetrics['oldest_created_at'],
            'failed_oldest_age_seconds' => $failedMetrics['oldest_age_seconds'],
            'spill_files' => $spillCount,
            'worker_running' => $running,
            'worker_ok' => $workerOk,
            'worker_stale' => $workerStale,
            'worker_last_started_at' => $lastStartedAt,
            'worker_last_finished_at' => $lastFinishedAt,
            'worker_last_exit_code' => $lastExitCode,
            'worker_last_message' => is_string($status['last_message'] ?? null) ? trim((string) $status['last_message']) : '',
        ];
    }
}

if (!function_exists('tp_postback_placeholder_pattern')) {
    function tp_postback_placeholder_pattern(): string
    {
        // Two separate bracket pairs: {token} or <token> — no mixed brackets.
        return '/(?:\{([a-z0-9_]+)\}|<([a-z0-9_]+)>)/i';
    }
}

if (!function_exists('tp_postback_url_for_validation')) {
    function tp_postback_url_for_validation(string $url): string
    {
        return preg_replace(tp_postback_placeholder_pattern(), 'PLACEHOLDER', $url) ?? $url;
    }
}

if (!function_exists('tp_replace_postback_placeholders')) {
    /** @param array<string, string> $replacements */
    function tp_replace_postback_placeholders(string $url, array $replacements): string
    {
        $normalized = [];
        foreach ($replacements as $key => $value) {
            if (!is_string($key) || $key === '' || !is_string($value)) {
                continue;
            }

            $normalized[strtolower($key)] = $value;
        }

        return preg_replace_callback(
            tp_postback_placeholder_pattern(),
            static function (array $matches) use ($normalized): string {
                // Group 1 = {token}, group 2 = <token> — use whichever matched.
                $token = strtolower((string) ($matches[1] !== '' ? $matches[1] : ($matches[2] ?? '')));
                if ($token === '' || !array_key_exists($token, $normalized)) {
                    return $matches[0];
                }

                return $normalized[$token];
            },
            $url,
        ) ?? $url;
    }
}

if (!function_exists('tp_redirect_tracker_encode_url')) {
    function tp_redirect_tracker_encode_url(string $url): string
    {
        return rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
    }
}

if (!function_exists('tp_redirect_tracker_decode_url')) {
    function tp_redirect_tracker_decode_url(string $encoded): string
    {
        if ($encoded === '' || preg_match('/^[A-Za-z0-9\-_]+$/', $encoded) !== 1) {
            return '';
        }

        $normalized = strtr($encoded, '-_', '+/');
        $remainder = strlen($normalized) % 4;
        if ($remainder !== 0) {
            $normalized .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($normalized, true);

        return is_string($decoded) ? $decoded : '';
    }
}

if (!function_exists('tp_redirect_tracker_fallback_token')) {
    function tp_redirect_tracker_fallback_token(string $url, string $secret, int $expiresAtUnix): string
    {
        if ($secret === '' || !preg_match('/^https?:\/\//i', $url) || $expiresAtUnix <= 0) {
            return '';
        }

        $payload = $expiresAtUnix . '.' . tp_redirect_tracker_encode_url($url);
        $signature = hash_hmac('sha256', $payload, $secret);

        return $payload . '.' . $signature;
    }
}

if (!function_exists('tp_redirect_tracker_resolve_fallback_token')) {
    function tp_redirect_tracker_resolve_fallback_token(string $token, string $secret, int $nowUnix): string
    {
        if ($token === '' || $secret === '') {
            return '';
        }

        $parts = explode('.', $token, 3);
        if (count($parts) !== 3) {
            return '';
        }

        [$expiresAtRaw, $encodedUrl, $signature] = $parts;
        if (
            $expiresAtRaw === ''
            || preg_match('/^\d+$/', $expiresAtRaw) !== 1
            || $encodedUrl === ''
            || preg_match('/^[a-f0-9]{64}$/', $signature) !== 1
        ) {
            return '';
        }

        $payload = $expiresAtRaw . '.' . $encodedUrl;
        $expectedSignature = hash_hmac('sha256', $payload, $secret);
        if (!hash_equals($expectedSignature, $signature)) {
            return '';
        }

        if ((int) $expiresAtRaw < $nowUnix) {
            return '';
        }

        $url = tp_redirect_tracker_decode_url($encodedUrl);
        if (!preg_match('/^https?:\/\//i', $url)) {
            return '';
        }

        return $url;
    }
}

if (!function_exists('tp_pdo_connect')) {
    /**
     * Unified PDO factory — MySQL primary, SQLite fallback.
     * withTimeout=true adds connect/read/write timeouts for hot-path callers.
     */
    function tp_pdo_connect(bool $withTimeout = false): ?PDO
    {
        $host = getenv('DB_HOST') ?: 'localhost';
        $user = getenv('DB_USER') ?: '';
        $pass = getenv('DB_PASS') ?: '';
        $name = getenv('DB_NAME') ?: '';

        if ($user !== '' && $name !== '') {
            try {
                $opts = tp_mysql_pdo_options([]);
                if ($withTimeout) {
                    $connectAttr = tp_pdo_mysql_attr('MYSQL_ATTR_CONNECT_TIMEOUT');
                    if ($connectAttr !== null) {
                        $opts[$connectAttr] = 3;
                    }
                    $initAttr = tp_pdo_mysql_attr('MYSQL_ATTR_INIT_COMMAND');
                    if ($initAttr !== null) {
                        $opts[$initAttr] = 'SET SESSION net_read_timeout=5, net_write_timeout=5, wait_timeout=60';
                    }
                }
                return new PDO("mysql:host={$host};dbname={$name};charset=utf8mb4", $user, $pass, $opts);
            } catch (Throwable) {
            }
        }

        if (extension_loaded('pdo_sqlite')) {
            $file = dirname(__DIR__) . '/data/sl_data.sqlite';
            if (file_exists($file)) {
                try {
                    return new PDO("sqlite:{$file}", null, null, tp_sqlite_pdo_options());
                } catch (Throwable) {
                }
            }
        }

        return null;
    }
}

if (!function_exists('tp_postback_queue_directory')) {
    function tp_postback_queue_directory(): string
    {
        $configured = trim((string) getenv('POSTBACK_QUEUE_DIR'));
        if ($configured !== '') {
            return rtrim($configured, "/\\");
        }

        return dirname(__DIR__) . '/data/postback_queue';
    }
}

if (!function_exists('tp_enqueue_postbacks')) {
    /** @param array<int, string> $urls */
    function tp_enqueue_postbacks(array $urls): void
    {
        if ($urls === []) {
            return;
        }

        $queueUrls = [];
        $seen = [];
        foreach ($urls as $url) {
            if (!is_string($url) || $url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
                continue;
            }
            if (isset($seen[$url])) {
                continue;
            }
            $seen[$url] = true;
            $queueUrls[] = $url;
        }

        if ($queueUrls === []) {
            return;
        }

        $queueDir = tp_postback_queue_directory();
        if (!is_dir($queueDir) && !@mkdir($queueDir, 0775, true) && !is_dir($queueDir)) {
            return;
        }

        $now = time();
        $encoded = json_encode([
            'created_at' => $now,
            'available_at' => $now,
            'attempts' => 0,
            'urls' => $queueUrls,
        ], JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            return;
        }

        $queueFile = $queueDir . '/queue.ndjson';
        $fh = @fopen($queueFile, 'a');
        if ($fh !== false) {
            if (flock($fh, LOCK_EX | LOCK_NB)) {
                fwrite($fh, $encoded . PHP_EOL);
                flock($fh, LOCK_UN);
            } else {
                @file_put_contents($queueDir . '/spill_' . getmypid() . '.ndjson', $encoded . PHP_EOL, FILE_APPEND);
            }
            fclose($fh);
        }
    }
}
