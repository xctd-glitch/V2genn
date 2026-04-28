<?php

declare(strict_types=1);

namespace App\RedirectDecision\Audit;

use PDO;
use Throwable;

/**
 * @phpstan-type DecisionPayload array<string, mixed>
 * @phpstan-type DecisionMetricInput array{
 *     bucket_unix: int,
 *     slug: string,
 *     decision: string,
 *     primary_reason: string,
 *     window_mode: string,
 *     country_code: string,
 *     device: string
 * }
 * @phpstan-type DecisionMetricRow array{
 *     bucket_unix: int|string,
 *     slug: string,
 *     decision: string,
 *     primary_reason: string,
 *     window_mode: string,
 *     country_code: string,
 *     device: string,
 *     total_count: int|string
 * }
 * @phpstan-type DecisionLogRow array<string, int|string>
 * @phpstan-type CountryDecisionRow array{
 *     country_code: string,
 *     decision: string,
 *     total_count: int|string
 * }
 */
final class PdoDecisionAuditRepository
{
    private bool $schemaReady = false;

    public function __construct(
        private readonly PDO $pdo
    ) {
    }

    /**
     * @param DecisionPayload $payload
     */
    public function record(array $payload, bool $storeAuditLog): void
    {
        if (!$this->ensureSchema()) {
            return;
        }

        $bucketUnix = (int) floor($this->intValue($payload['created_at_unix'] ?? time()) / 60) * 60;
        $primaryReason = $this->normalizeReason($payload['primary_reason'] ?? '');

        $this->incrementMetric([
            'bucket_unix' => $bucketUnix,
            'slug' => $this->truncateText($payload['slug'] ?? '', 191),
            'decision' => $this->truncateText($payload['decision'] ?? '', 32),
            'primary_reason' => $primaryReason,
            'window_mode' => $this->truncateText($payload['window_mode'] ?? '', 16),
            'country_code' => $this->truncateText($payload['country_code'] ?? '', 2),
            'device' => $this->truncateText($payload['device'] ?? '', 16),
        ]);

        if (!$storeAuditLog) {
            return;
        }

        $providerSourcesJson = json_encode($payload['provider_sources'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $reasonsJson = json_encode($payload['reasons'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($providerSourcesJson)) {
            $providerSourcesJson = '[]';
        }
        if (!is_string($reasonsJson)) {
            $reasonsJson = '[]';
        }

        try {
            $statement = $this->pdo->prepare(
                'INSERT INTO redirect_decision_audit_log
                    (
                        created_at_unix, link_id, slug, decision, primary_reason, window_mode, delivery_outcome,
                        country_code, device, visitor_network, is_vpn_like, is_bot,
                        profile_country_code, profile_asn, profile_organization,
                        provider_sources_json, reasons_json, target_host, redirect_host
                    )
                 VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );
            $statement->execute([
                $this->intValue($payload['created_at_unix'] ?? time()),
                $this->intValue($payload['link_id'] ?? 0),
                $this->truncateText($payload['slug'] ?? '', 191),
                $this->truncateText($payload['decision'] ?? '', 32),
                $primaryReason,
                $this->truncateText($payload['window_mode'] ?? '', 16),
                $this->truncateText($payload['delivery_outcome'] ?? '', 24),
                $this->truncateText($payload['country_code'] ?? '', 2),
                $this->truncateText($payload['device'] ?? '', 16),
                $this->truncateText($payload['visitor_network'] ?? '', 64),
                !empty($payload['is_vpn_like']) ? 1 : 0,
                !empty($payload['is_bot']) ? 1 : 0,
                $this->truncateText($payload['profile_country_code'] ?? '', 2),
                $this->intValue($payload['profile_asn'] ?? 0),
                $this->truncateText($payload['profile_organization'] ?? '', 255),
                $providerSourcesJson,
                $reasonsJson,
                $this->truncateText($payload['target_host'] ?? '', 255),
                $this->truncateText($payload['redirect_host'] ?? '', 255),
            ]);
        } catch (Throwable $e) {
            return;
        }
    }

    /**
     * @return list<DecisionMetricRow>
     */
    public function fetchMetricsSince(int $sinceUnix, int $limit = 200): array
    {
        if (!$this->ensureSchema()) {
            return [];
        }

        try {
            $statement = $this->pdo->prepare(
                'SELECT bucket_unix, slug, decision, primary_reason, window_mode, country_code, device, total_count
                 FROM redirect_decision_metrics
                 WHERE bucket_unix >= ?
                 ORDER BY bucket_unix DESC, total_count DESC
                 LIMIT ?'
            );
            $statement->bindValue(1, $sinceUnix, PDO::PARAM_INT);
            $statement->bindValue(2, $limit, PDO::PARAM_INT);
            $statement->execute();
            $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return [];
        }

        return $this->normalizeMetricRows($rows);
    }

    /**
     * @return list<DecisionLogRow>
     */
    public function fetchRecentLogs(int $limit = 50): array
    {
        if (!$this->ensureSchema()) {
            return [];
        }

        try {
            $statement = $this->pdo->prepare(
                'SELECT created_at_unix, slug, decision, primary_reason, window_mode, delivery_outcome,
                        country_code, device, visitor_network, is_vpn_like, is_bot,
                        profile_country_code, profile_asn, profile_organization, provider_sources_json, reasons_json,
                        target_host, redirect_host
                 FROM redirect_decision_audit_log
                 ORDER BY id DESC
                 LIMIT ?'
            );
            $statement->bindValue(1, $limit, PDO::PARAM_INT);
            $statement->execute();
            $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return [];
        }

        return $this->normalizeLogRows($rows);
    }

    /**
     * @return list<CountryDecisionRow>
     */
    public function fetchCountryDecisionSummary(int $sinceUnix, int $limit = 100): array
    {
        if (!$this->ensureSchema()) {
            return [];
        }

        try {
            $statement = $this->pdo->prepare(
                'SELECT country_code, decision, SUM(total_count) AS total_count
                 FROM redirect_decision_metrics
                 WHERE bucket_unix >= ?
                 GROUP BY country_code, decision
                 ORDER BY total_count DESC
                 LIMIT ?'
            );
            $statement->bindValue(1, $sinceUnix, PDO::PARAM_INT);
            $statement->bindValue(2, $limit, PDO::PARAM_INT);
            $statement->execute();
            $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return [];
        }

        return $this->normalizeCountryDecisionRows($rows);
    }

    public function fetchTotalCountBetween(int $fromUnix, int $untilUnix): int
    {
        if (!$this->ensureSchema()) {
            return 0;
        }

        try {
            $statement = $this->pdo->prepare(
                'SELECT COALESCE(SUM(total_count), 0) AS total_count
                 FROM redirect_decision_metrics
                 WHERE bucket_unix >= ? AND bucket_unix < ?'
            );
            $statement->bindValue(1, $fromUnix, PDO::PARAM_INT);
            $statement->bindValue(2, $untilUnix, PDO::PARAM_INT);
            $statement->execute();
            $row = $statement->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return 0;
        }

        if (!is_array($row)) {
            return 0;
        }

        return $this->intValue($row['total_count'] ?? null);
    }

    /**
     * @param DecisionMetricInput $metric
     */
    private function incrementMetric(array $metric): void
    {
        try {
            if ($this->driverName() === 'mysql') {
                $statement = $this->pdo->prepare(
                    'INSERT INTO redirect_decision_metrics
                        (bucket_unix, slug, decision, primary_reason, window_mode, country_code, device, total_count)
                     VALUES
                        (?, ?, ?, ?, ?, ?, ?, 1)
                     ON DUPLICATE KEY UPDATE
                        total_count = total_count + 1'
                );
            } else {
                $statement = $this->pdo->prepare(
                    'INSERT INTO redirect_decision_metrics
                        (bucket_unix, slug, decision, primary_reason, window_mode, country_code, device, total_count)
                     VALUES
                        (?, ?, ?, ?, ?, ?, ?, 1)
                     ON CONFLICT(bucket_unix, slug, decision, primary_reason, window_mode, country_code, device)
                     DO UPDATE SET total_count = total_count + 1'
                );
            }

            $statement->execute([
                (int) $metric['bucket_unix'],
                $metric['slug'],
                $metric['decision'],
                $metric['primary_reason'],
                $metric['window_mode'],
                $metric['country_code'],
                $metric['device'],
            ]);
        } catch (Throwable $e) {
            return;
        }
    }

    private function ensureSchema(): bool
    {
        if ($this->schemaReady) {
            return true;
        }

        try {
            if ($this->driverName() === 'mysql') {
                $this->pdo->exec(
                    'CREATE TABLE IF NOT EXISTS redirect_decision_metrics (
                        bucket_unix BIGINT NOT NULL,
                        slug VARCHAR(191) NOT NULL,
                        decision VARCHAR(32) NOT NULL,
                        primary_reason VARCHAR(64) NOT NULL,
                        window_mode VARCHAR(16) NOT NULL,
                        country_code CHAR(2) NOT NULL DEFAULT \'\',
                        device VARCHAR(16) NOT NULL DEFAULT \'\',
                        total_count BIGINT NOT NULL DEFAULT 0,
                        PRIMARY KEY (bucket_unix, slug, decision, primary_reason, window_mode, country_code, device)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
                );
                $this->pdo->exec(
                    'CREATE TABLE IF NOT EXISTS redirect_decision_audit_log (
                        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        created_at_unix BIGINT NOT NULL,
                        link_id BIGINT NOT NULL DEFAULT 0,
                        slug VARCHAR(191) NOT NULL,
                        decision VARCHAR(32) NOT NULL,
                        primary_reason VARCHAR(64) NOT NULL,
                        window_mode VARCHAR(16) NOT NULL,
                        delivery_outcome VARCHAR(24) NOT NULL,
                        country_code CHAR(2) NOT NULL DEFAULT \'\',
                        device VARCHAR(16) NOT NULL DEFAULT \'\',
                        visitor_network VARCHAR(64) NOT NULL DEFAULT \'\',
                        is_vpn_like TINYINT(1) NOT NULL DEFAULT 0,
                        is_bot TINYINT(1) NOT NULL DEFAULT 0,
                        profile_country_code CHAR(2) NOT NULL DEFAULT \'\',
                        profile_asn BIGINT NOT NULL DEFAULT 0,
                        profile_organization VARCHAR(255) NOT NULL DEFAULT \'\',
                        provider_sources_json JSON NOT NULL,
                        reasons_json JSON NOT NULL,
                        target_host VARCHAR(255) NOT NULL DEFAULT \'\',
                        redirect_host VARCHAR(255) NOT NULL DEFAULT \'\',
                        KEY idx_redirect_decision_audit_log_created (created_at_unix),
                        KEY idx_redirect_decision_audit_log_slug (slug)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
                );
            } else {
                $this->pdo->exec(
                    'CREATE TABLE IF NOT EXISTS redirect_decision_metrics (
                        bucket_unix INTEGER NOT NULL,
                        slug TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        primary_reason TEXT NOT NULL,
                        window_mode TEXT NOT NULL,
                        country_code TEXT NOT NULL DEFAULT \'\',
                        device TEXT NOT NULL DEFAULT \'\',
                        total_count INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (bucket_unix, slug, decision, primary_reason, window_mode, country_code, device)
                    )'
                );
                $this->pdo->exec(
                    'CREATE TABLE IF NOT EXISTS redirect_decision_audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at_unix INTEGER NOT NULL,
                        link_id INTEGER NOT NULL DEFAULT 0,
                        slug TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        primary_reason TEXT NOT NULL,
                        window_mode TEXT NOT NULL,
                        delivery_outcome TEXT NOT NULL,
                        country_code TEXT NOT NULL DEFAULT \'\',
                        device TEXT NOT NULL DEFAULT \'\',
                        visitor_network TEXT NOT NULL DEFAULT \'\',
                        is_vpn_like INTEGER NOT NULL DEFAULT 0,
                        is_bot INTEGER NOT NULL DEFAULT 0,
                        profile_country_code TEXT NOT NULL DEFAULT \'\',
                        profile_asn INTEGER NOT NULL DEFAULT 0,
                        profile_organization TEXT NOT NULL DEFAULT \'\',
                        provider_sources_json TEXT NOT NULL DEFAULT \'[]\',
                        reasons_json TEXT NOT NULL DEFAULT \'[]\',
                        target_host TEXT NOT NULL DEFAULT \'\',
                        redirect_host TEXT NOT NULL DEFAULT \'\'
                    )'
                );
                $this->pdo->exec(
                    'CREATE INDEX IF NOT EXISTS idx_redirect_decision_audit_log_created
                     ON redirect_decision_audit_log (created_at_unix)'
                );
                $this->pdo->exec(
                    'CREATE INDEX IF NOT EXISTS idx_redirect_decision_audit_log_slug
                     ON redirect_decision_audit_log (slug)'
                );
            }
        } catch (Throwable $e) {
            return false;
        }

        $this->schemaReady = true;

        return true;
    }

    private function truncateText(mixed $value, int $maxLength): string
    {
        if ($value instanceof \Stringable || is_scalar($value)) {
            $text = trim((string) $value);
        } else {
            $text = '';
        }

        if ($text === '') {
            return '';
        }

        if (mb_strlen($text) <= $maxLength) {
            return $text;
        }

        return mb_substr($text, 0, $maxLength);
    }

    private function normalizeReason(mixed $value): string
    {
        $reason = $this->truncateText($value, 64);

        return $reason !== '' ? $reason : 'none';
    }

    private function driverName(): string
    {
        $driverName = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        return is_string($driverName) ? $driverName : '';
    }

    private function intValue(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        if (is_float($value)) {
            return (int) $value;
        }

        return 0;
    }

    /**
     * @param mixed $rows
     * @return list<DecisionMetricRow>
     */
    private function normalizeMetricRows(mixed $rows): array
    {
        if (!is_array($rows)) {
            return [];
        }

        $normalized = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $normalized[] = [
                'bucket_unix' => $this->intOrStringValue($row['bucket_unix'] ?? null),
                'slug' => $this->stringValue($row['slug'] ?? null),
                'decision' => $this->stringValue($row['decision'] ?? null),
                'primary_reason' => $this->stringValue($row['primary_reason'] ?? null),
                'window_mode' => $this->stringValue($row['window_mode'] ?? null),
                'country_code' => $this->stringValue($row['country_code'] ?? null),
                'device' => $this->stringValue($row['device'] ?? null),
                'total_count' => $this->intOrStringValue($row['total_count'] ?? null),
            ];
        }

        return $normalized;
    }

    /**
     * @param mixed $rows
     * @return list<DecisionLogRow>
     */
    private function normalizeLogRows(mixed $rows): array
    {
        if (!is_array($rows)) {
            return [];
        }

        $normalized = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            /** @var DecisionLogRow $typedRow */
            $typedRow = [];
            foreach ($row as $key => $value) {
                if (!is_string($key)) {
                    continue;
                }

                $typedRow[$key] = $this->intOrStringValue($value);
            }

            $normalized[] = $typedRow;
        }

        return $normalized;
    }

    /**
     * @param mixed $rows
     * @return list<CountryDecisionRow>
     */
    private function normalizeCountryDecisionRows(mixed $rows): array
    {
        if (!is_array($rows)) {
            return [];
        }

        $normalized = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $normalized[] = [
                'country_code' => $this->stringValue($row['country_code'] ?? null),
                'decision' => $this->stringValue($row['decision'] ?? null),
                'total_count' => $this->intOrStringValue($row['total_count'] ?? null),
            ];
        }

        return $normalized;
    }

    private function stringValue(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    private function intOrStringValue(mixed $value): int|string
    {
        if (is_int($value) || is_string($value)) {
            return $value;
        }

        return 0;
    }
}
