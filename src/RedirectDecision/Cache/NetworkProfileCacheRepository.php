<?php

declare(strict_types=1);

namespace App\RedirectDecision\Cache;

use App\RedirectDecision\Value\NetworkProfile;
use PDO;
use Throwable;

/**
 * @phpstan-type NetworkProfileCacheRow array{
 *     country_code: string,
 *     asn: int|string,
 *     organization: string,
 *     is_vpn: bool|int|string,
 *     is_proxy: bool|int|string,
 *     is_hosting: bool|int|string,
 *     sources_json: string,
 *     checked_at_unix: int|string,
 *     expires_at_unix: int|string
 * }
 */
final class NetworkProfileCacheRepository implements NetworkProfileCacheRepositoryInterface
{
    private ?PDO $pdo = null;
    private bool $schemaReady = false;

    public function __construct(
        private readonly string $databasePath
    ) {
    }

    public function fetchFresh(string $ip, int $nowUnix): ?NetworkProfile
    {
        $row = $this->fetchRow($ip);
        if ($row === null) {
            return null;
        }

        if ((int) $row['expires_at_unix'] <= $nowUnix) {
            return null;
        }

        return $this->hydrateProfile($row);
    }

    public function fetchLatest(string $ip): ?NetworkProfile
    {
        $row = $this->fetchRow($ip);
        if ($row === null) {
            return null;
        }

        return $this->hydrateProfile($row);
    }

    public function store(string $ip, NetworkProfile $profile, int $ttlSeconds, int $nowUnix): void
    {
        $pdo = $this->pdo();
        if ($pdo === null) {
            return;
        }

        $expiresAtUnix = $nowUnix + max(60, $ttlSeconds);
        $sourcesJson = json_encode($profile->sources(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($sourcesJson)) {
            $sourcesJson = '[]';
        }

        try {
            $statement = $pdo->prepare(
                'INSERT INTO network_profile_cache
                    (ip, country_code, asn, organization, is_vpn, is_proxy, is_hosting, sources_json, checked_at_unix, expires_at_unix)
                 VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(ip) DO UPDATE SET
                    country_code = excluded.country_code,
                    asn = excluded.asn,
                    organization = excluded.organization,
                    is_vpn = excluded.is_vpn,
                    is_proxy = excluded.is_proxy,
                    is_hosting = excluded.is_hosting,
                    sources_json = excluded.sources_json,
                    checked_at_unix = excluded.checked_at_unix,
                    expires_at_unix = excluded.expires_at_unix'
            );
            $statement->execute([
                $ip,
                $profile->countryCode(),
                $profile->asn(),
                $profile->organization(),
                $profile->isVpn() ? 1 : 0,
                $profile->isProxy() ? 1 : 0,
                $profile->isHosting() ? 1 : 0,
                $sourcesJson,
                $nowUnix,
                $expiresAtUnix,
            ]);
        } catch (Throwable $e) {
            return;
        }
    }

    public function purgeExpired(int $nowUnix): void
    {
        $pdo = $this->pdo();
        if ($pdo === null) {
            return;
        }

        try {
            $statement = $pdo->prepare('DELETE FROM network_profile_cache WHERE expires_at_unix <= ?');
            $statement->execute([$nowUnix]);
        } catch (Throwable $e) {
            return;
        }
    }

    public function path(): string
    {
        return $this->databasePath;
    }

    /**
     * @return NetworkProfileCacheRow|null
     */
    private function fetchRow(string $ip): ?array
    {
        $pdo = $this->pdo();
        if ($pdo === null) {
            return null;
        }

        try {
            $statement = $pdo->prepare(
                'SELECT country_code, asn, organization, is_vpn, is_proxy, is_hosting, sources_json, checked_at_unix, expires_at_unix
                 FROM network_profile_cache
                 WHERE ip = ?
                 LIMIT 1'
            );
            $statement->execute([$ip]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return null;
        }

        if (!is_array($row)) {
            return null;
        }

        return [
            'country_code' => is_string($row['country_code'] ?? null) ? $row['country_code'] : '',
            'asn' => is_int($row['asn'] ?? null) || is_string($row['asn'] ?? null) ? $row['asn'] : 0,
            'organization' => is_string($row['organization'] ?? null) ? $row['organization'] : '',
            'is_vpn' => is_bool($row['is_vpn'] ?? null) || is_int($row['is_vpn'] ?? null) || is_string($row['is_vpn'] ?? null) ? $row['is_vpn'] : false,
            'is_proxy' => is_bool($row['is_proxy'] ?? null) || is_int($row['is_proxy'] ?? null) || is_string($row['is_proxy'] ?? null) ? $row['is_proxy'] : false,
            'is_hosting' => is_bool($row['is_hosting'] ?? null) || is_int($row['is_hosting'] ?? null) || is_string($row['is_hosting'] ?? null) ? $row['is_hosting'] : false,
            'sources_json' => is_string($row['sources_json'] ?? null) ? $row['sources_json'] : '[]',
            'checked_at_unix' => is_int($row['checked_at_unix'] ?? null) || is_string($row['checked_at_unix'] ?? null) ? $row['checked_at_unix'] : 0,
            'expires_at_unix' => is_int($row['expires_at_unix'] ?? null) || is_string($row['expires_at_unix'] ?? null) ? $row['expires_at_unix'] : 0,
        ];
    }

    /**
     * @param NetworkProfileCacheRow $row
     */
    private function hydrateProfile(array $row): NetworkProfile
    {
        return new NetworkProfile(
            strtoupper(trim($row['country_code'])),
            (int) $row['asn'],
            trim($row['organization']),
            (bool) $row['is_vpn'],
            (bool) $row['is_proxy'],
            (bool) $row['is_hosting'],
            $this->normalizeSources($row['sources_json'])
        );
    }

    /**
     * @return list<string>
     */
    private function normalizeSources(mixed $value): array
    {
        $decoded = is_string($value) ? json_decode($value, true) : null;
        if (!is_array($decoded)) {
            return [];
        }

        $normalized = [];
        foreach ($decoded as $item) {
            if (!is_string($item)) {
                continue;
            }

            $normalized[] = $item;
        }

        return $normalized;
    }

    private function pdo(): ?PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        if ($this->databasePath === '') {
            return null;
        }

        $needsBootstrap = !is_file($this->databasePath) || (int) (@filesize($this->databasePath) ?: 0) === 0;

        $directory = dirname($this->databasePath);
        if (!is_dir($directory) && !mkdir($directory, 0775, true) && !is_dir($directory)) {
            return null;
        }

        try {
            $pdo = new PDO(
                'sqlite:' . $this->databasePath,
                null,
                null,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
            $pdo->exec('PRAGMA busy_timeout = 1000');
            $pdo->exec('PRAGMA journal_mode = WAL');
            if (!$this->ensureSchema($pdo, $needsBootstrap)) {
                return null;
            }
            $this->pdo = $pdo;
        } catch (Throwable $e) {
            return null;
        }

        return $this->pdo;
    }

    private function ensureSchema(PDO $pdo, bool $needsBootstrap): bool
    {
        if ($this->schemaReady) {
            return true;
        }

        if (!$needsBootstrap) {
            $this->schemaReady = true;

            return true;
        }

        try {
            $pdo->exec(
                'CREATE TABLE IF NOT EXISTS network_profile_cache (
                    ip TEXT PRIMARY KEY,
                    country_code TEXT NOT NULL DEFAULT \'\',
                    asn INTEGER NOT NULL DEFAULT 0,
                    organization TEXT NOT NULL DEFAULT \'\',
                    is_vpn INTEGER NOT NULL DEFAULT 0,
                    is_proxy INTEGER NOT NULL DEFAULT 0,
                    is_hosting INTEGER NOT NULL DEFAULT 0,
                    sources_json TEXT NOT NULL DEFAULT \'[]\',
                    checked_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL
                )'
            );
            $pdo->exec(
                'CREATE INDEX IF NOT EXISTS idx_network_profile_cache_expires
                 ON network_profile_cache (expires_at_unix)'
            );
        } catch (Throwable $e) {
            return false;
        }

        $this->schemaReady = true;

        return true;
    }
}
