<?php

declare(strict_types=1);

namespace App\RedirectDecision\Cache;

use App\RedirectDecision\Value\NetworkProfile;
use PDO;
use Throwable;

/**
 * @phpstan-type PdoNetworkProfileCacheRow array{
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
final class PdoNetworkProfileCacheRepository implements NetworkProfileCacheRepositoryInterface
{
    private bool $schemaReady = false;
    private bool $schemaChecked = false;

    public function __construct(
        private readonly PDO $pdo
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
        if (!$this->ensureSchema()) {
            return;
        }

        $expiresAtUnix = $nowUnix + max(60, $ttlSeconds);
        $sourcesJson = json_encode($profile->sources(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($sourcesJson)) {
            $sourcesJson = '[]';
        }

        try {
            if ($this->driverName() === 'mysql') {
                $statement = $this->pdo->prepare(
                    'INSERT INTO redirect_network_profile_cache
                        (ip, country_code, asn, organization, is_vpn, is_proxy, is_hosting, sources_json, checked_at_unix, expires_at_unix)
                     VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                        country_code = VALUES(country_code),
                        asn = VALUES(asn),
                        organization = VALUES(organization),
                        is_vpn = VALUES(is_vpn),
                        is_proxy = VALUES(is_proxy),
                        is_hosting = VALUES(is_hosting),
                        sources_json = VALUES(sources_json),
                        checked_at_unix = VALUES(checked_at_unix),
                        expires_at_unix = VALUES(expires_at_unix)'
                );
            } else {
                $statement = $this->pdo->prepare(
                    'INSERT INTO redirect_network_profile_cache
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
            }

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
        if (!$this->ensureSchema()) {
            return;
        }

        try {
            $statement = $this->pdo->prepare('DELETE FROM redirect_network_profile_cache WHERE expires_at_unix <= ?');
            $statement->execute([$nowUnix]);
        } catch (Throwable $e) {
            return;
        }
    }

    /**
     * @return PdoNetworkProfileCacheRow|null
     */
    private function fetchRow(string $ip): ?array
    {
        if (!$this->ensureSchema()) {
            return null;
        }

        try {
            $statement = $this->pdo->prepare(
                'SELECT country_code, asn, organization, is_vpn, is_proxy, is_hosting, sources_json, checked_at_unix, expires_at_unix
                 FROM redirect_network_profile_cache
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
     * @param PdoNetworkProfileCacheRow $row
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

    private function ensureSchema(): bool
    {
        if ($this->schemaChecked) {
            return $this->schemaReady;
        }

        $driverName = $this->driverName();
        $cacheKey = 'rd_profile_cache_schema_' . $driverName;
        if (function_exists('apcu_fetch')) {
            $fetch = 'apcu_fetch';
            $cacheHit = false;
            $cached = $fetch($cacheKey, $cacheHit);
            if ($cacheHit) {
                $this->schemaChecked = true;
                $this->schemaReady = $cached === 1 || $cached === true;

                return $this->schemaReady;
            }
        }

        try {
            $statement = $this->pdo->query('SELECT 1 FROM redirect_network_profile_cache LIMIT 1');
            $this->schemaReady = $statement !== false;
        } catch (Throwable $e) {
            $this->schemaReady = false;
        }

        $this->schemaChecked = true;
        if (function_exists('apcu_store')) {
            $store = 'apcu_store';
            $store($cacheKey, $this->schemaReady ? 1 : 0, $this->schemaReady ? 600 : 60);
        }

        return $this->schemaReady;
    }

    private function driverName(): string
    {
        $driverName = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        return is_string($driverName) ? $driverName : '';
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
}
