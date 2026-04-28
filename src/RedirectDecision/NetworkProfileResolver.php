<?php

declare(strict_types=1);

namespace App\RedirectDecision;

use App\RedirectDecision\Cache\NetworkProfileCacheRepositoryInterface;
use App\RedirectDecision\Provider\NetworkProfileProviderInterface;
use App\RedirectDecision\Value\NetworkProfile;

final class NetworkProfileResolver
{
    /**
     * @param list<NetworkProfileProviderInterface> $providers
     */
    public function __construct(
        private readonly array $providers,
        private readonly ?NetworkProfileCacheRepositoryInterface $persistentCache = null,
        private readonly int $persistentCacheTtlSeconds = 21600
    ) {
    }

    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): NetworkProfile
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return new NetworkProfile();
        }

        $cacheKey = 'rd_profile_' . md5($ip);
        $nowUnix = time();
        if (function_exists('\tp_apcu_fetch')) {
            $cached = \tp_apcu_fetch($cacheKey);
            if (is_array($cached)) {
                return new NetworkProfile(
                    $this->normalizeString($cached['country_code'] ?? null),
                    $this->normalizeInt($cached['asn'] ?? null),
                    $this->normalizeString($cached['organization'] ?? null),
                    $this->normalizeBool($cached['is_vpn'] ?? null),
                    $this->normalizeBool($cached['is_proxy'] ?? null),
                    $this->normalizeBool($cached['is_hosting'] ?? null),
                    $this->normalizeSources($cached['sources'] ?? null)
                );
            }
        }

        if ($this->persistentCache instanceof NetworkProfileCacheRepositoryInterface) {
            $cachedProfile = $this->persistentCache->fetchFresh($ip, $nowUnix);
            if ($cachedProfile instanceof NetworkProfile) {
                if (\function_exists('tp_apcu_store')) {
                    call_user_func('tp_apcu_store', $cacheKey, $cachedProfile->toArray(), 21600);
                }

                return $cachedProfile;
            }
        }

        $profile = new NetworkProfile();
        foreach ($this->providers as $provider) {
            $resolved = $provider->resolve($ip, $server);
            if ($resolved === null) {
                continue;
            }

            $profile = $profile->merge($resolved);
        }

        if (
            !$profile->isVpnLike()
            && $profile->countryCode() === ''
            && $profile->asn() === 0
            && $profile->organization() === ''
            && $this->persistentCache instanceof NetworkProfileCacheRepositoryInterface
        ) {
            $staleProfile = $this->persistentCache->fetchLatest($ip);
            if ($staleProfile instanceof NetworkProfile) {
                $profile = $staleProfile;
            }
        }

        if ($this->persistentCache instanceof NetworkProfileCacheRepositoryInterface) {
            $this->persistentCache->store($ip, $profile, $this->persistentCacheTtlSeconds, $nowUnix);
            if ($this->shouldPurgePersistentCache($nowUnix)) {
                $this->persistentCache->purgeExpired($nowUnix);
            }
        }

        if (\function_exists('tp_apcu_store')) {
            call_user_func('tp_apcu_store', $cacheKey, $profile->toArray(), 21600);
        }

        return $profile;
    }

    private function shouldPurgePersistentCache(int $nowUnix): bool
    {
        if (!function_exists('\tp_apcu_add')) {
            return false;
        }

        $bucket = (string) intdiv($nowUnix, 900);

        return \tp_apcu_add('rd_profile_cache_purge_' . $bucket, 1, 900);
    }

    private function normalizeString(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }

        return $value;
    }

    private function normalizeInt(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        return 0;
    }

    private function normalizeBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        if (is_string($value)) {
            return in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'on'], true);
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function normalizeSources(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $normalized = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                continue;
            }

            $normalized[] = $item;
        }

        return $normalized;
    }
}
