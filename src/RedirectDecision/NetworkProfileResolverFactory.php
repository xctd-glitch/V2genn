<?php

declare(strict_types=1);

namespace App\RedirectDecision;

use App\RedirectDecision\Cache\NetworkProfileCacheRepositoryInterface;
use App\RedirectDecision\Provider\CloudflareHeaderProfileProvider;
use App\RedirectDecision\Provider\GenericCountryHeaderProvider;
use App\RedirectDecision\Provider\GeoLite2CountryProvider;
use App\RedirectDecision\Provider\HeaderRiskProfileProvider;
use App\RedirectDecision\Provider\IptoAsnProfileProvider;
use App\RedirectDecision\Provider\TrustedHeaderAsnProfileProvider;

final class NetworkProfileResolverFactory
{
    public function __construct(
        private readonly string $geoLitePath,
        private readonly string $iptoAsnEndpoint = '',
        private readonly ?NetworkProfileCacheRepositoryInterface $persistentCache = null,
        private readonly int $persistentCacheTtlSeconds = 21600
    ) {
    }

    public function create(): NetworkProfileResolver
    {
        $providers = [
            new TrustedHeaderAsnProfileProvider(),
            new CloudflareHeaderProfileProvider(),
            new GenericCountryHeaderProvider(),
            new HeaderRiskProfileProvider(),
            new GeoLite2CountryProvider($this->geoLitePath),
        ];

        $iptoAsnEndpoint = trim($this->iptoAsnEndpoint);
        if ($iptoAsnEndpoint !== '') {
            $providers[] = new IptoAsnProfileProvider($iptoAsnEndpoint);
        }

        return new NetworkProfileResolver(
            $providers,
            $this->persistentCache,
            $this->normalizePersistentCacheTtl($this->persistentCacheTtlSeconds)
        );
    }

    private function normalizePersistentCacheTtl(int $ttlSeconds): int
    {
        if ($ttlSeconds < 300) {
            return 300;
        }

        if ($ttlSeconds > 86400) {
            return 86400;
        }

        return $ttlSeconds;
    }
}
