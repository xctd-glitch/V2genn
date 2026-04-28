<?php

declare(strict_types=1);

namespace App\RedirectDecision\Cache;

use App\RedirectDecision\Value\NetworkProfile;

interface NetworkProfileCacheRepositoryInterface
{
    public function fetchFresh(string $ip, int $nowUnix): ?NetworkProfile;

    public function fetchLatest(string $ip): ?NetworkProfile;

    public function store(string $ip, NetworkProfile $profile, int $ttlSeconds, int $nowUnix): void;

    public function purgeExpired(int $nowUnix): void;
}
