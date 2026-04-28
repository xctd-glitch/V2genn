<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;

interface NetworkProfileProviderInterface
{
    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile;
}
