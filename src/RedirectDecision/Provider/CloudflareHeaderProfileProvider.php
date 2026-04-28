<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;

final class CloudflareHeaderProfileProvider implements NetworkProfileProviderInterface
{
    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        $countryCode = strtoupper(trim((string) ($server['HTTP_CF_IPCOUNTRY'] ?? '')));
        if ($countryCode !== '' && preg_match('/^[A-Z]{2}$/', $countryCode) === 1) {
            return new NetworkProfile($countryCode, 0, '', false, false, false, ['cloudflare_header_country']);
        }

        return null;
    }
}
