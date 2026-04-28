<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;

/**
 * Reads the X-Country-Code header set by reverse proxies (nginx GeoIP, cPanel, etc.).
 * Positioned after CloudflareHeaderProfileProvider so CF-IPCountry takes precedence.
 */
final class GenericCountryHeaderProvider implements NetworkProfileProviderInterface
{
    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        $countryCode = strtoupper(trim((string) ($server['HTTP_X_COUNTRY_CODE'] ?? '')));
        if ($countryCode !== '' && preg_match('/^[A-Z]{2}$/', $countryCode) === 1) {
            return new NetworkProfile($countryCode, 0, '', false, false, false, ['generic_country_header']);
        }

        return null;
    }
}
