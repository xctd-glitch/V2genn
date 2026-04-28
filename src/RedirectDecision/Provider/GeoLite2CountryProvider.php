<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;
use Throwable;

final class GeoLite2CountryProvider implements NetworkProfileProviderInterface
{
    public function __construct(
        private readonly string $databasePath
    ) {
    }

    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        if ($this->databasePath === '' || !is_file($this->databasePath)) {
            return null;
        }

        if (!class_exists('MaxMind\\Db\\Reader')) {
            return null;
        }

        try {
            $reader = new \MaxMind\Db\Reader($this->databasePath);
            $record = $reader->get($ip);
            $reader->close();
        } catch (Throwable $e) {
            return null;
        }

        if (!is_array($record)) {
            return null;
        }

        $country = $record['country'] ?? null;
        if (!is_array($country)) {
            return null;
        }

        $isoCode = $country['iso_code'] ?? null;
        $countryCode = is_string($isoCode) ? strtoupper(trim($isoCode)) : '';
        if ($countryCode === '' || preg_match('/^[A-Z]{2}$/', $countryCode) !== 1) {
            return null;
        }

        return new NetworkProfile($countryCode, 0, '', false, false, false, ['geolite2_country']);
    }
}
