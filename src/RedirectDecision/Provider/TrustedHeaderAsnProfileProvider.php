<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;

final class TrustedHeaderAsnProfileProvider implements NetworkProfileProviderInterface
{
    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        $asn = $this->resolveAsn($server);
        $organization = $this->resolveOrganization($server);

        if ($asn === 0 && $organization === '') {
            return null;
        }

        return new NetworkProfile('', $asn, $organization, false, false, false, ['trusted_header_asn']);
    }

    /**
     * @param array<string, string> $server
     */
    private function resolveAsn(array $server): int
    {
        foreach (
            [
                'HTTP_X_TRAFFIC_ASN',
                'HTTP_X_TRAFFIC_AS_NUMBER',
                'HTTP_X_ASN',
                'HTTP_X_AS_NUMBER',
            ] as $header
        ) {
            $rawValue = trim((string) ($server[$header] ?? ''));
            if ($rawValue === '') {
                continue;
            }

            if (preg_match('/^(?:AS)?(\d+)$/i', $rawValue, $matches) !== 1) {
                continue;
            }

            return (int) $matches[1];
        }

        return 0;
    }

    /**
     * @param array<string, string> $server
     */
    private function resolveOrganization(array $server): string
    {
        foreach (
            [
                'HTTP_X_TRAFFIC_ORGANIZATION',
                'HTTP_X_TRAFFIC_ORG',
                'HTTP_X_AS_ORGANIZATION',
                'HTTP_X_AS_ORG',
            ] as $header
        ) {
            $value = trim((string) ($server[$header] ?? ''));
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }
}
