<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;

final class HeaderRiskProfileProvider implements NetworkProfileProviderInterface
{
    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        $countryCode = strtoupper(trim((string) ($server['HTTP_CF_IPCOUNTRY'] ?? '')));
        $isVpn = $countryCode === 'T1';
        $isProxy = false;
        $isHosting = false;

        $headerMap = [
            'HTTP_X_TRAFFIC_VPN' => 'vpn',
            'HTTP_X_VPN' => 'vpn',
            'HTTP_X_PROXY' => 'proxy',
            'HTTP_CF_VPN' => 'vpn',
            'HTTP_X_HOSTING_PROVIDER' => 'hosting',
        ];

        foreach ($headerMap as $header => $type) {
            $value = strtolower(trim((string) ($server[$header] ?? '')));
            if (!in_array($value, ['1', 'true', 'yes', 'on'], true)) {
                continue;
            }

            if ($type === 'vpn') {
                $isVpn = true;
            } elseif ($type === 'proxy') {
                $isProxy = true;
            } elseif ($type === 'hosting') {
                $isHosting = true;
            }
        }

        if (!$isVpn && !$isProxy && !$isHosting) {
            return null;
        }

        return new NetworkProfile('', 0, '', $isVpn, $isProxy, $isHosting, ['header_risk']);
    }
}
