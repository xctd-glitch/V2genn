<?php

declare(strict_types=1);

namespace App\RedirectDecision\Provider;

use App\RedirectDecision\Value\NetworkProfile;
use Throwable;

final class IptoAsnProfileProvider implements NetworkProfileProviderInterface
{
    public function __construct(
        private readonly string $endpoint
    ) {
    }

    /**
     * @param array<string, string> $server
     */
    public function resolve(string $ip, array $server): ?NetworkProfile
    {
        $endpoint = trim($this->endpoint);
        if (
            $endpoint === ''
            || (
                strpos($endpoint, '{ip}') === false
                && filter_var($endpoint, FILTER_VALIDATE_URL) === false
            )
        ) {
            return null;
        }

        if (!function_exists('curl_init')) {
            return null;
        }

        if (strpos($endpoint, '{ip}') !== false) {
            $url = str_replace('{ip}', rawurlencode($ip), $endpoint);
        } else {
            $url = rtrim($endpoint, '/') . '/' . rawurlencode($ip);
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS => 250,
            CURLOPT_CONNECTTIMEOUT_MS => 150,
            CURLOPT_HTTPGET => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);

        try {
            $body = curl_exec($ch);
            $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        } catch (Throwable $e) {
            return null;
        }

        if (!is_string($body) || $body === '' || $statusCode < 200 || $statusCode >= 300) {
            return null;
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return null;
        }

        if (array_key_exists('announced', $decoded) && $decoded['announced'] === false) {
            return null;
        }

        $asn = $this->normalizeInt($decoded['asn'] ?? $decoded['as_number'] ?? null);
        $organization = $this->normalizeString($decoded['as_description'] ?? $decoded['organization'] ?? null);
        $countryCode = strtoupper($this->normalizeString($decoded['as_country_code'] ?? $decoded['country_code'] ?? $decoded['country'] ?? null));
        $isHosting = $this->detectHostingOrganization($organization);

        if ($asn === 0 && $organization === '' && $countryCode === '') {
            return null;
        }

        if ($countryCode !== '' && preg_match('/^[A-Z]{2}$/', $countryCode) !== 1) {
            $countryCode = '';
        }

        return new NetworkProfile(
            $countryCode,
            $asn,
            $organization,
            false,
            false,
            $isHosting,
            ['iptoasn_http']
        );
    }

    private function detectHostingOrganization(string $organization): bool
    {
        if ($organization === '') {
            return false;
        }

        return preg_match(
            '/amazon|aws|google cloud|gcp|microsoft|azure|digitalocean|ovh|hetzner|oracle cloud|linode|vultr|cloudflare|choopa|leaseweb|alibaba cloud/i',
            $organization
        ) === 1;
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

    private function normalizeString(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }

        return trim($value);
    }
}
