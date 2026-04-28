<?php

declare(strict_types=1);

if (!function_exists('tp_normalize_host_value')) {
    function tp_normalize_host_value(string $value): string
    {
        $value = strtolower(trim($value));
        if ($value === '') {
            return '';
        }

        if (str_contains($value, '://')) {
            $parsedHost = parse_url($value, PHP_URL_HOST);
            if ($parsedHost !== null && $parsedHost !== false) {
                $value = (string) $parsedHost;
            }
        }

        $value = preg_replace('/^[^@\/?#]*@/', '', $value) ?? $value;
        $value = preg_replace('/^[a-z][a-z0-9+.-]*:\/\//i', '', $value) ?? $value;
        $value = preg_replace('/[\/?#].*$/', '', $value) ?? $value;
        $value = preg_replace('/^\*\./', '', $value) ?? $value;
        $value = preg_replace('/:\d+$/', '', $value) ?? $value;
        $value = trim($value, ". \t\n\r\0\x0B[]");

        return $value;
    }
}

if (!function_exists('tp_request_host')) {
    function tp_request_host(): string
    {
        $hostValue = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
        $host = is_string($hostValue) ? tp_normalize_host_value($hostValue) : 'localhost';

        return $host !== '' ? $host : 'localhost';
    }
}

if (!function_exists('tp_request_scheme')) {
    function tp_request_scheme(): string
    {
        $https = $_SERVER['HTTPS'] ?? null;
        if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
            return 'https';
        }

        $forwardedProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
        if (is_string($forwardedProto) && strtolower(trim($forwardedProto)) === 'https') {
            return 'https';
        }

        $serverPort = $_SERVER['SERVER_PORT'] ?? null;
        if ((is_int($serverPort) && $serverPort === 443) || (is_string($serverPort) && $serverPort === '443')) {
            return 'https';
        }

        return 'http';
    }
}

if (!function_exists('tp_is_public_domain_host')) {
    function tp_is_public_domain_host(string $host): bool
    {
        $host = tp_normalize_host_value($host);

        if ($host === '' || filter_var($host, FILTER_VALIDATE_IP) !== false || !str_contains($host, '.')) {
            return false;
        }

        return preg_match(
            '/^(?=.{1,253}$)(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i',
            $host,
        ) === 1;
    }
}

if (!function_exists('tp_public_base_host')) {
    function tp_public_base_host(string $configuredHost = ''): string
    {
        $normalizedConfiguredHost = tp_normalize_host_value($configuredHost);
        if ($normalizedConfiguredHost !== '' && tp_is_public_domain_host($normalizedConfiguredHost)) {
            return $normalizedConfiguredHost;
        }

        return tp_request_host();
    }
}

if (!function_exists('tp_public_base_url')) {
    function tp_public_base_url(string $configuredHost = ''): string
    {
        return tp_request_scheme() . '://' . tp_public_base_host($configuredHost);
    }
}
