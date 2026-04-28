<?php

declare(strict_types=1);

require_once __DIR__ . '/runtime_compat.php';

if (!function_exists('tp_server_string')) {
    function tp_server_string(string $key): string
    {
        $value = $_SERVER[$key] ?? null;

        return is_string($value) ? $value : '';
    }
}

if (!function_exists('tp_server_int')) {
    function tp_server_int(string $key): int
    {
        $value = $_SERVER[$key] ?? null;
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        return 0;
    }
}

if (!function_exists('tp_is_https')) {
    function tp_is_https(): bool
    {
        $https = strtolower(tp_server_string('HTTPS'));
        if ($https !== '' && $https !== 'off') {
            return true;
        }

        if (tp_server_int('SERVER_PORT') === 443) {
            return true;
        }

        $forwardedProto = strtolower(trim(tp_server_string('HTTP_X_FORWARDED_PROTO')));

        return $forwardedProto === 'https';
    }
}

if (!function_exists('tp_is_localhost')) {
    function tp_is_localhost(): bool
    {
        $host = tp_request_host();

        return in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || str_ends_with($host, '.local');
    }
}

if (!function_exists('tp_request_host')) {
    function tp_request_host(): string
    {
        $hostValue = tp_server_string('HTTP_HOST');
        if ($hostValue === '') {
            $hostValue = tp_server_string('SERVER_NAME');
        }

        $host = strtolower($hostValue);
        $host = preg_replace('/:\d+$/', '', $host) ?? $host;
        $host = trim($host, '[]');

        return $host;
    }
}

if (!function_exists('tp_can_send_cross_origin_opener_policy')) {
    function tp_can_send_cross_origin_opener_policy(): bool
    {
        if (tp_is_https()) {
            return true;
        }

        return tp_request_host() === 'localhost';
    }
}

if (!function_exists('tp_secure_session_bootstrap')) {
    function tp_secure_session_bootstrap(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $isHttps = tp_is_https();

        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_strict_mode', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.cookie_secure', $isHttps ? '1' : '0');

        $sessionSavePath = trim((string) ini_get('session.save_path'));
        $resolvedSessionPath = $sessionSavePath;
        if (str_contains($resolvedSessionPath, ';')) {
            $parts = explode(';', $resolvedSessionPath);
            $resolvedSessionPath = (string) end($parts);
        }
        $resolvedSessionPath = trim($resolvedSessionPath, " \t\n\r\0\x0B\"'");

        $hasWritableSessionPath = $resolvedSessionPath !== ''
            && is_dir($resolvedSessionPath)
            && is_writable($resolvedSessionPath);

        if (!$hasWritableSessionPath) {
            $fallbackSessionPath = dirname(__DIR__) . '/data/sessions';
            if (
                (!is_dir($fallbackSessionPath) && @mkdir($fallbackSessionPath, 0775, true))
                || is_dir($fallbackSessionPath)
            ) {
                if (is_writable($fallbackSessionPath)) {
                    ini_set('session.save_path', $fallbackSessionPath);
                }
            }
        }

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }
}

if (!function_exists('tp_destroy_session')) {
    function tp_destroy_session(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return;
        }

        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $cookieName = session_name();
            $params = session_get_cookie_params();
            if ($cookieName !== false) {
                setcookie($cookieName, '', [
                    'expires' => time() - 42000,
                    'path' => $params['path'],
                    'domain' => $params['domain'],
                    'secure' => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'],
                ]);
            }
        }

        session_destroy();
    }
}

if (!function_exists('tp_csp_nonce')) {
    function tp_csp_nonce(): string
    {
        /** @var string $nonce */
        static $nonce = '';

        if ($nonce === '') {
            $nonce = (string) bin2hex(tp_random_bytes(16));
        }

        return $nonce;
    }
}

if (!function_exists('tp_csrf_token')) {
    function tp_csrf_token(): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new RuntimeException('Session must be active before generating a CSRF token.');
        }

        if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token']) || $_SESSION['csrf_token'] === '') {
            $_SESSION['csrf_token'] = bin2hex(tp_random_bytes(32));
        }

        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('tp_is_valid_csrf_token')) {
    function tp_is_valid_csrf_token(?string $token): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        if (!is_string($token) || $token === '') {
            return false;
        }

        $sessionToken = $_SESSION['csrf_token'] ?? '';
        if (!is_string($sessionToken) || $sessionToken === '') {
            return false;
        }

        return hash_equals($sessionToken, $token);
    }
}

if (!function_exists('tp_csp_nonce_attr')) {
    function tp_csp_nonce_attr(): string
    {
        return ' nonce="' . htmlspecialchars(tp_csp_nonce(), ENT_QUOTES, 'UTF-8') . '"';
    }
}

if (!function_exists('tp_send_security_headers')) {
    function tp_send_security_headers(): void
    {
        if (headers_sent()) {
            return;
        }

        $nonce = tp_csp_nonce();
        $csp = [
            "default-src 'self'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "manifest-src 'self'",
            "worker-src 'self'",
            "script-src 'self' 'nonce-{$nonce}' 'unsafe-eval'",
            "script-src-attr 'none'",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "style-src-attr 'unsafe-inline'",
            "img-src 'self' data: blob: https:",
            "font-src 'self' data: https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-src 'none'",
            "media-src 'self'",
        ];

        if (tp_is_https() && !tp_is_localhost()) {
            $csp[] = 'upgrade-insecure-requests';
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }

        header_remove('X-Powered-By');
        header('Content-Security-Policy: ' . implode('; ', $csp));
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()');
        if (tp_can_send_cross_origin_opener_policy()) {
            header('Cross-Origin-Opener-Policy: same-origin');
        }
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Origin-Agent-Cluster: ?1');
    }
}
