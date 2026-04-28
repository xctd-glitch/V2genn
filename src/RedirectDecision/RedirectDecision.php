<?php

declare(strict_types=1);

/**
 * @phpstan-type RedirectDecisionConfig array{
 *     enabled: bool,
 *     redirect_url: string,
 *     allowed_countries: list<string>,
 *     cycle_anchor_unix: int,
 *     filter_duration_seconds: int,
 *     normal_duration_seconds: int,
 *     require_wap: bool,
 *     require_no_vpn: bool,
 *     updated_at: string
 * }
 * @phpstan-type RedirectDecisionWindow array{
 *     mode: 'filter'|'normal',
 *     cycle_length_seconds: int,
 *     cycle_position_seconds: int,
 *     seconds_until_switch: int,
 *     next_switch_at_unix: int
 * }
 * @phpstan-type RedirectDecisionContext array{
 *     device: 'wap'|'web',
 *     country: string,
 *     is_vpn: bool,
 *     is_bot: bool,
 *     redirect_url: string
 * }
 * @phpstan-type RedirectDecisionResult array{
 *     decision: string,
 *     redirect_url: string,
 *     config: RedirectDecisionConfig,
 *     window: RedirectDecisionWindow,
 *     context: RedirectDecisionContext,
 *     reasons: list<string>
 * }
 * @phpstan-type RedirectDecisionMeta array{
 *     title?: mixed,
 *     description?: mixed,
 *     image?: mixed,
 *     canonical_url?: mixed
 * }
 */
final class RedirectDecision
{
    public const FILTER_DURATION_SECONDS = 120;
    public const NORMAL_DURATION_SECONDS = 180;

    private const MIN_DURATION_SECONDS = 10;
    private const MAX_DURATION_SECONDS = 86400;

    private const CONFIG_CACHE_TTL_SECONDS = 300;

    public static function storagePath(): string
    {
        return dirname(__DIR__, 2) . '/data/redirect_decision_config.json';
    }

    private static function configCacheKey(): string
    {
        return 'redirect_decision_config_' . md5(self::storagePath());
    }

    /**
     * @return RedirectDecisionConfig|null
     */
    private static function fetchCachedConfig(string $fingerprint): ?array
    {
        if ($fingerprint === '' || !function_exists('apcu_fetch')) {
            return null;
        }

        $fetch = 'apcu_fetch';
        $cacheHit = false;
        $cached = $fetch(self::configCacheKey(), $cacheHit);
        if (
            !$cacheHit
            || !is_array($cached)
            || ($cached['fingerprint'] ?? '') !== $fingerprint
            || !is_array($cached['config'] ?? null)
        ) {
            return null;
        }

        $config = $cached['config'];
        if (!self::isRedirectDecisionConfig($config)) {
            return null;
        }

        return $config;
    }

    /**
     * @param RedirectDecisionConfig $config
     */
    private static function storeCachedConfig(array $config, string $fingerprint): void
    {
        if ($fingerprint === '' || !function_exists('apcu_store')) {
            return;
        }

        $store = 'apcu_store';
        $store(self::configCacheKey(), [
            'fingerprint' => $fingerprint,
            'config' => $config,
        ], self::CONFIG_CACHE_TTL_SECONDS);
    }

    private static function clearCachedConfig(): void
    {
        if (function_exists('apcu_delete')) {
            $delete = 'apcu_delete';
            $delete(self::configCacheKey());
        }
    }

    /**
     * @return RedirectDecisionConfig
     */
    public static function defaultConfig(): array
    {
        return [
            'enabled' => false,
            'redirect_url' => '',
            'allowed_countries' => [],
            'cycle_anchor_unix' => time(),
            'filter_duration_seconds' => self::FILTER_DURATION_SECONDS,
            'normal_duration_seconds' => self::NORMAL_DURATION_SECONDS,
            'require_wap' => true,
            'require_no_vpn' => true,
            'updated_at' => gmdate(DATE_ATOM),
        ];
    }

    /**
     * @return RedirectDecisionConfig
     */
    public static function loadConfig(): array
    {
        $path = self::storagePath();
        if (!is_file($path)) {
            self::clearCachedConfig();

            return self::defaultConfig();
        }

        $mtime = (int) (@filemtime($path) ?: 0);
        $size = (int) (@filesize($path) ?: 0);
        $fingerprint = $mtime . ':' . $size;
        $cachedConfig = self::fetchCachedConfig($fingerprint);
        if ($cachedConfig !== null) {
            return $cachedConfig;
        }

        $raw = file_get_contents($path);
        if (!is_string($raw) || $raw === '') {
            return self::defaultConfig();
        }

        $decoded = json_decode($raw, true);
        if (!self::isStringKeyArray($decoded)) {
            return self::defaultConfig();
        }

        try {
            $config = self::normalizeConfig($decoded, self::defaultConfig());
            self::storeCachedConfig($config, $fingerprint);

            return $config;
        } catch (Throwable $e) {
            return self::defaultConfig();
        }
    }

    /**
     * @param array<string, mixed> $input
     * @return RedirectDecisionConfig
     */
    public static function saveConfig(array $input): array
    {
        $config = self::normalizeConfig($input, self::loadConfig());
        $config['updated_at'] = gmdate(DATE_ATOM);
        $path = self::storagePath();
        $dir = dirname($path);

        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException('Failed to create the redirect dashboard storage directory.');
        }

        $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || file_put_contents($path, $json . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('Failed to save the redirect dashboard configuration.');
        }

        $mtime = (int) (@filemtime($path) ?: 0);
        $size = (int) (@filesize($path) ?: 0);
        self::storeCachedConfig($config, $mtime . ':' . $size);

        return $config;
    }

    /**
     * @param RedirectDecisionConfig $config
     * @return RedirectDecisionConfig
     */
    public static function resetCycle(array $config, ?int $now = null): array
    {
        $normalized = self::normalizeConfig($config, self::defaultConfig());
        $normalized['cycle_anchor_unix'] = self::normalizeTimestamp($now ?? time());
        $normalized['updated_at'] = gmdate(DATE_ATOM);

        return self::saveConfig($normalized);
    }

    /**
     * @param array<string, mixed> $input
     * @param RedirectDecisionConfig|null $base
     * @return RedirectDecisionConfig
     */
    public static function normalizeConfig(array $input, ?array $base = null): array
    {
        $config = $base ?? self::defaultConfig();

        $config['enabled'] = self::normalizeBoolean($input['enabled'] ?? $config['enabled']);
        $config['redirect_url'] = self::normalizeRedirectUrl($input['redirect_url'] ?? $config['redirect_url']);
        $config['allowed_countries'] = self::normalizeCountries($input['allowed_countries'] ?? $config['allowed_countries']);
        $config['cycle_anchor_unix'] = self::normalizeTimestamp($input['cycle_anchor_unix'] ?? $config['cycle_anchor_unix']);
        $config['filter_duration_seconds'] = self::normalizeDuration(
            $input['filter_duration_seconds'] ?? $config['filter_duration_seconds'],
            self::FILTER_DURATION_SECONDS
        );
        $config['normal_duration_seconds'] = self::normalizeDuration(
            $input['normal_duration_seconds'] ?? $config['normal_duration_seconds'],
            self::NORMAL_DURATION_SECONDS
        );
        $config['require_wap'] = self::normalizeBoolean($input['require_wap'] ?? $config['require_wap']);
        $config['require_no_vpn'] = self::normalizeBoolean($input['require_no_vpn'] ?? $config['require_no_vpn']);
        $updatedAt = $input['updated_at'] ?? $config['updated_at'];
        $config['updated_at'] = is_string($updatedAt) ? $updatedAt : gmdate(DATE_ATOM);

        return $config;
    }

    /**
     * @param RedirectDecisionConfig $config
     * @return RedirectDecisionWindow
     */
    public static function currentWindow(array $config, ?int $now = null): array
    {
        $normalized = self::normalizeConfig($config, self::defaultConfig());
        $filterDuration = $normalized['filter_duration_seconds'];
        $normalDuration = $normalized['normal_duration_seconds'];
        $cycleLength = $filterDuration + $normalDuration;
        $currentTime = self::normalizeTimestamp($now ?? time());

        // Clamp future anchors (clock skew / user input) to currentTime so the
        // cycle starts "now" instead of freezing at position 0 until time
        // catches up. cycleLength is guaranteed > 0 by normalizeDuration.
        $anchor = $normalized['cycle_anchor_unix'];
        if ($anchor > $currentTime) {
            $anchor = $currentTime;
        }
        $elapsed = $currentTime - $anchor;
        $position = $cycleLength > 0 ? ($elapsed % $cycleLength) : 0;

        $isFilterMode = $position < $filterDuration;
        $secondsUntilSwitch = $isFilterMode
            ? $filterDuration - $position
            : $cycleLength - $position;

        return [
            'mode' => $isFilterMode ? 'filter' : 'normal',
            'cycle_length_seconds' => $cycleLength,
            'cycle_position_seconds' => $position,
            'seconds_until_switch' => $secondsUntilSwitch,
            'next_switch_at_unix' => $currentTime + $secondsUntilSwitch,
        ];
    }

    /**
     * @param RedirectDecisionConfig $config
     * @param array<string, mixed> $context
     * @return RedirectDecisionResult
     */
    public static function evaluate(array $config, array $context, ?int $now = null): array
    {
        $normalizedConfig = self::normalizeConfig($config, self::defaultConfig());
        $window = self::currentWindow($normalizedConfig, $now);
        $normalizedContext = self::normalizeContext($context, $normalizedConfig['redirect_url']);
        $reasons = [];

        if ($normalizedContext['is_bot']) {
            $reasons[] = 'bot_meta_tag';

            return self::buildResult('meta_tag', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if (!$normalizedConfig['enabled']) {
            $reasons[] = 'system_off';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if ($window['mode'] !== 'filter') {
            $reasons[] = 'normal_window';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if ($normalizedConfig['require_wap'] && $normalizedContext['device'] !== 'wap') {
            $reasons[] = 'non_wap';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if ($normalizedContext['country'] === '') {
            $reasons[] = 'country_unknown';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if (
            $normalizedConfig['allowed_countries'] !== []
            && !in_array($normalizedContext['country'], $normalizedConfig['allowed_countries'], true)
        ) {
            $reasons[] = 'country_not_allowed';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if ($normalizedConfig['require_no_vpn'] && $normalizedContext['is_vpn']) {
            $reasons[] = 'vpn_detected';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        if ($normalizedContext['redirect_url'] === '') {
            $reasons[] = 'missing_redirect_url';

            return self::buildResult('normal', '', $normalizedConfig, $window, $normalizedContext, $reasons);
        }

        $reasons[] = 'redirect_url_match';

        return self::buildResult(
            'redirect_url',
            $normalizedContext['redirect_url'],
            $normalizedConfig,
            $window,
            $normalizedContext,
            $reasons
        );
    }

    /**
     * @param RedirectDecisionMeta $meta
     */
    public static function renderMetaTagPage(array $meta): string
    {
        $title = htmlspecialchars(trim(self::stringValue($meta['title'] ?? 'Shortlink Preview')), ENT_QUOTES, 'UTF-8');
        $description = htmlspecialchars(
            trim(self::stringValue($meta['description'] ?? 'Crawler receives the meta tag page.')),
            ENT_QUOTES,
            'UTF-8'
        );
        $image = htmlspecialchars(trim(self::stringValue($meta['image'] ?? '')), ENT_QUOTES, 'UTF-8');
        $canonical = htmlspecialchars(trim(self::stringValue($meta['canonical_url'] ?? '')), ENT_QUOTES, 'UTF-8');

        $imageTag = $image !== '' ? '<meta property="og:image" content="' . $image . '">' : '';
        $canonicalTag = $canonical !== '' ? '<meta property="og:url" content="' . $canonical . '">' : '';

        return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>' . $title .
            '</title><meta property="og:title" content="' . $title .
            '"><meta property="og:description" content="' . $description .
            '"><meta name="twitter:card" content="summary_large_image">' .
            $imageTag . $canonicalTag .
            '</head><body></body></html>';
    }

    /**
     * @param array<string, mixed> $context
     * @return RedirectDecisionContext
     */
    private static function normalizeContext(array $context, string $defaultRedirectUrl): array
    {
        $redirectUrl = self::normalizeRedirectUrl(self::stringValue($context['redirect_url'] ?? ''));
        if ($redirectUrl === '') {
            $redirectUrl = $defaultRedirectUrl;
        }

        return [
            'device' => strtolower(trim(self::stringValue($context['device'] ?? 'web'))) === 'wap' ? 'wap' : 'web',
            'country' => self::normalizeCountryCode(self::stringValue($context['country'] ?? '')),
            'is_vpn' => self::normalizeBoolean($context['is_vpn'] ?? false),
            'is_bot' => self::normalizeBoolean($context['is_bot'] ?? false),
            'redirect_url' => $redirectUrl,
        ];
    }

    /**
     * @param RedirectDecisionConfig $config
     * @param RedirectDecisionWindow $window
     * @param RedirectDecisionContext $context
     * @param list<string> $reasons
     * @return RedirectDecisionResult
     */
    private static function buildResult(
        string $decision,
        string $redirectUrl,
        array $config,
        array $window,
        array $context,
        array $reasons
    ): array {
        return [
            'decision' => $decision,
            'redirect_url' => $redirectUrl,
            'config' => $config,
            'window' => $window,
            'context' => $context,
            'reasons' => $reasons,
        ];
    }

    private static function normalizeDuration(mixed $value, int $default): int
    {
        if (is_int($value)) {
            $seconds = $value;
        } elseif (is_string($value) && preg_match('/^\d+$/', $value) === 1) {
            $seconds = (int) $value;
        } else {
            return $default;
        }

        if ($seconds < self::MIN_DURATION_SECONDS || $seconds > self::MAX_DURATION_SECONDS) {
            return $default;
        }

        return $seconds;
    }

    private static function normalizeRedirectUrl(mixed $value): string
    {
        if ($value instanceof Stringable || is_scalar($value)) {
            $url = trim((string) $value);
        } else {
            $url = '';
        }

        if ($url === '') {
            return '';
        }

        if (strlen($url) > 2048 || !filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('redirect_url is invalid.');
        }

        $schemeValue = parse_url($url, PHP_URL_SCHEME);
        $scheme = is_string($schemeValue) ? strtolower($schemeValue) : '';
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new InvalidArgumentException('redirect_url must use http or https.');
        }

        return $url;
    }

    /**
     * @return list<string>
     */
    private static function normalizeCountries(mixed $value): array
    {
        $items = [];
        if (is_string($value)) {
            $items = preg_split('/[\s,]+/', $value) ?: [];
        } elseif (is_array($value)) {
            $items = $value;
        }

        $normalized = [];
        foreach ($items as $item) {
            if (!$item instanceof Stringable && !is_scalar($item)) {
                continue;
            }

            $country = self::normalizeCountryCode((string) $item);
            if ($country === '') {
                continue;
            }

            $normalized[$country] = $country;
        }

        return array_values($normalized);
    }

    private static function normalizeCountryCode(string $value): string
    {
        $country = strtoupper(trim($value));
        if ($country === '') {
            return '';
        }

        if (!preg_match('/^[A-Z]{2}$/', $country)) {
            throw new InvalidArgumentException('Country codes must use a 2-letter ISO format.');
        }

        return $country;
    }

    private static function normalizeTimestamp(mixed $value): int
    {
        if (is_int($value)) {
            $timestamp = $value;
        } elseif (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            $timestamp = (int) $value;
        } else {
            return time();
        }

        if ($timestamp <= 0) {
            return time();
        }

        return $timestamp;
    }

    private static function normalizeBoolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value === 1;
        }

        if ($value instanceof Stringable || is_string($value) || is_float($value)) {
            $normalized = strtolower(trim((string) $value));
        } else {
            return false;
        }

        return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
    }

    private static function stringValue(mixed $value): string
    {
        if ($value instanceof Stringable || is_scalar($value)) {
            return (string) $value;
        }

        return '';
    }

    /**
     * @phpstan-assert-if-true array<string, mixed> $value
     */
    private static function isStringKeyArray(mixed $value): bool
    {
        if (!is_array($value)) {
            return false;
        }

        foreach (array_keys($value) as $key) {
            if (!is_string($key)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @phpstan-assert-if-true RedirectDecisionConfig $value
     */
    private static function isRedirectDecisionConfig(mixed $value): bool
    {
        if (!is_array($value)) {
            return false;
        }

        if (
            !is_bool($value['enabled'] ?? null)
            || !is_string($value['redirect_url'] ?? null)
            || !is_array($value['allowed_countries'] ?? null)
            || !is_int($value['cycle_anchor_unix'] ?? null)
            || !is_int($value['filter_duration_seconds'] ?? null)
            || !is_int($value['normal_duration_seconds'] ?? null)
            || !is_bool($value['require_wap'] ?? null)
            || !is_bool($value['require_no_vpn'] ?? null)
            || !is_string($value['updated_at'] ?? null)
        ) {
            return false;
        }

        foreach ($value['allowed_countries'] as $country) {
            if (!is_string($country)) {
                return false;
            }
        }

        return true;
    }
}
