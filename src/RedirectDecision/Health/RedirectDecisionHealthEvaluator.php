<?php

declare(strict_types=1);

namespace App\RedirectDecision\Health;

/**
 * @phpstan-type RedirectDecisionProviderState array{
 *     geolite2: array{active: bool},
 *     iptoasn: array{configured: bool, active: bool},
 *     persistent_cache: array{backend: string}
 * }
 * @phpstan-type RedirectDecisionHealthAlert array{
 *     severity: 'critical'|'warning',
 *     code: string,
 *     message: string
 * }
 * @phpstan-type RedirectDecisionHealthState array{
 *     healthy: bool,
 *     current_hour_count: int,
 *     previous_hour_count: int,
 *     alerts: list<RedirectDecisionHealthAlert>
 * }
 */
final class RedirectDecisionHealthEvaluator
{
    /**
     * @param RedirectDecisionProviderState $providerState
     * @return RedirectDecisionHealthState
     */
    public static function evaluate(array $providerState, int $currentHourCount, int $previousHourCount): array
    {
        $alerts = [];

        $geoLiteActive = !empty($providerState['geolite2']['active']);
        $iptoAsnConfigured = !empty($providerState['iptoasn']['configured']);
        $iptoAsnActive = !empty($providerState['iptoasn']['active']);
        $cacheBackend = trim($providerState['persistent_cache']['backend']);

        if (!$geoLiteActive) {
            $alerts[] = [
                'severity' => 'critical',
                'code' => 'provider_geolite2_down',
                'message' => 'GeoLite2 is inactive. Local country fallback is unavailable.',
            ];
        }

        if ($iptoAsnConfigured && !$iptoAsnActive) {
            $alerts[] = [
                'severity' => 'critical',
                'code' => 'provider_iptoasn_down',
                'message' => 'IPtoASN is configured, but the provider is inactive.',
            ];
        }

        if ($cacheBackend !== 'shared_db') {
            $alerts[] = [
                'severity' => 'warning',
                'code' => 'cache_not_shared',
                'message' => 'Persistent cache is not using the shared DB yet.',
            ];
        }

        if ($previousHourCount >= 50 && $currentHourCount < (int) floor($previousHourCount * 0.3)) {
            $alerts[] = [
                'severity' => 'warning',
                'code' => 'audit_volume_drop',
                'message' => 'Audit volume in the last hour dropped sharply compared with the previous hour.',
            ];
        }

        if ($currentHourCount === 0 && $previousHourCount > 0) {
            $alerts[] = [
                'severity' => 'critical',
                'code' => 'audit_volume_zero',
                'message' => 'Audit volume in the last hour is zero even though traffic existed in the previous hour.',
            ];
        }

        return [
            'healthy' => count($alerts) === 0,
            'current_hour_count' => $currentHourCount,
            'previous_hour_count' => $previousHourCount,
            'alerts' => $alerts,
        ];
    }
}
