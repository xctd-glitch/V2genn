<?php

declare(strict_types=1);

use App\RedirectDecision\Audit\PdoDecisionAuditRepository;
use App\RedirectDecision\Health\RedirectDecisionHealthEvaluator;

require_once dirname(__DIR__) . '/bootstrap/runtime_compat.php';
require_once dirname(__DIR__) . '/src/RedirectDecision/bootstrap.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function alertExit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

function alertDb(): ?PDO
{
    $host = trim((string) getenv('DB_HOST'));
    $user = trim((string) getenv('DB_USER'));
    $pass = trim((string) getenv('DB_PASS'));
    $name = trim((string) getenv('DB_NAME'));

    if ($user !== '' && $name !== '') {
        try {
            return new PDO(
                'mysql:host=' . ($host !== '' ? $host : 'localhost') . ';dbname=' . $name . ';charset=utf8mb4',
                $user,
                $pass,
                tp_mysql_pdo_options()
            );
        } catch (Throwable $e) {
            return null;
        }
    }

    $sqlitePath = dirname(__DIR__) . '/data/sl_data.sqlite';
    if (is_file($sqlitePath)) {
        try {
            return new PDO(
                'sqlite:' . $sqlitePath,
                null,
                null,
                tp_sqlite_pdo_options()
            );
        } catch (Throwable $e) {
            return null;
        }
    }

    return null;
}

/**
 * @return array{
 *     geolite2: array{active: bool},
 *     iptoasn: array{configured: bool, active: bool},
 *     persistent_cache: array{backend: string}
 * }
 */
function alertProviderState(): array
{
    $geoLitePath = trim((string) getenv('GEOLITE2_COUNTRY_DB'));
    if ($geoLitePath === '') {
        $cpanelUser = trim((string) getenv('CPANEL_USER'));
        $baseDir    = trim((string) getenv('BASE_DIR'));
        if ($cpanelUser !== '' && $baseDir !== '') {
            $geoLitePath = '/home/' . $cpanelUser . '/' . $baseDir . '/data/geoip/GeoLite2-Country.mmdb';
        } else {
            $geoLitePath = dirname(__DIR__) . '/data/geoip/GeoLite2-Country.mmdb';
        }
    }

    $iptoAsnEndpoint = trim((string) getenv('IPTOASN_ENDPOINT'));

    return [
        'geolite2' => [
            'active' => is_file($geoLitePath) && class_exists('MaxMind\\Db\\Reader'),
        ],
        'iptoasn' => [
            'configured' => $iptoAsnEndpoint !== '',
            'active' => $iptoAsnEndpoint !== '' && function_exists('curl_init'),
        ],
        'persistent_cache' => [
            'backend' => alertDb() instanceof PDO ? 'shared_db' : 'sqlite_local',
        ],
    ];
}

$pdo = alertDb();
if (!$pdo instanceof PDO) {
    alertExit('DB not available for audit/alert.', 2);
}

$repository = new PdoDecisionAuditRepository($pdo);
$currentHourStart = (int) floor(time() / 3600) * 3600;
$previousHourStart = $currentHourStart - 3600;
$currentHourCount = $repository->fetchTotalCountBetween($currentHourStart, $currentHourStart + 3600);
$previousHourCount = $repository->fetchTotalCountBetween($previousHourStart, $currentHourStart);
$health = RedirectDecisionHealthEvaluator::evaluate(alertProviderState(), $currentHourCount, $previousHourCount);

if (!empty($health['healthy'])) {
    alertExit(
        'HEALTHY current_hour=' . $currentHourCount . ' previous_hour=' . $previousHourCount,
        0
    );
}

$messages = array_map(
    static function (array $alert): string {
        return $alert['code'];
    },
    is_array($health['alerts'] ?? null) ? $health['alerts'] : []
);

alertExit(
    'ALERT current_hour=' . $currentHourCount . ' previous_hour=' . $previousHourCount . ' alerts=' . implode(',', $messages),
    1
);
