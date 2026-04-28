<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/bootstrap/runtime_compat.php';
require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

require_once __DIR__ . '/RedirectDecision.php';
require_once __DIR__ . '/Value/NetworkProfile.php';
require_once __DIR__ . '/Cache/NetworkProfileCacheRepositoryInterface.php';
require_once __DIR__ . '/Cache/NetworkProfileCacheRepository.php';
require_once __DIR__ . '/Cache/PdoNetworkProfileCacheRepository.php';
require_once __DIR__ . '/Audit/PdoDecisionAuditRepository.php';
require_once __DIR__ . '/Health/RedirectDecisionHealthEvaluator.php';
require_once __DIR__ . '/Provider/NetworkProfileProviderInterface.php';
require_once __DIR__ . '/Provider/TrustedHeaderAsnProfileProvider.php';
require_once __DIR__ . '/Provider/CloudflareHeaderProfileProvider.php';
require_once __DIR__ . '/Provider/GenericCountryHeaderProvider.php';
require_once __DIR__ . '/Provider/HeaderRiskProfileProvider.php';
require_once __DIR__ . '/Provider/GeoLite2CountryProvider.php';
require_once __DIR__ . '/Provider/IptoAsnProfileProvider.php';
require_once __DIR__ . '/NetworkProfileResolver.php';
require_once __DIR__ . '/NetworkProfileResolverFactory.php';
