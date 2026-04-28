<?php

declare(strict_types=1);

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$requestPath = parse_url($requestUri, PHP_URL_PATH);
$requestPath = is_string($requestPath) ? $requestPath : '/';

$documentRoot = __DIR__;
$filePath = realpath($documentRoot . $requestPath);
if ($filePath !== false && str_starts_with($filePath, $documentRoot) && is_file($filePath)) {
    return false;
}

if ($requestPath === '/' || $requestPath === '/index.php') {
    require $documentRoot . '/admin/index.php';
    return true;
}

if ($requestPath === '/handler.php') {
    require $documentRoot . '/admin/handler.php';
    return true;
}

if ($requestPath === '/ogimg.php') {
    require $documentRoot . '/redirect/ogimg.php';
    return true;
}

if ($requestPath === '/go.php') {
    // No-JS / meta-refresh fallback target from the redirect loader.
    require $documentRoot . '/redirect/go.php';
    return true;
}

if ($requestPath === '/metrics' || $requestPath === '/healthz') {
    require $documentRoot . '/metrics.php';
    return true;
}

if ($requestPath === '/redirect-engine') {
    require $documentRoot . '/admin/redirect-engine.php';
    return true;
}

if ($requestPath === '/postback') {
    require $documentRoot . '/redirect/recv.php';
    return true;
}

if ($requestPath === '/gen') {
    require $documentRoot . '/user/sl.php';
    return true;
}

if ($requestPath === '/privacy') {
    require $documentRoot . '/privacy.php';
    return true;
}

if ($requestPath === '/terms') {
    require $documentRoot . '/terms.php';
    return true;
}

if ($requestPath !== '/'
    && preg_match('/^\/([A-Za-z0-9_-]{1,30})$/', $requestPath, $matches) === 1
) {
    $_GET['s'] = $matches[1];
    $_REQUEST['s'] = $matches[1];
    require $documentRoot . '/redirect/go.php';
    return true;
}

return false;
