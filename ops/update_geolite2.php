<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/RedirectDecision/bootstrap.php';

tp_load_env_file(dirname(__DIR__) . '/.env');

function updateGeoLite2Exit(string $message, int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, $message . PHP_EOL);
    exit($code);
}

function envString(string $key): string
{
    return trim((string) getenv($key));
}

function downloadGeoLite2Archive(string $url, string $destinationPath): void
{
    if (!function_exists('curl_init')) {
        throw new RuntimeException('cURL extension is not available to download GeoLite2.');
    }

    $handle = fopen($destinationPath, 'wb');
    if ($handle === false) {
        throw new RuntimeException('Failed to open temporary GeoLite2 file.');
    }

    $curl = curl_init($url);
    if ($curl === false) {
        fclose($handle);
        throw new RuntimeException('Failed to initialize cURL for GeoLite2.');
    }

    curl_setopt_array($curl, [
        CURLOPT_FILE => $handle,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FAILONERROR => true,
        CURLOPT_USERAGENT => 'notrackng-geolite2-updater/1.0',
    ]);

    try {
        if (curl_exec($curl) === false) {
            throw new RuntimeException('GeoLite2 download failed: ' . curl_error($curl));
        }
    } catch (Throwable $e) {
        fclose($handle);
        throw $e;
    }

    fclose($handle);
}

function extractGeoLite2Mmdb(string $archivePath, string $extractDir): string
{
    $tarPath = preg_replace('/\.gz$/', '', $archivePath);
    if (!is_string($tarPath) || $tarPath === '') {
        throw new RuntimeException('GeoLite2 tar path is invalid.');
    }

    if (is_file($tarPath) && !unlink($tarPath)) {
        throw new RuntimeException('Failed to clean up old GeoLite2 tar file.');
    }

    try {
        $archive = new PharData($archivePath);
        $archive->decompress();
        $tar = new PharData($tarPath);
        $tar->extractTo($extractDir, null, true);
    } catch (Throwable $e) {
        throw new RuntimeException('GeoLite2 extraction failed: ' . $e->getMessage(), 0, $e);
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($extractDir, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if (!$file instanceof SplFileInfo) {
            continue;
        }

        if (strtolower($file->getFilename()) === 'geolite2-country.mmdb') {
            return $file->getPathname();
        }
    }

    throw new RuntimeException('GeoLite2-Country.mmdb not found in archive.');
}

function recursivelyDeleteDirectory(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        if (!$item instanceof SplFileInfo) {
            continue;
        }

        if ($item->isDir()) {
            rmdir($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }

    rmdir($path);
}

$licenseKey = envString('MAXMIND_LICENSE_KEY');
$downloadUrl = envString('MAXMIND_GEOLITE2_URL');
$targetPath = envString('GEOLITE2_COUNTRY_DB');

if ($targetPath === '') {
    $cpanelUser = envString('CPANEL_USER');
    $baseDir    = envString('BASE_DIR');
    if ($cpanelUser !== '' && $baseDir !== '') {
        $targetPath = '/home/' . $cpanelUser . '/' . $baseDir . '/data/geoip/GeoLite2-Country.mmdb';
    } else {
        $targetPath = dirname(__DIR__) . '/data/geoip/GeoLite2-Country.mmdb';
    }
}

if ($downloadUrl === '') {
    if ($licenseKey === '') {
        updateGeoLite2Exit('MAXMIND_LICENSE_KEY is not set.', 2);
    }

    $downloadUrl = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key='
        . rawurlencode($licenseKey)
        . '&suffix=tar.gz';
}

$targetDirectory = dirname($targetPath);
if (!is_dir($targetDirectory) && !mkdir($targetDirectory, 0775, true) && !is_dir($targetDirectory)) {
    updateGeoLite2Exit('Failed to create GeoLite2 target directory.', 3);
}

$workDirectory = $targetDirectory . '/.geolite2-update';
$archivePath = $workDirectory . '/GeoLite2-Country.tar.gz';

if (is_dir($workDirectory)) {
    recursivelyDeleteDirectory($workDirectory);
}

if (!mkdir($workDirectory, 0775, true) && !is_dir($workDirectory)) {
    updateGeoLite2Exit('Failed to create GeoLite2 working directory.', 4);
}

try {
    downloadGeoLite2Archive($downloadUrl, $archivePath);
    $mmdbPath = extractGeoLite2Mmdb($archivePath, $workDirectory);
    if (!copy($mmdbPath, $targetPath)) {
        throw new RuntimeException('Failed to copy MMDB file to target.');
    }

    chmod($targetPath, 0640);
    recursivelyDeleteDirectory($workDirectory);
} catch (Throwable $e) {
    recursivelyDeleteDirectory($workDirectory);
    updateGeoLite2Exit($e->getMessage(), 1);
}

updateGeoLite2Exit('GeoLite2 successfully updated to ' . $targetPath, 0);
