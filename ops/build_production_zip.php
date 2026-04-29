<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(2);
}

if (!class_exists('ZipArchive')) {
    fwrite(STDERR, "ZipArchive extension is not available.\n");
    exit(2);
}

$root = dirname(__DIR__);
$buildDir = $root . '/build';
if (!is_dir($buildDir) && !mkdir($buildDir, 0775, true) && !is_dir($buildDir)) {
    fwrite(STDERR, "Failed to create build directory.\n");
    exit(1);
}

$args  = $argv ?? [];
$force = in_array('--force', $args, true);

// Abort if vendor/ still contains dev dependencies unless --force is passed.
// Run: composer install --no-dev --optimize-autoloader --classmap-authoritative
if (!$force && is_dir($root . '/vendor/phpunit')) {
    fwrite(STDERR, "ERROR: vendor/ contains dev dependencies (vendor/phpunit found).\n");
    fwrite(STDERR, "Run: composer install --no-dev --optimize-autoloader --classmap-authoritative\n");
    fwrite(STDERR, "Or pass --force to skip this check.\n");
    exit(1);
}

$date   = gmdate('Ymd');
$suffix = '';
foreach ($args as $arg) {
    if (str_starts_with($arg, '--suffix=')) {
        $suffix = preg_replace('/[^A-Za-z0-9._-]/', '', substr($arg, 9)) ?? '';
    }
}

$fileName = 'notrackng-production-' . $date . ($suffix !== '' ? '-' . $suffix : '') . '.zip';
$target = $buildDir . '/' . $fileName;

$excludePaths = [
    '.env',
    '.git',
    '.gitignore',
    '.github',
    '.codex',
    '.sixth',
    '.claude',
    '.agents',
    '.gemini',
    '.termdock',
    '.idea',
    '.vscode',
    '.cursor',
    '.phpunit.cache',
    '.phpunit.result.cache',
    'build',
    'tests',
    'node_modules',
    'coverage',
    'data/config.json',
    'data/sessions',
    'data/sl_data.sqlite',
    'data/ogimg_cache',
    'data/postback_queue',
    'data/postback_queue_spill',
    'data/phpstan',
    '.php-cs-fixer.cache',
    '.php-cs-fixer.dist.php',
    'phpcs.xml.dist',
    'phpstan.neon.dist',
    'phpunit.xml.dist',
    'CLAUDE.md',
    'AGENTS.md',
    'composer.lock',
    'custom-instructions.md',
    'php-production-automation',
    'php-prod-audit-report.j',
    'php-prod-audit-report.json',
];

$excludeExtensions = [
    'log',
    'pid',
];

$normalize = static function (string $path): string {
    return str_replace('\\', '/', $path);
};

$isExcluded = static function (string $relativePath) use ($excludePaths, $excludeExtensions, $normalize): bool {
    $relativePath = ltrim($normalize($relativePath), '/');
    foreach ($excludePaths as $excluded) {
        $excluded = ltrim($normalize($excluded), '/');
        if ($relativePath === $excluded) {
            return true;
        }

        if ($excluded !== '' && str_starts_with($relativePath, $excluded . '/')) {
            return true;
        }
    }

    $extension = strtolower(pathinfo($relativePath, PATHINFO_EXTENSION));
    if ($extension !== '' && in_array($extension, $excludeExtensions, true)) {
        return true;
    }

    return false;
};

$zip = new ZipArchive();
if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "Failed to open zip archive for writing.\n");
    exit(1);
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

// .htaccess ships without the install.php deny block so the installer is
// accessible on a fresh deployment. The user must restore the block after
// installation completes (see deployment step 4 below).
$htaccessInstallBlock = '/\n?<FilesMatch\s+"[^"]*install\\\\\.php[^"]*">[\s\S]*?<\/FilesMatch>/';
$htaccessRaw  = (string) file_get_contents($root . '/.htaccess');
$htaccessClean = preg_replace($htaccessInstallBlock, '', $htaccessRaw) ?? $htaccessRaw;
$zip->addFromString('.htaccess', $htaccessClean);

$addedFiles = 0;
foreach ($iterator as $item) {
    if (!$item instanceof SplFileInfo) {
        continue;
    }

    $fullPath = $item->getPathname();
    $relativePath = $normalize(substr($fullPath, strlen($root) + 1));
    // .htaccess already added above with install.php block stripped.
    if ($relativePath === '' || $relativePath === '.htaccess' || $isExcluded($relativePath)) {
        continue;
    }

    if ($item->isDir()) {
        $zip->addEmptyDir($relativePath);
        continue;
    }

    if ($zip->addFile($fullPath, $relativePath)) {
        $addedFiles++;
    }
}

// Ensure required runtime directories exist after extraction.
// These are excluded from file enumeration but must be present on the server.
$runtimeDirs = [
    'data/sessions',
    'data/ogimg_cache',
    'data/postback_queue',
    'data/postback_queue_spill',
];
foreach ($runtimeDirs as $dir) {
    $zip->addEmptyDir($dir);
}

$zip->close();

fwrite(STDOUT, 'Build complete: ' . $target . ' (' . $addedFiles . " file(s)).\n");
fwrite(STDOUT, 'Runtime placeholder dirs added: ' . implode(', ', $runtimeDirs) . "\n");
fwrite(STDOUT, "\n");
fwrite(STDOUT, "Deployment steps (cPanel shared hosting):\n");
fwrite(STDOUT, "  1. Upload ZIP to server and extract into public_html/ (or subdirectory).\n");
fwrite(STDOUT, "  2. chmod 755 data/ data/sessions/ data/ogimg_cache/ data/postback_queue/ data/postback_queue_spill/\n");
fwrite(STDOUT, "  3. Open https://yourdomain.com/install.php in browser and complete the wizard.\n");
fwrite(STDOUT, "  4. IMPORTANT: After installation, add to .htaccess to lock install.php:\n");
fwrite(STDOUT, "       <FilesMatch \"^install\\.php\$\">\n");
fwrite(STDOUT, "           Order allow,deny\n");
fwrite(STDOUT, "           Deny from all\n");
fwrite(STDOUT, "       </FilesMatch>\n");
fwrite(STDOUT, "  5. Run: php ops/ensure_mysql_hot_indexes.php\n");
exit(0);
