<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(2);
}

$root = dirname(__DIR__);
$buildDir = $root . '/build';
if (!is_dir($buildDir) && !mkdir($buildDir, 0775, true) && !is_dir($buildDir)) {
    fwrite(STDERR, "Failed to create build directory.\n");
    exit(1);
}

$args     = $argv ?? [];
$force    = in_array('--force', $args, true);
$asFolder = in_array('--folder', $args, true);

if (!$asFolder && !class_exists('ZipArchive')) {
    fwrite(STDERR, "ZipArchive extension is not available. Pass --folder to build into a directory instead.\n");
    exit(2);
}

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

$baseName = 'notrackng-production-' . $date . ($suffix !== '' ? '-' . $suffix : '');
$fileName = $baseName . '.zip';
$target   = $buildDir . '/' . ($asFolder ? $baseName : $fileName);

if ($asFolder) {
    if (is_dir($target)) {
        // Wipe a stale folder build so re-runs are deterministic.
        $cleanup = static function (string $dir) use (&$cleanup): void {
            $items = @scandir($dir);
            if (!is_array($items)) {
                return;
            }
            foreach ($items as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $path = $dir . '/' . $entry;
                if (is_dir($path) && !is_link($path)) {
                    $cleanup($path);
                    @rmdir($path);
                } else {
                    @unlink($path);
                }
            }
        };
        $cleanup($target);
        @rmdir($target);
    }
    if (!@mkdir($target, 0755, true) && !is_dir($target)) {
        fwrite(STDERR, "Failed to create build folder: {$target}\n");
        exit(1);
    }
}

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

// .htaccess ships without the install.php deny block so the installer is
// accessible on a fresh deployment. The user must restore the block after
// installation completes (see deployment step 4 below).
$htaccessInstallBlock = '/\n?<FilesMatch\s+"[^"]*install\\\\\.php[^"]*">[\s\S]*?<\/FilesMatch>/';
$htaccessRaw  = (string) file_get_contents($root . '/.htaccess');
$htaccessClean = preg_replace($htaccessInstallBlock, '', $htaccessRaw) ?? $htaccessRaw;

// Defense-in-depth deny .htaccess dropped into sensitive subdirs.
// Apache's AllowOverride may differ between cPanel hosts, so the global
// .htaccess RewriteRule + per-directory deny gives us belt-and-suspenders.
$denyHtaccess = "Order allow,deny\nDeny from all\nRequire all denied\n";
$denyHtaccessTargets = [
    'data/.htaccess',
    'vendor/.htaccess',
    'ops/.htaccess',
    'src/.htaccess',
    'module/.htaccess',
    'bootstrap/.htaccess',
    'tests/.htaccess',
];

$runtimeDirs = [
    'data/sessions',
    'data/ogimg_cache',
    'data/postback_queue',
    'data/postback_queue_spill',
];

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

$addedFiles = 0;

if ($asFolder) {
    // ── Folder mode ────────────────────────────────────────────────
    $writeFile = static function (string $relativePath, string $contents) use ($target): bool {
        $abs = $target . '/' . ltrim($relativePath, '/');
        $dir = dirname($abs);
        if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }
        return file_put_contents($abs, $contents) !== false;
    };
    $copyFile = static function (string $absSrc, string $relativePath) use ($target): bool {
        $abs = $target . '/' . ltrim($relativePath, '/');
        $dir = dirname($abs);
        if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }
        return @copy($absSrc, $abs);
    };
    $ensureDir = static function (string $relativePath) use ($target): void {
        $abs = $target . '/' . ltrim($relativePath, '/');
        if (!is_dir($abs)) {
            @mkdir($abs, 0755, true);
        }
    };

    $writeFile('.htaccess', $htaccessClean);

    foreach ($iterator as $item) {
        if (!$item instanceof SplFileInfo) {
            continue;
        }
        $fullPath = $item->getPathname();
        $relativePath = $normalize(substr($fullPath, strlen($root) + 1));
        if ($relativePath === '' || $relativePath === '.htaccess' || $isExcluded($relativePath)) {
            continue;
        }
        if ($item->isDir()) {
            $ensureDir($relativePath);
            continue;
        }
        if ($copyFile($fullPath, $relativePath)) {
            $addedFiles++;
        }
    }

    foreach ($runtimeDirs as $dir) {
        $ensureDir($dir);
    }
    foreach ($denyHtaccessTargets as $relPath) {
        $writeFile($relPath, $denyHtaccess);
    }
    // Drop a deployment guide alongside the build for cPanel operators.
    $writeFile('DEPLOY-CPANEL.md', tp_render_deploy_cpanel_guide($baseName));
} else {
    // ── ZIP mode (legacy default) ──────────────────────────────────
    $zip = new ZipArchive();
    if ($zip->open($target, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        fwrite(STDERR, "Failed to open zip archive for writing.\n");
        exit(1);
    }
    $zip->addFromString('.htaccess', $htaccessClean);

    foreach ($iterator as $item) {
        if (!$item instanceof SplFileInfo) {
            continue;
        }
        $fullPath = $item->getPathname();
        $relativePath = $normalize(substr($fullPath, strlen($root) + 1));
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

    foreach ($runtimeDirs as $dir) {
        $zip->addEmptyDir($dir);
    }
    foreach ($denyHtaccessTargets as $relPath) {
        $zip->addFromString($relPath, $denyHtaccess);
    }
    $zip->addFromString('DEPLOY-CPANEL.md', tp_render_deploy_cpanel_guide($baseName));

    $zip->close();
}

fwrite(STDOUT, 'Build complete: ' . $target . ' (' . $addedFiles . " file(s)).\n");
fwrite(STDOUT, 'Runtime placeholder dirs added: ' . implode(', ', $runtimeDirs) . "\n");
fwrite(STDOUT, 'Per-directory deny .htaccess dropped into: ' . implode(', ', array_map(static fn (string $p): string => dirname($p), $denyHtaccessTargets)) . "\n");
fwrite(STDOUT, "\n");
fwrite(STDOUT, $asFolder
    ? "Folder is ready to upload. See DEPLOY-CPANEL.md inside the folder for the full checklist.\n"
    : "ZIP is ready to upload. Extract on the server then follow DEPLOY-CPANEL.md inside the archive.\n"
);
exit(0);

/**
 * Builds the cPanel deployment guide that ships inside every production build.
 */
function tp_render_deploy_cpanel_guide(string $buildName): string
{
    $phpVersion = PHP_VERSION;
    return <<<MARKDOWN
# Deployment Guide — {$buildName} (cPanel Shared Hosting)

This build is a self-contained drop-in for cPanel-style shared hosts. It
ships with vendor/ pre-installed (no Composer required on the server),
runtime placeholder directories, defense-in-depth per-directory `.htaccess`
deny files, and the installer wizard enabled.

## 1. Upload

Pick one of:

- **File Manager**: zip the folder locally → upload `{$buildName}.zip`
  → "Extract" inside `public_html/` (or your subdomain document root).
- **rsync / SFTP**: sync the folder contents directly into the document root,
  preserving file permissions.

The result on the server should look like:

```
public_html/
├── .htaccess          (~147 KB; routing + hotlink protection)
├── .user.ini          (shared-host PHP config)
├── admin/
├── assets/
├── bootstrap/
├── data/              (writable; runtime state)
├── module/
├── ops/
├── redirect/
├── src/
├── user/
├── vendor/            (pre-installed; do NOT delete)
├── install.php        (delete after step 4)
├── router.php         (only used by `php -S`; harmless on cPanel)
├── DEPLOY-CPANEL.md   (this file)
└── …
```

## 2. File system permissions

```
chmod 755 data/ data/sessions/ data/ogimg_cache/ data/postback_queue/ data/postback_queue_spill/
chmod 644 .htaccess .user.ini
```

If your host enforces `0644` for PHP files (most do), no further chmod is
required. The PHP user must own the writable dirs (usually automatic on
cPanel).

## 3. Run the installer

Open `https://your-domain.example/install.php` and complete the wizard:

1. **Database** — provide DB host / user / password / database name.
2. **Admin user** — pick a strong password (the installer hashes it via
   bcrypt cost 10 before storing).
3. **cPanel + Cloudflare** — paste your **freshly rotated** API tokens.
   The form defaults are intentionally empty in this build.
4. **MaxMind / Affiliate Network keys** — also empty by default; paste
   your own.
5. **Generate** — the installer writes `.env`, `data/config.json`,
   `data/sl_data.sqlite` (if no MySQL), and creates schema.

## 4. Lock down the installer

After the wizard reports success, **either** delete `install.php`:

```
rm install.php
```

**or** add this block to the very top of `.htaccess` (the build ships with
this block already commented-out style — you must add it):

```apache
<FilesMatch "^install\.php\$">
    Require all denied
</FilesMatch>
```

Re-running the wizard from this point requires removing the block again.

## 5. Set the security knobs (manual, post-install)

Edit `.env` (created in step 3) and add these lines if missing:

```dotenv
# Super-admin login (fail-closed when empty)
# Generate with: php -r 'echo password_hash("PASSWORD-BARU", PASSWORD_BCRYPT) . PHP_EOL;'
SUPER_ADMIN_HASH='\$2y\$10\$REPLACE_WITH_BCRYPT_HASH'

# Postback signature secret (enables HMAC verification on /postback)
POSTBACK_SECRET='choose-a-32-byte-random-string'

# App-token for handler.php API calls without session (optional)
APP_TOKEN='choose-a-32-byte-random-string'
```

Then `chmod 600 .env` and verify only the PHP user can read it.

## 6. Cron jobs

In cPanel → Cron Jobs, add:

| Frequency | Command |
|-----------|---------|
| Daily 03:00 | `/usr/local/bin/php /home/USER/public_html/ops/update_cf_ips.php >> /home/USER/logs/cf_ips.log 2>&1` |
| Every 5 min | `/usr/local/bin/php /home/USER/public_html/ops/process_postback_queue.php >> /home/USER/logs/postback.log 2>&1` |
| Weekly Sun 04:00 | `/usr/local/bin/php /home/USER/public_html/ops/update_geolite2.php >> /home/USER/logs/geolite.log 2>&1` |
| Monthly 1st 02:00 | `/usr/local/bin/php /home/USER/public_html/ops/prune_decision_audit.php >> /home/USER/logs/prune.log 2>&1` |

(Replace `/usr/local/bin/php` with the absolute PHP 8.3 binary your host
exposes — check via `which php` over SSH or via cPanel "Select PHP Version".)

## 7. Cloudflare in front (recommended)

This build trusts `CF-Connecting-IP` / `X-Forwarded-For` **only** when the
peer connecting to the origin is a Cloudflare edge IP (verified against
`data/cf_ips.json`). Daily cron in step 6 keeps this list fresh.

For maximum protection, also restrict origin firewall (cPanel → Security
→ IP Blocker, or via host support) so only Cloudflare ranges can reach
your server on ports 80/443.

## 8. Smoke test

```bash
curl -I https://your-domain.example/                       # 200 + CSP header
curl -I https://your-domain.example/healthz                # 200
curl -I https://your-domain.example/install.php            # 403 after step 4
curl -I https://your-domain.example/.env                   # 403
curl -I https://your-domain.example/vendor/autoload.php    # 403
curl -I https://your-domain.example/data/cf_ips.json       # 403
curl -I https://your-domain.example/composer.json          # 403
```

## 9. Rollback

This build does not run any destructive migration on existing installs.
To rollback, restore the previous folder and re-point `.env` /
`data/config.json` (those live outside the build folder once installed).

---

Build manifest: `{$buildName}`
Generated: PHP {$phpVersion}
MARKDOWN;
}
