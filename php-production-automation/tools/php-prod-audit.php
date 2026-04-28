<?php

declare(strict_types=1);

/**
 * Read-only PHP production inventory/audit helper.
 *
 * Usage:
 *   php tools/php-prod-audit.php --root=. --format=json
 *   php tools/php-prod-audit.php --root=. --format=text
 *
 * This script does not modify or delete files.
 */

final class PhpProdAudit
{
    private string $root;
    private string $format;

    /** @var array<string, int> */
    private array $extensionCounts = [];

    /** @var array<int, array{path:string,size:int}> */
    private array $largestFiles = [];

    /** @var array<int, array{path:string,type:string,evidence:string}> */
    private array $findings = [];

    /** @var array<int, string> */
    private array $phpFiles = [];

    /** @var array<int, string> */
    private array $entrypoints = [];

    /** @var array<int, string> */
    private array $composerFiles = [];

    /** @var array<int, string> */
    private array $sqlFiles = [];

    /** @var array<int, string> */
    private array $serverConfigFiles = [];

    /** @var array<int, string> */
    private array $riskyPublicFiles = [];

    public function __construct(string $root, string $format)
    {
        $realRoot = realpath($root);
        if ($realRoot === false || !is_dir($realRoot)) {
            throw new InvalidArgumentException('Invalid --root path.');
        }

        $this->root = rtrim($realRoot, DIRECTORY_SEPARATOR);
        $this->format = $format === 'text' ? 'text' : 'json';
    }

    public function run(): int
    {
        $this->scan();

        $report = [
            'generated_at' => gmdate('c'),
            'root' => $this->root,
            'php_version' => PHP_VERSION,
            'summary' => [
                'php_files' => count($this->phpFiles),
                'entrypoints' => count($this->entrypoints),
                'composer_files' => count($this->composerFiles),
                'sql_files' => count($this->sqlFiles),
                'server_config_files' => count($this->serverConfigFiles),
                'risky_public_files' => count($this->riskyPublicFiles),
                'findings' => count($this->findings),
            ],
            'extension_counts' => $this->extensionCounts,
            'entrypoints' => $this->entrypoints,
            'composer_files' => $this->composerFiles,
            'sql_files' => $this->sqlFiles,
            'server_config_files' => $this->serverConfigFiles,
            'risky_public_files' => $this->riskyPublicFiles,
            'largest_files' => $this->largestFiles,
            'findings' => $this->findings,
        ];

        if ($this->format === 'text') {
            $this->printText($report);
            return 0;
        }

        echo json_encode(
            $report,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        ) . PHP_EOL;

        return 0;
    }

    private function scan(): void
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator(
                    $this->root,
                    FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
                ),
                function (SplFileInfo $file): bool {
                    return $this->shouldInclude($file);
                }
            )
        );

        foreach ($iterator as $file) {
            if (!$file instanceof SplFileInfo || !$file->isFile()) {
                continue;
            }

            $path = $file->getPathname();
            $relativePath = $this->relative($path);
            $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
            $basename = strtolower($file->getBasename());

            if (!isset($this->extensionCounts[$extension])) {
                $this->extensionCounts[$extension] = 0;
            }
            $this->extensionCounts[$extension]++;

            $this->trackLargest($relativePath, $file->getSize());

            if ($extension === 'php') {
                $this->phpFiles[] = $relativePath;
                $this->analyzePhpFile($path, $relativePath, $basename);
            }

            if ($basename === 'composer.json' || $basename === 'composer.lock') {
                $this->composerFiles[] = $relativePath;
            }

            if ($extension === 'sql') {
                $this->sqlFiles[] = $relativePath;
            }

            if (
                $basename === '.htaccess'
                || str_contains($basename, 'nginx')
                || str_contains($basename, 'apache')
                || str_contains($basename, 'vhost')
            ) {
                $this->serverConfigFiles[] = $relativePath;
            }

            if ($this->isRiskyPublicFile($basename, $extension)) {
                $this->riskyPublicFiles[] = $relativePath;
                $this->addFinding(
                    $relativePath,
                    'risky-public-file',
                    'Backup/archive/dump/log/config-like file may be dangerous if web-accessible.'
                );
            }
        }

        sort($this->phpFiles);
        sort($this->entrypoints);
        sort($this->composerFiles);
        sort($this->sqlFiles);
        sort($this->serverConfigFiles);
        sort($this->riskyPublicFiles);
        arsort($this->extensionCounts);
    }

    private function shouldInclude(SplFileInfo $file): bool
    {
        $name = $file->getFilename();

        if ($file->isDir()) {
            $skipDirs = [
                '.git',
                '.idea',
                '.vscode',
                'vendor',
                'node_modules',
                'storage/cache',
                'cache',
                'tmp',
                'temp',
            ];

            foreach ($skipDirs as $skipDir) {
                if ($name === $skipDir) {
                    return false;
                }
            }
        }

        return true;
    }

    private function analyzePhpFile(string $path, string $relativePath, string $basename): void
    {
        if ($basename === 'index.php' || $basename === 'admin.php' || $basename === 'login.php' || $basename === 'api.php') {
            $this->entrypoints[] = $relativePath;
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            $this->addFinding($relativePath, 'read-error', 'Unable to read PHP file.');
            return;
        }

        $this->detectPattern($content, $relativePath, 'raw-superglobal', '/\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\s*\\[/i', 'Direct superglobal access found. Verify validation and context escaping.');
        $this->detectPattern($content, $relativePath, 'mysqli-usage', '/\\bmysqli_(query|multi_query|real_query|connect)\\s*\\(/i', 'mysqli usage found. Prefer PDO for refactored database code.');
        $this->detectPattern($content, $relativePath, 'possible-sql-concat', '/\\b(SELECT|INSERT|UPDATE|DELETE)\\b[^;\\n]*(\\.\\s*\\$|\\$\\w+\\s*\\.)/i', 'Possible SQL string concatenation. Verify prepared statements.');
        $this->detectPattern($content, $relativePath, 'multi-query', '/\\bmulti_query\\s*\\(/i', 'Multi-query execution found. Verify it is not request-controlled and disable multi statements in PDO.');
        $this->detectPattern($content, $relativePath, 'eval-like', '/\\b(eval|assert|create_function)\\s*\\(/i', 'Dynamic code execution found. Treat as high-risk.');
        $this->detectPattern($content, $relativePath, 'shell-exec', '/\\b(shell_exec|exec|system|passthru|proc_open|popen)\\s*\\(/i', 'Shell execution found. Verify input is not request-controlled.');
        $this->detectPattern($content, $relativePath, 'unsafe-include', '/\\b(include|include_once|require|require_once)\\s*\\(?\\s*\\$_(GET|POST|REQUEST|COOKIE)/i', 'Include/require from request input found. Block path traversal/RFI risk.');
        $this->detectPattern($content, $relativePath, 'possible-open-redirect', '/header\\s*\\(\\s*[\\\'"]Location\\s*:\\s*[\\\'"]\\s*\\./i', 'Dynamic Location header found. Verify redirect allowlist.');
        $this->detectPattern($content, $relativePath, 'session-start', '/\\bsession_start\\s*\\(/i', 'Session start found. Verify it is not used unnecessarily on hot stateless endpoints.');
        $this->detectPattern($content, $relativePath, 'unescaped-echo', '/\\becho\\s+\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[/i', 'Potential unescaped direct output from request input.');
        $this->detectPattern($content, $relativePath, 'missing-strict-types', '/^\\s*<\\?php(?!\\s+declare\\(strict_types=1\\);)/', 'PHP file may be missing declare(strict_types=1). Apply only when safe.');
        $this->detectPattern($content, $relativePath, 'throwable-name', '/catch\\s*\\(\\s*Throwable\\s+\\$(?!e\\b)\\w+\\s*\\)/', 'Throwable catch variable is not `$e`.');
        $this->detectPattern($content, $relativePath, 'arrow-function', '/\\bfn\\s*\\(/', 'PHP arrow function found. Project preference says avoid `fn()`.');
    }

    private function detectPattern(
        string $content,
        string $relativePath,
        string $type,
        string $pattern,
        string $evidence
    ): void {
        if (preg_match($pattern, $content) === 1) {
            $this->addFinding($relativePath, $type, $evidence);
        }
    }

    private function isRiskyPublicFile(string $basename, string $extension): bool
    {
        $riskyExtensions = [
            'bak',
            'backup',
            'old',
            'orig',
            'save',
            'sql',
            'sqlite',
            'db',
            'log',
            'zip',
            'tar',
            'gz',
            'rar',
            '7z',
            'env',
            'pem',
            'key',
        ];

        if (in_array($extension, $riskyExtensions, true)) {
            return true;
        }

        $riskyNames = [
            '.env',
            '.env.local',
            'config.php.bak',
            'database.php.bak',
            'backup.sql',
            'dump.sql',
        ];

        return in_array($basename, $riskyNames, true);
    }

    private function trackLargest(string $relativePath, int $size): void
    {
        $this->largestFiles[] = [
            'path' => $relativePath,
            'size' => $size,
        ];

        usort(
            $this->largestFiles,
            function (array $a, array $b): int {
                return $b['size'] <=> $a['size'];
            }
        );

        if (count($this->largestFiles) > 20) {
            array_pop($this->largestFiles);
        }
    }

    private function addFinding(string $path, string $type, string $evidence): void
    {
        $this->findings[] = [
            'path' => $path,
            'type' => $type,
            'evidence' => $evidence,
        ];
    }

    private function relative(string $path): string
    {
        $relative = substr($path, strlen($this->root) + 1);
        return str_replace(DIRECTORY_SEPARATOR, '/', $relative);
    }

    /**
     * @param array<string, mixed> $report
     */
    private function printText(array $report): void
    {
        echo 'PHP Production Audit Report' . PHP_EOL;
        echo 'Generated: ' . $report['generated_at'] . PHP_EOL;
        echo 'Root: ' . $report['root'] . PHP_EOL;
        echo 'PHP: ' . $report['php_version'] . PHP_EOL;
        echo PHP_EOL;

        echo 'Summary' . PHP_EOL;
        foreach ($report['summary'] as $key => $value) {
            echo '- ' . $key . ': ' . (string) $value . PHP_EOL;
        }
        echo PHP_EOL;

        echo 'Findings' . PHP_EOL;
        foreach ($this->findings as $finding) {
            echo '- [' . $finding['type'] . '] ' . $finding['path'] . ' — ' . $finding['evidence'] . PHP_EOL;
        }
    }
}

/**
 * @return array{root:string,format:string}
 */
function parseArguments(array $argv): array
{
    $root = '.';
    $format = 'json';

    foreach ($argv as $arg) {
        if (str_starts_with($arg, '--root=')) {
            $root = substr($arg, 7);
            continue;
        }

        if (str_starts_with($arg, '--format=')) {
            $format = substr($arg, 9);
            continue;
        }
    }

    return [
        'root' => $root,
        'format' => $format,
    ];
}

try {
    $options = parseArguments($argv);
    $audit = new PhpProdAudit($options['root'], $options['format']);
    exit($audit->run());
} catch (Throwable $e) {
    fwrite(STDERR, 'Audit failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}
