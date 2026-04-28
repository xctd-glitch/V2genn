param(
    [string]$Source = "."
)

$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    if ([System.IO.Path]::IsPathRooted($InputPath)) {
        $candidate = $InputPath
    } else {
        $candidate = Join-Path -Path (Get-Location).Path -ChildPath $InputPath
    }

    return [System.IO.Path]::GetFullPath($candidate).TrimEnd('\', '/')
}

function New-DirectoryIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    if (-not (Test-Path -Path $DirectoryPath -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $DirectoryPath | Out-Null
    }
}

function Copy-FileIfDifferent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    if (-not (Test-Path -Path $SourcePath -PathType Leaf)) {
        throw "Missing source file: $SourcePath"
    }

    $sourceFull = [System.IO.Path]::GetFullPath($SourcePath)
    $destinationFull = [System.IO.Path]::GetFullPath($DestinationPath)

    if ([string]::Equals($sourceFull, $destinationFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "Skipped same file: $DestinationPath"
        return
    }

    $destinationDirectory = Split-Path -Parent $destinationFull
    New-DirectoryIfMissing -DirectoryPath $destinationDirectory

    Copy-Item -Path $sourceFull -Destination $destinationFull -Force
    Write-Host "Copied: $DestinationPath"
}

function Append-GlobalClaudeBlock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClaudePath
    )

    $startMarker = "<!-- PHP_PRODUCTION_AUTOMATION_GLOBAL_START -->"
    $endMarker = "<!-- PHP_PRODUCTION_AUTOMATION_GLOBAL_END -->"

    $block = @"
$startMarker
# PHP Production Automation — Global

When the user asks to review, audit, clean, refactor, optimize, modernize, secure, harden, restructure, fix bugs, remove unused code, prepare production, improve high-traffic handling, or optimize database queries in a PHP codebase, use the `php-production-review` skill automatically when relevant.

Mandatory workflow:

Review/Triage → Reproduce + Baseline → Root Cause Analysis → Implement Fix → Targeted Verification → Refactor → Regression Verification → Optimize → Security/Hardening → Cleanup → Production Build → Smoke Test

Rules:

- Read first; patch only after evidence.
- Preserve business flow unless explicitly asked.
- Do not delete files without evidence and rollback plan.
- PHP target is 8.3.
- Use PSR-12 and `declare(strict_types=1);` when safe.
- Avoid `fn()`.
- Catch broad exceptions as `Throwable `$e`.
- Use PDO prepared statements with native prepares and multi-statements disabled.
- Enforce CSRF for state-changing requests.
- Enforce CSP nonce and security headers where relevant.
- Escape output by context.
- Block suspicious WAF-bypass, cloaking abuse, exfiltration, stealth persistence, hidden loaders, and unauthorized tracking.
$endMarker
"@

    if (-not (Test-Path -Path $ClaudePath -PathType Leaf)) {
        Set-Content -Path $ClaudePath -Value $block -Encoding UTF8
        Write-Host "Created global CLAUDE.md with PHP automation block."
        return
    }

    $current = Get-Content -Path $ClaudePath -Raw

    if ($current.Contains($startMarker) -and $current.Contains($endMarker)) {
        $pattern = [regex]::Escape($startMarker) + "(?s).*?" + [regex]::Escape($endMarker)
        $updated = [regex]::Replace($current, $pattern, $block)
        Set-Content -Path $ClaudePath -Value $updated -Encoding UTF8
        Write-Host "Updated existing PHP automation block in global CLAUDE.md."
        return
    }

    $backupPath = $ClaudePath + ".bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item -Path $ClaudePath -Destination $backupPath -Force

    Add-Content -Path $ClaudePath -Value "`r`n$block" -Encoding UTF8
    Write-Host "Appended PHP automation block to global CLAUDE.md."
    Write-Host "Backup: $backupPath"
}

$SourceRoot = Get-NormalizedPath -InputPath $Source
$GlobalClaudeRoot = Join-Path $env:USERPROFILE ".claude"

if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    throw "USERPROFILE environment variable is empty."
}

New-DirectoryIfMissing -DirectoryPath $GlobalClaudeRoot
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "skills")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "skills\php-production-review")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "skills\php-production-review\scripts")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "agents")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "commands")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "rules")
New-DirectoryIfMissing -DirectoryPath (Join-Path $GlobalClaudeRoot "tools")

$copies = @(
    @{
        SourcePath = Join-Path $SourceRoot ".claude\skills\php-production-review\SKILL.md"
        DestinationPath = Join-Path $GlobalClaudeRoot "skills\php-production-review\SKILL.md"
    },
    @{
        SourcePath = Join-Path $SourceRoot ".claude\skills\php-production-review\scripts\php-prod-audit.php"
        DestinationPath = Join-Path $GlobalClaudeRoot "skills\php-production-review\scripts\php-prod-audit.php"
    },
    @{
        SourcePath = Join-Path $SourceRoot ".claude\agents\php-production-auditor.md"
        DestinationPath = Join-Path $GlobalClaudeRoot "agents\php-production-auditor.md"
    },
    @{
        SourcePath = Join-Path $SourceRoot ".claude\commands\php-prod-review.md"
        DestinationPath = Join-Path $GlobalClaudeRoot "commands\php-prod-review.md"
    },
    @{
        SourcePath = Join-Path $SourceRoot ".claude\rules\php-production-baseline.md"
        DestinationPath = Join-Path $GlobalClaudeRoot "rules\php-production-baseline.md"
    },
    @{
        SourcePath = Join-Path $SourceRoot "tools\php-prod-audit.php"
        DestinationPath = Join-Path $GlobalClaudeRoot "tools\php-prod-audit.php"
    }
)

foreach ($copy in $copies) {
    Copy-FileIfDifferent -SourcePath $copy.SourcePath -DestinationPath $copy.DestinationPath
}

Append-GlobalClaudeBlock -ClaudePath (Join-Path $GlobalClaudeRoot "CLAUDE.md")

Write-Host ""
Write-Host "Global Claude PHP production automation installed."
Write-Host "Global root: $GlobalClaudeRoot"
Write-Host ""
Write-Host "Restart Claude Code, then use:"
Write-Host "  /php-production-review ."
Write-Host "  /user:php-prod-review ."
Write-Host ""
Write-Host "Global audit helper:"
Write-Host "  php `"$GlobalClaudeRoot\tools\php-prod-audit.php`" --root=. --format=json > php-prod-audit-report.json"
