param(
    [string]$Target = "."
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
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path -Path $Source -PathType Leaf)) {
        throw "Missing source file: $Source"
    }

    $sourceFull = [System.IO.Path]::GetFullPath($Source)
    $destinationFull = [System.IO.Path]::GetFullPath($Destination)

    if ([string]::Equals($sourceFull, $destinationFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "Skipped same file: $Destination"
        return
    }

    $destinationDirectory = Split-Path -Parent $destinationFull
    New-DirectoryIfMissing -DirectoryPath $destinationDirectory

    Copy-Item -Path $sourceFull -Destination $destinationFull -Force
    Write-Host "Copied: $Destination"
}

$SourceRoot = Get-NormalizedPath -InputPath $PSScriptRoot
$TargetRoot = Get-NormalizedPath -InputPath $Target

New-DirectoryIfMissing -DirectoryPath $TargetRoot
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\skills")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\skills\php-production-review")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\skills\php-production-review\scripts")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\agents")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\commands")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot ".claude\rules")
New-DirectoryIfMissing -DirectoryPath (Join-Path $TargetRoot "tools")

$copies = @(
    @{
        Source = Join-Path $SourceRoot "CLAUDE.md"
        Destination = Join-Path $TargetRoot "CLAUDE.md"
    },
    @{
        Source = Join-Path $SourceRoot "custom-instructions.md"
        Destination = Join-Path $TargetRoot "custom-instructions.md"
    },
    @{
        Source = Join-Path $SourceRoot ".claude\skills\php-production-review\SKILL.md"
        Destination = Join-Path $TargetRoot ".claude\skills\php-production-review\SKILL.md"
    },
    @{
        Source = Join-Path $SourceRoot ".claude\skills\php-production-review\scripts\php-prod-audit.php"
        Destination = Join-Path $TargetRoot ".claude\skills\php-production-review\scripts\php-prod-audit.php"
    },
    @{
        Source = Join-Path $SourceRoot ".claude\agents\php-production-auditor.md"
        Destination = Join-Path $TargetRoot ".claude\agents\php-production-auditor.md"
    },
    @{
        Source = Join-Path $SourceRoot ".claude\commands\php-prod-review.md"
        Destination = Join-Path $TargetRoot ".claude\commands\php-prod-review.md"
    },
    @{
        Source = Join-Path $SourceRoot ".claude\rules\php-production-baseline.md"
        Destination = Join-Path $TargetRoot ".claude\rules\php-production-baseline.md"
    },
    @{
        Source = Join-Path $SourceRoot "tools\php-prod-audit.php"
        Destination = Join-Path $TargetRoot "tools\php-prod-audit.php"
    }
)

foreach ($copy in $copies) {
    Copy-FileIfDifferent -Source $copy.Source -Destination $copy.Destination
}

Write-Host ""
Write-Host "Installed Claude PHP production automation into: $TargetRoot"