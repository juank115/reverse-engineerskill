#Requires -Version 5.1

<#
.SYNOPSIS
    Installs the reverse-engineering skill for Claude Code, OpenCode, and other agents.

.DESCRIPTION
    Creates copies or directory junctions in the standard skill directories.
    Default behavior is to create junctions (symlinks for directories on Windows).
    Pass -Copy to copy files instead.

.PARAMETER Copy
    Copy files instead of creating junctions.

.PARAMETER Force
    Do not prompt before replacing an existing skill.
#>

[CmdletBinding()]
param(
    [switch]$Copy,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$SkillName = "reverse-engineering"
$RepoRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)).Path
$SkillsRoot = Join-Path $RepoRoot "skills"
$SkillSource = Join-Path $SkillsRoot $SkillName

if (-not (Test-Path $SkillSource -PathType Container)) {
    throw "Skill source directory not found at: $SkillSource"
}

$TargetDirs = @(
    (Join-Path (Join-Path $env:USERPROFILE ".claude") "skills"),
    (Join-Path (Join-Path (Join-Path $env:USERPROFILE ".config") "opencode") "skills"),
    (Join-Path (Join-Path $env:USERPROFILE ".agents") "skills")
)

function Install-Skill {
    param(
        [string]$TargetDir
    )

    $TargetPath = Join-Path $TargetDir $SkillName

    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }

    if (Test-Path -LiteralPath $TargetPath) {
        if (-not $Force) {
            $answer = Read-Host "$TargetPath already exists. Replace? [y/N]"
            if ($answer -notmatch '^[Yy]$') {
                Write-Host "Skipping $TargetDir"
                return
            }
        }
        Remove-Item -LiteralPath $TargetPath -Recurse -Force
    }

    if ($Copy) {
        Copy-Item -LiteralPath $SkillSource -Destination $TargetPath -Recurse
        Write-Host "Copied skill to $TargetPath"
    } else {
        New-Item -ItemType Junction -Path $TargetPath -Target $SkillSource | Out-Null
        Write-Host "Linked skill to $TargetPath"
    }
}

Write-Host "Installing $SkillName skill..."
Write-Host "Source: $SkillSource"
$InstallMode = if ($Copy) { "copy" } else { "junction" }
Write-Host "Mode: $InstallMode"
Write-Host ""

foreach ($dir in $TargetDirs) {
    Install-Skill -TargetDir $dir
}

Write-Host ""
Write-Host "Installation complete."
Write-Host "Restart Claude Code / OpenCode / your agent for the skill to load."
