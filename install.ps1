# disk-cleaner-mcp - Windows Installer
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -LocalBinary target\release\disk-cleaner-mcp.exe
#   powershell -ExecutionPolicy Bypass -File install.ps1 -LocalBinary target\release\disk-cleaner-mcp.exe -SkipClientConfig
# Installs the MCP server binary (with atomic hot-swap if running) and additively registers it into detected MCP clients.

param(
    [string]$Version = "latest",
    [switch]$SkipBinary,
    [switch]$SkipClientConfig,
    [string]$LocalBinary = "",
    [string]$InstallDir = "$env:LOCALAPPDATA\disk-cleaner-mcp"
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$exe = Join-Path $InstallDir "disk-cleaner-mcp.exe"

function Remove-StaleBackupBinaries {
    param(
        [Parameter(Mandatory = $true)][string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return
    }

    Get-ChildItem -LiteralPath $Directory -Filter "disk-cleaner-mcp.old*.exe" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Install-BinaryAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$SourceFile,
        [Parameter(Mandatory = $true)][string]$TargetExe
    )

    $targetDir = Split-Path -Path $TargetExe -Parent
    $oldExe = Join-Path $targetDir "disk-cleaner-mcp.old.exe"

    # Best-effort cleanup of stale .old.exe before direct copy
    Remove-Item -LiteralPath $oldExe -Force -ErrorAction SilentlyContinue

    try {
        Copy-Item -LiteralPath $SourceFile -Destination $TargetExe -Force -ErrorAction Stop
    } catch {
        if (Test-Path -LiteralPath $TargetExe -PathType Leaf) {
            # Running MCP binary is locked against overwrite, but Windows allows renaming it on the same volume.
            $backupTarget = $oldExe
            try {
                Move-Item -LiteralPath $TargetExe -Destination $backupTarget -Force -ErrorAction Stop
            } catch {
                $backupTarget = Join-Path $targetDir "disk-cleaner-mcp.old.$PID.exe"
                Move-Item -LiteralPath $TargetExe -Destination $backupTarget -Force -ErrorAction Stop
            }
            Copy-Item -LiteralPath $SourceFile -Destination $TargetExe -Force -ErrorAction Stop
            Write-Host "Running binary was locked; hot-swapped via $backupTarget (will auto-clean on next run)." -ForegroundColor Yellow
        } else {
            throw
        }
    }
}

Write-Host "=== disk-cleaner-mcp installer (Windows) ===" -ForegroundColor Cyan

# 1. Create install dir & best-effort clean stale .old.exe backups
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Remove-StaleBackupBinaries -Directory $InstallDir

# 2. Install binary: -LocalBinary takes precedence over GitHub Release download
if (-not [string]::IsNullOrWhiteSpace($LocalBinary)) {
    if (-not (Test-Path -LiteralPath $LocalBinary -PathType Leaf)) {
        throw "Local binary not found at $LocalBinary."
    }
    $srcFull = [System.IO.Path]::GetFullPath($LocalBinary)
    $dstFull = [System.IO.Path]::GetFullPath($exe)
    if ($srcFull -ne $dstFull) {
        Install-BinaryAtomically -SourceFile $LocalBinary -TargetExe $exe
        Write-Host "Installed local binary from $LocalBinary to $exe" -ForegroundColor Green
    } else {
        Write-Host "Using existing local binary at $exe" -ForegroundColor Green
    }
} elseif (-not $SkipBinary) {
    $asset = "disk-cleaner-mcp-x86_64-pc-windows-msvc.exe"
    if ($Version -eq "latest") {
        # /latest/download/ is a GitHub redirect that always points to the newest release
        $url = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/$asset"
        $sumUrl = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/checksums.txt"
    } else {
        $url = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/$Version/$asset"
        $sumUrl = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/$Version/checksums.txt"
    }
    Write-Host "Downloading $url ..."
    $tmp = "$exe.tmp.$PID"
    $sumFile = Join-Path $env:TEMP "checksums-disk-cleaner-$PID.txt"
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp
        # Verify SHA256 against release checksums (supply-chain integrity)
        Invoke-WebRequest -Uri $sumUrl -OutFile $sumFile
        $line = Get-Content -LiteralPath $sumFile | Where-Object { $_ -match [regex]::Escape($asset) } | Select-Object -First 1
        if (-not $line) { throw "checksums.txt missing entry for $asset" }
        $expected = ($line -split '\s+')[0]
        $actual = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
        if ($expected.ToLower() -ne $actual) { throw "checksum mismatch (expected $expected, got $actual)" }
        Write-Host "Checksum OK: $actual" -ForegroundColor Green
        Install-BinaryAtomically -SourceFile $tmp -TargetExe $exe
    } finally {
        Remove-Item -LiteralPath $sumFile -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        }
    }
}

# 3. Verify binary exists
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Binary not found at $exe. Pass -LocalBinary <path>, build it locally, or check the release URL."
}

function Register-JsonMcpClient {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootKey,
        [Parameter(Mandatory = $true)][PSCustomObject]$ServerEntry,
        [string]$DetectDir = ""
    )

    $parentDir = Split-Path -Path $Path -Parent
    $shouldRegister = if (-not [string]::IsNullOrWhiteSpace($DetectDir)) {
        (Test-Path -LiteralPath $DetectDir -PathType Container) -or (Test-Path -LiteralPath $Path -PathType Leaf)
    } else {
        Test-Path -LiteralPath $parentDir -PathType Container
    }

    if (-not $shouldRegister) {
        return
    }

    Write-Host "Configuring $Name ($Path)..."

    $json = $null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $json = $raw | ConvertFrom-Json
        }
    }
    if ($null -eq $json) {
        $json = [PSCustomObject]@{}
    }

    if (-not ($json.PSObject.Properties.Name -contains $RootKey)) {
        $json | Add-Member -MemberType NoteProperty -Name $RootKey -Value ([PSCustomObject]@{})
    } elseif ($null -eq $json.$RootKey) {
        $json.$RootKey = [PSCustomObject]@{}
    }

    $servers = $json.$RootKey
    $alreadyPresent = if ($servers -is [System.Collections.IDictionary]) {
        $servers.Contains("disk-cleaner-mcp")
    } else {
        $servers.PSObject.Properties.Name -contains "disk-cleaner-mcp"
    }

    if ($alreadyPresent) {
        Write-Host "  already present, skipping"
        return
    }

    if ($servers -is [System.Collections.IDictionary]) {
        $servers["disk-cleaner-mcp"] = $ServerEntry
    } else {
        $servers | Add-Member -MemberType NoteProperty -Name "disk-cleaner-mcp" -Value $ServerEntry
    }

    # Write UTF-8 WITHOUT BOM - a BOM breaks strict JSON parsers reading MCP client configs
    $serialized = ($json | ConvertTo-Json -Depth 20) + "`n"
    [System.IO.File]::WriteAllText($Path, $serialized, $utf8NoBom)
    Write-Host "  OK" -ForegroundColor Green
}

function Register-CodexToml {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BinaryPath
    )

    $parentDir = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $parentDir -PathType Container)) {
        return
    }

    Write-Host "Configuring Codex ($Path)..."

    $existing = ""
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    }

    if ($existing -match '(?m)^\s*\[mcp_servers\.(?:"disk-cleaner-mcp"|''disk-cleaner-mcp''|disk-cleaner-mcp)\]\s*$') {
        Write-Host "  already present, skipping"
        return
    }

    # Use TOML single-quoted literal string so Windows backslashes never trigger escape errors
    if ($BinaryPath.Contains("'")) {
        $escaped = $BinaryPath.Replace('\', '\\').Replace('"', '\"')
        $cmdToml = "`"$escaped`""
    } else {
        $cmdToml = "'$BinaryPath'"
    }

    $block = "[mcp_servers.disk-cleaner-mcp]`ncommand = $cmdToml`n"
    if ([string]::IsNullOrWhiteSpace($existing)) {
        $updated = $block
    } elseif ($existing.EndsWith("`n")) {
        $updated = $existing + "`n" + $block
    } else {
        $updated = $existing + "`n`n" + $block
    }

    [System.IO.File]::WriteAllText($Path, $updated, $utf8NoBom)
    Write-Host "  OK" -ForegroundColor Green
}

# 4. Additive MCP client registrations (never overwrite existing keys)
if ($SkipClientConfig) {
    Write-Host "Skipping MCP client configuration (-SkipClientConfig)." -ForegroundColor DarkGray
} else {
    $standardEntry = [PSCustomObject]@{
        command = $exe
        args    = @()
        env     = [PSCustomObject]@{}
    }

    $openCodeEntry = [PSCustomObject]@{
        type    = "local"
        command = [string[]]@($exe)
        enabled = $true
    }

    $jsonClients = @(
        @{
            Name      = "Claude Desktop"
            Path      = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
            RootKey   = "mcpServers"
            Entry     = $standardEntry
            DetectDir = ""
        },
        @{
            Name      = "Claude Code"
            Path      = Join-Path $env:USERPROFILE ".claude.json"
            RootKey   = "mcpServers"
            Entry     = $standardEntry
            DetectDir = Join-Path $env:USERPROFILE ".claude"
        },
        @{
            Name      = "Cursor"
            Path      = Join-Path $env:USERPROFILE ".cursor\mcp.json"
            RootKey   = "mcpServers"
            Entry     = $standardEntry
            DetectDir = ""
        },
        @{
            Name      = "Gemini CLI"
            Path      = Join-Path $env:USERPROFILE ".gemini\settings.json"
            RootKey   = "mcpServers"
            Entry     = $standardEntry
            DetectDir = ""
        },
        @{
            Name      = "Antigravity"
            Path      = Join-Path $env:USERPROFILE ".gemini\antigravity\mcp_config.json"
            RootKey   = "mcpServers"
            Entry     = $standardEntry
            DetectDir = ""
        },
        @{
            Name      = "OpenCode"
            Path      = Join-Path $env:USERPROFILE ".config\opencode\opencode.json"
            RootKey   = "mcp"
            Entry     = $openCodeEntry
            DetectDir = ""
        }
    )

    foreach ($client in $jsonClients) {
        Register-JsonMcpClient `
            -Name $client.Name `
            -Path $client.Path `
            -RootKey $client.RootKey `
            -ServerEntry $client.Entry `
            -DetectDir $client.DetectDir
    }

    Register-CodexToml -Path (Join-Path $env:USERPROFILE ".codex\config.toml") -BinaryPath $exe
}

# 5. Best-effort cleanup of stale .old.exe backups at script end
Remove-StaleBackupBinaries -Directory $InstallDir

Write-Host ""
Write-Host "Installed at: $exe" -ForegroundColor Green
Write-Host "Test: $exe (expect MCP server to start, then you can use get_system_status / smart_scan / scan / analyze / delete)"
