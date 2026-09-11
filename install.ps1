# disk-cleaner-mcp — Windows Installer
# Usage:  powershell -ExecutionPolicy Bypass -File install.ps1
# Installs the MCP server binary + registers it into Claude Desktop / Cursor / other MCP clients.

param(
    [string]$Version = "latest",
    [switch]$SkipBinary,
    [string]$InstallDir = "$env:LOCALAPPDATA\disk-cleaner-mcp"
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $InstallDir "disk-cleaner-mcp.exe"

Write-Host "=== disk-cleaner-mcp installer (Windows) ===" -ForegroundColor Cyan

# 1. Create install dir
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# 2. Download prebuilt binary from GitHub Releases
if (-not $SkipBinary) {
    $asset = "disk-cleaner-mcp-x86_64-pc-windows-msvc.exe"
    if ($Version -eq "latest") {
        # /latest/download/ is a GitHub redirect that always points to the newest release
        $url = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/latest/download/$asset"
    } else {
        $url = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/$Version/$asset"
    }
    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $exe
}

# 3. Verify binary exists
if (-not (Test-Path $exe)) {
    throw "Binary not found at $exe. Build it locally or fix the release URL."
}

# 4. MCP client registrations
$mcpConfigs = @(
    @{ name = "Claude Desktop";  path = "$env:APPDATA\Claude\claude_desktop_config.json" },
    @{ name = "Cursor";          path = "$env:APPDATA\Cursor\mcp.json" },
    @{ name = "Codex";           path = "$env:USERPROFILE\.codex\config.toml" }
)

foreach ($cfg in $mcpConfigs) {
    if (Test-Path (Split-Path $cfg.path -Parent)) {
        Write-Host "Adding to $($cfg.name) ($($cfg.path))..."
        $command = "`"$exe`""
        $entry = @{ "disk-cleaner-mcp" = @{ command = $command; args = @(); env = @{} } }
        if (Test-Path $cfg.path) {
            $json = Get-Content $cfg.path -Raw | ConvertFrom-Json
            if (-not $json.'mcpServers') { $json | Add-Member -NotePropertyName mcpServers -NotePropertyValue @{} }
            $mcpServers = $json.mcpServers
            if (-not $mcpServers."disk-cleaner-mcp") {
                $mcpServers | Add-Member -NotePropertyName "disk-cleaner-mcp" -NotePropertyValue $entry."disk-cleaner-mcp"
                # Write WITHOUT BOM — a BOM breaks strict JSON parsers (Node) reading the client config
                [System.IO.File]::WriteAllText($cfg.path, ($json | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
                Write-Host "  OK" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""
Write-Host "Installed at: $exe" -ForegroundColor Green
Write-Host "Test: $exe (expect MCP server to start, then you can use get_system_status / scan / analyze / delete)"