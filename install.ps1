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
    $url = "https://github.com/CThawngs/Disk-Cleaner-MCP/releases/download/$Version/disk-cleaner-mcp-x86_64-pc-windows-msvc.exe"
    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $Db
}

# 3. Verify binary exists
if (-not (Test-Path $Db)) {
    throw "Binary not found at $Db. Build it locally or fix the release URL."
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
        $command = "`"$Db`""
        $entry = @{ "disk-cleaner-mcp" = @{ command = $command; args = @(); env = @{} } }
        if (Test-Path $cfg.path) {
            $json = Get-Content $cfg.path -Raw | ConvertFrom-Json
            if (-not $json.'mcpServers') { $json | Add-Member -NotePropertyName mcpServers -NotePropertyValue @{} }
            $mcpServers = $json.mcpServers
            if (-not $mcpServers."disk-cleaner-mcp") {
                $mcpServers | Add-Member -NotePropertyName "disk-cleaner-mcp" -NotePropertyValue $entry."disk-cleaner-mcp"
                $json | ConvertTo-Json -Depth 10 | Set-Content $cfg.path -Encoding UTF8
                Write-Host "  OK" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""
Write-Host "Installed at: $Db" -ForegroundColor Green
Write-Host "Test: $Db (expect MCP server to start, then you can use get_system_status / scan / analyze / delete)"