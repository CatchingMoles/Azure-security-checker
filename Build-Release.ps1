<#
.SYNOPSIS
    Build script voor Catching Moles Security Auditor
    
.DESCRIPTION
    Combineert alle modulaire bestanden tot één release bestand.
    Gebruikt voor distributie via one-liner.
    
.EXAMPLE
    .\Build-Release.ps1
    
.OUTPUTS
    CatchingMoles-Release.ps1 - All-in-one release bestand
#>

[CmdletBinding()]
param()

Write-Host "`nBuilding Catching Moles Release..." -ForegroundColor Cyan
Write-Host ""

# Configuratie
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputFile = Join-Path $scriptPath "CatchingMoles-Release.ps1"
$version = "2.0.0"

# Build order (dependency order!)
$buildOrder = @(
    @{ Path = "utils\Logging.ps1"; Description = "Logging utilities" }
    @{ Path = "utils\FileSystem.ps1"; Description = "File system operations" }
    @{ Path = "modules\Audit-Storage.ps1"; Description = "Storage Account audit module" }
    @{ Path = "modules\Audit-WebApp.ps1"; Description = "Web App audit module" }
    @{ Path = "modules\Audit-KeyVault.ps1"; Description = "Key Vault audit module" }
    @{ Path = "modules\Audit-SqlServer.ps1"; Description = "SQL Server audit module" }
    @{ Path = "modules\Audit-NetworkSecurityGroup.ps1"; Description = "Network Security Group audit module" }
    @{ Path = "modules\Audit-Monitoring.ps1"; Description = "Monitoring and Logging audit module" }
    @{ Path = "modules\Audit-Compliance.ps1"; Description = "Defender for Cloud CSPM compliance module" }
    @{ Path = "modules\Audit-RBAC.ps1"; Description = "RBAC audit module (God-mode detection)" }
    @{ Path = "modules\Audit-VNetTopology.ps1"; Description = "VNet Topology audit module (Network exposure + Cost)" }
    @{ Path = "Invoke-CatchingMoles.ps1"; Description = "Orchestrator / Controller" }
)

# Start building - use array to avoid encoding issues
$outputLines = @()

# Header
$outputLines += "<#"
$outputLines += "==============================================================================="
$outputLines += "CATCHING MOLES SECURITY AUDITOR - RELEASE BUILD"
$outputLines += "==============================================================================="
$outputLines += ""
$outputLines += "Version: $version"
$outputLines += "Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$outputLines += "Architecture: Zero-Crypto / Random ID based anonymization"
$outputLines += ""
$outputLines += "This is a compiled release file containing:"
foreach ($module in $buildOrder) {
    $outputLines += "  - $($module.Path) ($($module.Description))"
}
$outputLines += ""
$outputLines += "For source code, visit: https://github.com/[your-repo]/Az-security-baselinechecker"
$outputLines += "==============================================================================="
$outputLines += "#>"
$outputLines += ""

# ============================================================================
# EXTRACT PARAM BLOCK FROM CONTROLLER (Via Marker)
# ============================================================================
$controllerPath = Join-Path $scriptPath "Invoke-CatchingMoles.ps1"
$controllerRaw = Get-Content $controllerPath -Raw
$controllerParts = $controllerRaw -split "# COMPILER-MARKER: END-PARAMS"

if ($controllerParts.Count -eq 2) {
    Write-Host "Extracting param block via Marker..." -ForegroundColor Gray
    Write-Host "  > Param block extracted successfully" -ForegroundColor Green
    
    # Strip leading comment block from first part
    $paramSection = $controllerParts[0] -replace '(?s)^<#.*?#>\s*', ''
    $outputLines += $paramSection.Trim()
    $outputLines += ""
    $outputLines += ""
}
else {
    Write-Host "ERROR: Marker '# COMPILER-MARKER: END-PARAMS' not found in Controller!" -ForegroundColor Red
    exit 1
}

# Process each module
foreach ($module in $buildOrder) {
    $modulePath = Join-Path $scriptPath $module.Path
    
    if (-not (Test-Path $modulePath)) {
        Write-Host "ERROR: File not found: $($module.Path)" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Adding: $($module.Path)" -ForegroundColor Green
    
    # Add source marker
    $outputLines += "# ============================================================================"
    $outputLines += "# SOURCE: $($module.Path)"
    $outputLines += "# $($module.Description)"
    $outputLines += "# ============================================================================"
    $outputLines += ""
    
    # Read and add module content (skip initial comment blocks)
    $content = Get-Content $modulePath -Raw
    
    # Remove leading comment block (synopsis)
    $content = $content -replace '(?s)^<#.*?#>\s*', ''
    
    # Special handling for Controller: Use body from marker split (param already at top)
    if ($module.Path -eq "Invoke-CatchingMoles.ps1") {
        Write-Host "  > Using Controller body after marker (param already at top)" -ForegroundColor Gray
        $content = $controllerParts[1].Trim()
    }
    
    $outputLines += $content.Trim()
    $outputLines += ""
    $outputLines += ""
}

# Write output
Write-Host ""
Write-Host "Writing to: $outputFile" -ForegroundColor Cyan

# CRITICAL: Use UTF-8 WITHOUT BOM for irm | iex compatibility
# Standard Out-File -Encoding UTF8 adds BOM which breaks PowerShell comment parsing
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$outputContent = $outputLines -join "`r`n"
[System.IO.File]::WriteAllText($outputFile, $outputContent, $utf8NoBom)

# Summary
$lineCount = (Get-Content $outputFile).Count
$sizeKB = [math]::Round((Get-Item $outputFile).Length / 1KB, 2)

Write-Host ""
Write-Host "Build successful!" -ForegroundColor Green
Write-Host "   File: CatchingMoles-Release.ps1" -ForegroundColor White
Write-Host "   Lines: $lineCount" -ForegroundColor White
Write-Host "   Size: $sizeKB KB" -ForegroundColor White
Write-Host ""
Write-Host "Ready for distribution!" -ForegroundColor Green
Write-Host ""
