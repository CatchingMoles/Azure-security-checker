<#
===============================================================================
CATCHING MOLES SECURITY AUDITOR - RELEASE BUILD
===============================================================================

Version: 2.0.0
Built: 2026-05-03 13:07:50
Architecture: Zero-Crypto / Random ID based anonymization

This is a compiled release file containing:
  - utils\Logging.ps1 (Logging utilities)
  - utils\FileSystem.ps1 (File system operations)
  - modules\Audit-Storage.ps1 (Storage Account audit module)
  - modules\Audit-WebApp.ps1 (Web App audit module)
  - modules\Audit-KeyVault.ps1 (Key Vault audit module)
  - modules\Audit-SqlServer.ps1 (SQL Server audit module)
  - modules\Audit-NetworkSecurityGroup.ps1 (Network Security Group audit module)
  - modules\Audit-Monitoring.ps1 (Monitoring and Logging audit module)
  - modules\Audit-Compliance.ps1 (Defender for Cloud CSPM compliance module)
  - modules\Audit-RBAC.ps1 (RBAC audit module (God-mode detection))
  - modules\Audit-VNetTopology.ps1 (VNet Topology audit module (Network exposure + Cost))
  - Invoke-CatchingMoles.ps1 (Orchestrator / Controller)

For source code, visit: https://github.com/[your-repo]/Az-security-baselinechecker
===============================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FunctionUrl,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableComplianceCheck,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AllowedRegions = @('westeurope', 'northeurope', 'germanywestcentral', 'francecentral', 'switzerlandnorth'),
    
    [Parameter(Mandatory = $false)]
    [switch]$QuietMode
)


# ============================================================================
# SOURCE: utils\Logging.ps1
# Logging utilities
# ============================================================================

function Write-AuditLog {
    <#
    .SYNOPSIS
        Schrijft audit log berichten naar console met timestamp en kleurcodering
    
    .PARAMETER Message
        Het bericht om te loggen
    
    .PARAMETER Level
        Log level: Info, Warning, Error, Success
    
    .EXAMPLE
        Write-AuditLog "Scanning storage accounts..." -Level Info
        Write-AuditLog "Security issue found!" -Level Warning
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    # Skip verbose logging in Quiet Mode (if global variable is set)
    if ($script:QuietMode -and $Level -eq 'Info') {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'Info'    { 'Gray' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}


# ============================================================================
# SOURCE: utils\FileSystem.ps1
# File system operations
# ============================================================================

# Configuratie constante
$script:OUTPUT_DIR_NAME = "CatchingMoles-Rapport"

function New-OutputDirectory {
    <#
    .SYNOPSIS
        Maakt de output directory aan in de huidige werkmap
    
    .DESCRIPTION
        CreÃ«ert een directory genaamd 'CatchingMoles-Rapport' in de current working directory.
        Als de directory al bestaat, wordt deze hergebruikt.
    
    .OUTPUTS
        String - Het volledige pad naar de output directory
    
    .EXAMPLE
        $outputDir = New-OutputDirectory
        # Returns: C:\Users\user\CatchingMoles-Rapport
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $outputPath = Join-Path (Get-Location) $script:OUTPUT_DIR_NAME
    
    try {
        if (-not (Test-Path $outputPath)) {
            New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
            Write-AuditLog "Created output directory: $outputPath" -Level Info
        }
        else {
            Write-AuditLog "Using existing output directory: $outputPath" -Level Info
        }
        
        return $outputPath
    }
    catch {
        Write-AuditLog "Failed to create output directory: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-MappingCSV {
    <#
    .SYNOPSIS
        Exporteert de mapping tussen Random IDs en echte resource namen naar CSV
    
    .DESCRIPTION
        âš ï¸ CONFIDENTIAL - Dit bestand bevat echte Azure resource namen.
        Exporteert een CSV bestand met de correlatie tussen anonieme Random IDs
        en de werkelijke resource namen voor lokale reference.
    
    .PARAMETER MappingData
        Array van PSCustomObjects met RandomId, RealStorageAccountName, etc.
    
    .PARAMETER OutputDirectory
        Pad waar het CSV bestand wordt opgeslagen
    
    .OUTPUTS
        String - Het volledige pad naar het gegenereerde CSV bestand
    
    .EXAMPLE
        $path = Export-MappingCSV -MappingData $data -OutputDirectory "C:\Output"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$MappingData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )
    
    try {
        $filePath = Join-Path $OutputDirectory "Client_Secret_Mapping.csv"
        
        # Export naar CSV met headers
        $MappingData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
        
        Write-AuditLog "Secret mapping saved to: $filePath" -Level Success
        return $filePath
    }
    catch {
        Write-AuditLog "Failed to save mapping CSV: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-TransmitPayload {
    <#
    .SYNOPSIS
        Exporteert de anonieme payload voor externe transmissie
    
    .DESCRIPTION
        âœ… SAFE - Dit bestand bevat GEEN gevoelige informatie.
        Exporteert een JSON bestand met alleen Random IDs en generic security findings.
        Dit bestand is veilig om extern te delen.
    
    .PARAMETER AnonymousFindings
        Array van anonieme findings (alleen RandomId, Location, Issues, etc.)
    
    .PARAMETER OutputDirectory
        Pad waar het JSON bestand wordt opgeslagen
    
    .OUTPUTS
        String - Het volledige pad naar het gegenereerde JSON bestand
    
    .EXAMPLE
        $path = Export-TransmitPayload -AnonymousFindings $findings -OutputDirectory "C:\Output"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AnonymousFindings,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )
    
    try {
        $filePath = Join-Path $OutputDirectory "Transmit_Payload.json"
        
        # Export naar JSON met formatting
        $AnonymousFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-AuditLog "Anonymous payload saved to: $filePath" -Level Success
        return $filePath
    }
    catch {
        Write-AuditLog "Failed to save payload JSON: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-CloudShellEnvironment {
    <#
    .SYNOPSIS
        Detecteert of het script draait in Azure Cloud Shell
    
    .DESCRIPTION
        Controleert environment variables die specifiek zijn voor Cloud Shell.
    
    .OUTPUTS
        Boolean - $true als Cloud Shell, $false anders
    
    .EXAMPLE
        if (Test-CloudShellEnvironment) {
            Write-Host "Running in Cloud Shell"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    return ($env:ACC_CLOUD -or $env:AZUREPS_HOST_ENVIRONMENT -eq 'cloud-shell')
}


# ============================================================================
# SOURCE: modules\Audit-Storage.ps1
# Storage Account audit module
# ============================================================================

function Test-StorageAccountSecurity {
    <#
    .SYNOPSIS
        Voert security checks uit op een enkel Storage Account
    
    .DESCRIPTION
        Controleert:
        - Public Blob Access
        - TLS versie compliance
        - Data residency (optioneel)
    
    .PARAMETER StorageAccount
        Het Storage Account object van Get-AzStorageAccount
    
    .PARAMETER EnableCompliance
        Schakel data residency checks in
    
    .PARAMETER AllowedRegions
        Array van toegestane Azure regio's
    
    .OUTPUTS
        PSCustomObject met Issues en Severity
    
    .EXAMPLE
        $result = Test-StorageAccountSecurity -StorageAccount $account
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageAccount,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableCompliance = $false,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRegions = @()
    )
    
    $issues = @()
    $severity = "Low"
    
    # Check 1: Public Blob Access
    if ($StorageAccount.AllowBlobPublicAccess) {
        $issues += "Public Blob Access enabled"
        $severity = "High"
    }
    
    # Check 2: TLS Version Compliance
    $minTlsVersion = $StorageAccount.MinimumTlsVersion
    $isTlsCompliant = $false
    
    if ($minTlsVersion) {
        $isTlsCompliant = $minTlsVersion -in @('TLS1_2', 'TLS1_3')
    }
    
    if (-not $isTlsCompliant) {
        if ($minTlsVersion) {
            $issues += "Minimum TLS Version too low: $minTlsVersion (required: TLS1_2+)"
        }
        else {
            $issues += "Minimum TLS Version not set (required: TLS1_2+)"
        }
        $severity = "High"
    }
    
    # Check 3: Data Residency (optioneel)
    if ($EnableCompliance -and $AllowedRegions.Count -gt 0) {
        $location = $StorageAccount.Location.ToLower()
        $allowedLower = $AllowedRegions | ForEach-Object { $_.ToLower() }
        
        if ($location -notin $allowedLower) {
            $issues += "Data Residency Violation - Region '$($StorageAccount.Location)' not allowed"
            $severity = if ($severity -eq "High") { "Critical" } else { "High" }
        }
    }
    
    return [PSCustomObject]@{
        Issues        = $issues
        Severity      = $severity
        MinTlsVersion = $minTlsVersion
        PublicAccess  = $StorageAccount.AllowBlobPublicAccess
    }
}

function Get-StorageAccountFindings {
    <#
    .SYNOPSIS
        Scant alle Storage Accounts in een subscription
    
    .DESCRIPTION
        Haalt alle Storage Accounts op in de huidige Azure context (subscription)
        en voert security checks uit. Genereert anonieme findings met Random GUIDs.
    
    .PARAMETER Subscription
        Het Azure Subscription object
    
    .PARAMETER EnableCompliance
        Schakel data residency checks in
    
    .PARAMETER AllowedRegions
        Array van toegestane Azure regio's
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, AccountCount, IssuesCount
    
    .EXAMPLE
        $result = Get-StorageAccountFindings -Subscription $sub -EnableCompliance $true
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableCompliance = $false,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRegions = @()
    )
    
    $mappingData = @()
    $anonymousFindings = @()
    $accountCount = 0
    $issuesCount = 0
    
    try {
        # Scan storage accounts in deze subscription
        Write-AuditLog "Scanning storage accounts in subscription: $($Subscription.Name)..." -Level Info
        $storageAccounts = Get-AzStorageAccount -ErrorAction Stop
        
        if (-not $storageAccounts) {
            Write-Host "  [INFO] No storage accounts found in this subscription" -ForegroundColor Gray
            Write-AuditLog "No storage accounts found in subscription: $($Subscription.Name)" -Level Warning
            
            return @{
                MappingData       = @()
                AnonymousFindings = @()
                AccountCount      = 0
                IssuesCount       = 0
            }
        }
        
        foreach ($account in $storageAccounts) {
            try {
                $accountCount++
                
                # Voer security checks uit
                $securityCheck = Test-StorageAccountSecurity -StorageAccount $account -EnableCompliance $EnableCompliance -AllowedRegions $AllowedRegions
                
                # Alleen findings bewaren als er issues zijn
                if ($securityCheck.Issues.Count -gt 0) {
                    $issuesCount++
                    
                    # Genereer Random GUID (Zero-Crypto!)
                    $randomId = (New-Guid).ToString()
                    
                    # CONFIDENTIAL MAPPING
                    $mappingEntry = [PSCustomObject]@{
                        RandomId               = $randomId
                        RealStorageAccountName = $account.StorageAccountName
                        RealSubscriptionName   = $Subscription.Name
                        RealLocation           = $account.Location
                    }
                    $mappingData += $mappingEntry
                    
                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousEntry = [PSCustomObject]@{
                        RandomId      = $randomId
                        Location      = $account.Location
                        MinTlsVersion = if ($securityCheck.MinTlsVersion) { $securityCheck.MinTlsVersion } else { "Not Set" }
                        PublicAccess  = $securityCheck.PublicAccess
                        Issues        = $securityCheck.Issues
                        Severity      = $securityCheck.Severity
                    }
                    $anonymousFindings += $anonymousEntry
                    
                    Write-AuditLog "Security issue(s) found in $($account.StorageAccountName): $($securityCheck.Issues -join ', ')" -Level Warning
                }
                
                # Console output (alleen bij issues of niet-quiet mode)
                if (-not $script:QuietMode -or $securityCheck.Issues.Count -gt 0) {
                    $status = if ($securityCheck.Issues.Count -gt 0) { "[!] UNSAFE" } else { "[OK] SAFE" }
                    $statusColor = if ($securityCheck.Issues.Count -gt 0) { 'Yellow' } else { 'Green' }
                    
                    Write-Host "  [$status] $($account.StorageAccountName) (Location: $($account.Location))" -ForegroundColor $statusColor
                    
                    if ($securityCheck.Issues.Count -gt 0) {
                        foreach ($issue in $securityCheck.Issues) {
                            Write-Host "           - [!] $issue" -ForegroundColor Yellow
                        }
                        Write-Host "           - Random ID: $randomId" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-AuditLog "Error processing storage account (account skipped): $($_.Exception.Message)" -Level Error
                continue
            }
        }
        
        Write-Host "  [OK] Scanned $accountCount storage account(s)" -ForegroundColor Green
        Write-AuditLog "Successfully scanned $accountCount storage account(s) in $($Subscription.Name)" -Level Success
    }
    catch {
        Write-AuditLog "Azure API error while scanning subscription $($Subscription.Name): $($_.Exception.Message)" -Level Error
        Write-Host "  [ERROR] Error scanning this subscription (API error)" -ForegroundColor Red
    }
    
    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        AccountCount      = $accountCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-WebApp.ps1
# Web App audit module
# ============================================================================

function Test-WebAppSecurity {
    <#
    .SYNOPSIS
        Voert security checks uit op een enkele Web App
    
    .DESCRIPTION
        Controleert Web App configuratie tegen OWASP Top 10 en Azure best practices:
        
        CRITICAL CHECKS:
        - Remote Debugging (OWASP A05: Security Misconfiguration)
        - HTTPS Only enforcement (OWASP A02: Cryptographic Failures)
        - TLS versie compliance - minimum 1.2 (OWASP A02)
        
        HIGH/MEDIUM CHECKS:
        - FTP/FTPS configuratie (OWASP A05: Security Misconfiguration)
        - Managed Identity configuration (OWASP A01: Broken Access Control)
        
        LOW/INFORMATIONAL CHECKS:
        - Diagnostic Logging (OWASP A09: Security Logging and Monitoring Failures)
        - Client Certificate authentication (defense in depth)
    
    .PARAMETER WebApp
        Het Web App object van Get-AzWebApp
    
    .OUTPUTS
        PSCustomObject met Issues en Severity
    
    .EXAMPLE
        $result = Test-WebAppSecurity -WebApp $app
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$WebApp
    )
    
    $issues = @()
    $severity = "Low"
    
    # Null-safe: Check if SiteConfig exists
    if (-not $WebApp.SiteConfig) {
        Write-AuditLog "Warning: SiteConfig not available for $($WebApp.Name)" -Level Warning
        return [PSCustomObject]@{
            Issues   = @("Unable to retrieve configuration")
            Severity = "Unknown"
            Config   = @{}
        }
    }
    
    # ========================================================================
    # CRITICAL CHECKS (OWASP Top 10)
    # ========================================================================
    
    # Check 1: Remote Debugging (OWASP A05: Security Misconfiguration)
    # Remote Debugging exposes internal app state and should NEVER be enabled in production
    if ($WebApp.SiteConfig.RemoteDebuggingEnabled -eq $true) {
        $issues += "Remote Debugging is ENABLED - critical production security risk"
        $severity = "Critical"
    }
    
    # Check 2: HTTPS Only enforcement (OWASP A02: Cryptographic Failures)
    if (-not $WebApp.HttpsOnly) {
        $issues += "HTTPS Only is disabled - allows insecure HTTP traffic"
        $severity = "Critical"
    }
    
    # Check 3: TLS Version Compliance (OWASP A02: Cryptographic Failures)
    $minTls = $WebApp.SiteConfig.MinTlsVersion
    $isTlsCompliant = $false
    
    if ($minTls) {
        # Azure TLS versions: "1.0", "1.1", "1.2", "1.3"
        $isTlsCompliant = $minTls -in @('1.2', '1.3')
    }
    
    if (-not $isTlsCompliant) {
        if ($minTls) {
            $issues += "Insecure TLS version: $minTls (required: 1.2 or 1.3)"
        }
        else {
            $issues += "TLS version not configured (required: 1.2 or 1.3)"
        }
        
        # Escalate to High if not already Critical
        if ($severity -ne "Critical") {
            $severity = "High"
        }
    }

    # ========================================================================
    # HIGH/MEDIUM CHECKS
    # ========================================================================
    
    # Check 4: FTP State (OWASP A05: Security Misconfiguration)
    $ftpsState = $WebApp.SiteConfig.FtpsState
    
    if ($ftpsState -and $ftpsState -notin @("FtpsOnly", "Disabled")) {
        $issues += "Insecure FTP state: $ftpsState (recommended: FtpsOnly or Disabled)"
        
        # Escalate to Medium if still Low
        if ($severity -eq "Low") {
            $severity = "Medium"
        }
    }
    
    # Check 5: Managed Identity (OWASP A01: Broken Access Control / Secret Management)
    # Managed Identity allows secret-less authentication to Azure services
    $identityType = if ($WebApp.Identity) { $WebApp.Identity.Type } else { "None" }
    
    if ($identityType -eq "None" -or -not $identityType) {
        $issues += "Managed Identity not configured - consider enabling for secret-less Azure authentication"
        
        # Escalate to Medium if still Low
        if ($severity -eq "Low") {
            $severity = "Medium"
        }
    }
    
    # ========================================================================
    # LOW/INFORMATIONAL CHECKS
    # ========================================================================
    
    # Check 6: Diagnostic Logging (OWASP A09: Security Logging and Monitoring Failures)
    $httpLoggingEnabled = $WebApp.SiteConfig.HttpLoggingEnabled -eq $true
    $detailedErrorsEnabled = $WebApp.SiteConfig.DetailedErrorLoggingEnabled -eq $true
    
    if (-not $httpLoggingEnabled -and -not $detailedErrorsEnabled) {
        $issues += "Diagnostic logging disabled - HTTP logs and detailed errors not captured"
        
        # Only raise to Medium if there are other security issues (defense in depth)
        if ($issues.Count -gt 1 -and $severity -eq "Low") {
            $severity = "Medium"
        }
    }
    
    # Check 7: Client Certificate Mode (Optional hardening - defense in depth)
    $clientCertEnabled = $WebApp.ClientCertEnabled
    if (-not $clientCertEnabled) {
        # This is informational, not critical
        # Only add as issue if other issues exist (defense in depth)
        if ($issues.Count -gt 0) {
            $issues += "Client certificate authentication disabled (optional hardening)"
        }
    }
    
    return [PSCustomObject]@{
        Issues   = $issues
        Severity = $severity
        Config   = @{
            # Critical/High Security Controls
            RemoteDebuggingEnabled = $WebApp.SiteConfig.RemoteDebuggingEnabled
            HttpsOnly              = $WebApp.HttpsOnly
            MinTlsVersion          = if ($minTls) { $minTls } else { "Not Set" }
            FtpsState              = if ($ftpsState) { $ftpsState } else { "Not Set" }
            
            # Identity & Access
            ManagedIdentityType    = $identityType
            ClientCertEnabled      = $clientCertEnabled
            
            # Monitoring & Logging
            HttpLoggingEnabled     = $httpLoggingEnabled
            DetailedErrorsEnabled  = $detailedErrorsEnabled
        }
    }
}

function Get-WebAppFindings {
    <#
    .SYNOPSIS
        Scant alle Web Apps in een subscription
    
    .DESCRIPTION
        Haalt alle Web Apps op in de huidige Azure context (subscription)
        en voert security checks uit. Genereert anonieme findings met Random GUIDs.
    
    .PARAMETER Subscription
        Het Azure Subscription object
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, AppCount, IssuesCount
    
    .EXAMPLE
        $result = Get-WebAppFindings -Subscription $sub
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    $mappingData = @()
    $anonymousFindings = @()
    $appCount = 0
    $issuesCount = 0
    
    try {
        # Scan Web Apps in deze subscription
        Write-AuditLog "Scanning Web Apps in subscription: $($Subscription.Name)..." -Level Info
        $webApps = Get-AzWebApp -ErrorAction Stop
        
        if (-not $webApps) {
            Write-Host "  [INFO] No Web Apps found in this subscription" -ForegroundColor Gray
            Write-AuditLog "No Web Apps found in subscription: $($Subscription.Name)" -Level Warning
            
            return @{
                MappingData       = @()
                AnonymousFindings = @()
                AppCount          = 0
                IssuesCount       = 0
            }
        }
        
        foreach ($app in $webApps) {
            try {
                $appCount++
                
                # Voer security checks uit
                $securityCheck = Test-WebAppSecurity -WebApp $app
                
                # Alleen findings bewaren als er issues zijn
                if ($securityCheck.Issues.Count -gt 0) {
                    $issuesCount++
                    
                    # Genereer Random GUID (Zero-Crypto!)
                    $randomId = (New-Guid).ToString()
                    
                    # CONFIDENTIAL MAPPING
                    $mappingEntry = [PSCustomObject]@{
                        RandomId         = $randomId
                        RealResourceName = $app.Name
                        ResourceType     = "WebApp"
                        RealSubscription = $Subscription.Name
                        RealLocation     = $app.Location
                    }
                    $mappingData += $mappingEntry
                    
                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousEntry = [PSCustomObject]@{
                        RandomId     = $randomId
                        ResourceType = "WebApp"
                        Location     = $app.Location
                        Issues       = $securityCheck.Issues
                        Severity     = $securityCheck.Severity
                        Details      = $securityCheck.Config
                    }
                    $anonymousFindings += $anonymousEntry
                    
                    Write-AuditLog "Security issue(s) found in WebApp $($app.Name): $($securityCheck.Issues -join ', ')" -Level Warning
                }
                
                # Console output (alleen bij issues of niet-quiet mode)
                if (-not $script:QuietMode -or $securityCheck.Issues.Count -gt 0) {
                    $status = if ($securityCheck.Issues.Count -gt 0) { "[!] UNSAFE" } else { "[OK] SAFE" }
                    $statusColor = if ($securityCheck.Issues.Count -gt 0) { 'Yellow' } else { 'Green' }
                    
                    Write-Host "  [$status] $($app.Name) (Location: $($app.Location))" -ForegroundColor $statusColor
                    
                    if ($securityCheck.Issues.Count -gt 0) {
                        foreach ($issue in $securityCheck.Issues) {
                            Write-Host "           - [!] $issue" -ForegroundColor Yellow
                        }
                        Write-Host "           - Random ID: $randomId" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-AuditLog "Error processing Web App (app skipped): $($_.Exception.Message)" -Level Error
                continue
            }
        }
        
        Write-Host "  [OK] Scanned $appCount Web App(s)" -ForegroundColor Green
        Write-AuditLog "Successfully scanned $appCount Web App(s) in $($Subscription.Name)" -Level Success
    }
    catch {
        Write-AuditLog "Azure API error while scanning Web Apps in $($Subscription.Name): $($_.Exception.Message)" -Level Error
        Write-Host "  [ERROR] Error scanning Web Apps in this subscription (API error)" -ForegroundColor Red
    }
    
    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        AppCount          = $appCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-KeyVault.ps1
# Key Vault audit module
# ============================================================================

function Test-KeyVaultSecurity {
    <#
    .SYNOPSIS
        Voert security checks uit op een enkele Key Vault
    
    .DESCRIPTION
        Controleert Key Vault configuratie tegen OWASP Top 10 en Azure best practices:
        
        CRITICAL CHECKS:
        - Soft Delete enabled (OWASP A01: Data protection)
        - Purge Protection enabled (OWASP A01: Prevent permanent data loss)
        - Public network access (OWASP A01: Network exposure)
        
        HIGH/MEDIUM CHECKS:
        - Firewall configuration (OWASP A05: Security Misconfiguration)
        - RBAC vs Access Policies (OWASP A01: Access control - MKB QUICK WIN!)
        - Diagnostic logging (OWASP A09: Logging and Monitoring)
    
    .PARAMETER KeyVault
        Het KeyVault object van Get-AzKeyVault
    
    .OUTPUTS
        PSCustomObject met Issues en Severity
    
    .EXAMPLE
        $result = Test-KeyVaultSecurity -KeyVault $vault
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$KeyVault
    )
    
    $issues = @()
    $severity = "Low"
    
    # ========================================================================
    # CRITICAL CHECKS (Data Protection)
    # ========================================================================
    
    # Check 1: Soft Delete Protection (OWASP A01: Broken Access Control / Data Loss Prevention)
    # Soft Delete allows recovery of deleted vaults and secrets within retention period
    if (-not $KeyVault.EnableSoftDelete) {
        $issues += "Soft Delete DISABLED - deleted secrets cannot be recovered (critical data loss risk)"
        $severity = "Critical"
    }
    
    # Check 2: Purge Protection (OWASP A01: Prevent Permanent Data Loss)
    # Purge Protection prevents immediate permanent deletion during soft-delete period
    if ($KeyVault.EnableSoftDelete -and -not $KeyVault.EnablePurgeProtection) {
        $issues += "Purge Protection DISABLED - secrets can be permanently deleted during retention period"
        if ($severity -ne "Critical") { $severity = "High" }
    }
    
    # ========================================================================
    # HIGH CHECKS (Network Security)
    # ========================================================================
    
    # Check 3: Public Network Access (OWASP A01: Broken Access Control)
    # Key Vaults should use Private Endpoints to limit network exposure
    $publicNetworkAccess = $KeyVault.PublicNetworkAccess
    
    if ($publicNetworkAccess -eq "Enabled" -or -not $publicNetworkAccess) {
        # Check if firewall rules are configured (mitigation)
        $networkAcls = $KeyVault.NetworkAcls
        
        if (-not $networkAcls -or $networkAcls.DefaultAction -ne "Deny") {
            $issues += "Public network access enabled without firewall restrictions (unrestricted internet exposure)"
            if ($severity -eq "Low") { $severity = "High" }
        }
        else {
            # Firewall configured but still publicly accessible
            $issues += "Public network access enabled (consider Private Endpoint for zero-trust architecture)"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
    }
    
    # ========================================================================
    # MEDIUM CHECKS (Access Control & Monitoring)
    # ========================================================================
    
    # Check 4: Firewall Configuration Details (OWASP A05: Security Misconfiguration)
    if ($networkAcls) {
        $allowedIPs = if ($networkAcls.IpAddressRanges) { $networkAcls.IpAddressRanges.Count } else { 0 }
        $allowedVNets = if ($networkAcls.VirtualNetworkResourceIds) { $networkAcls.VirtualNetworkResourceIds.Count } else { 0 }
        
        if ($networkAcls.DefaultAction -eq "Allow") {
            $issues += "Firewall default action is 'Allow' (should be 'Deny' with explicit allow rules)"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
        else {
            # Default Deny is good - informational message about rules
            if ($allowedIPs -eq 0 -and $allowedVNets -eq 0) {
                # No firewall rules with Deny default = completely locked down
                # This might be intentional with Private Endpoint
            }
        }
    }
    
    # Check 5: RBAC Permission Model (OWASP A01: Access Control - MKB QUICK WIN!)
    # Azure RBAC is preferred over legacy Access Policies for better security
    # RBAC provides: Granular permissions, Azure AD integration, Better audit trails
    $rbacEnabled = $KeyVault.EnableRbacAuthorization
    
    if (-not $rbacEnabled) {
        $issues += "Legacy Access Policies in use (QUICK WIN: migrate to Azure RBAC for better security and audit trails)"
        
        # This is a Quick Win for MKB - elevate to Medium severity
        if ($severity -eq "Low") { $severity = "Medium" }
    }
    
    # Check 6: Diagnostic Logging (OWASP A09: Security Logging and Monitoring Failures)
    # Note: Diagnostic settings are not part of Get-AzKeyVault output
    # We'll document this as a recommendation
    # Actual check would require: Get-AzDiagnosticSetting -ResourceId $KeyVault.ResourceId
    
    return [PSCustomObject]@{
        Issues   = $issues
        Severity = $severity
        Config   = @{
            # Data Protection
            SoftDeleteEnabled       = $KeyVault.EnableSoftDelete
            PurgeProtectionEnabled  = $KeyVault.EnablePurgeProtection
            SoftDeleteRetentionDays = $KeyVault.SoftDeleteRetentionInDays
            
            # Network Security
            PublicNetworkAccess     = if ($publicNetworkAccess) { $publicNetworkAccess } else { "Enabled (default)" }
            FirewallDefaultAction   = if ($networkAcls) { $networkAcls.DefaultAction } else { "Allow (no firewall)" }
            FirewallIPRules         = if ($networkAcls -and $networkAcls.IpAddressRanges) { $networkAcls.IpAddressRanges.Count } else { 0 }
            FirewallVNetRules       = if ($networkAcls -and $networkAcls.VirtualNetworkResourceIds) { $networkAcls.VirtualNetworkResourceIds.Count } else { 0 }
            
            # Access Control
            RBACEnabled             = $rbacEnabled
            
            # Metadata
            SKU                     = $KeyVault.Sku
            Location                = $KeyVault.Location
        }
    }
}

function Get-KeyVaultFindings {
    <#
    .SYNOPSIS
        Scant alle Key Vaults in een subscription
    
    .DESCRIPTION
        Haalt alle Key Vaults op in de huidige Azure context (subscription)
        en voert security checks uit. Genereert anonieme findings met Random GUIDs.
    
    .PARAMETER Subscription
        Het Azure Subscription object
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, VaultCount, IssuesCount
    
    .EXAMPLE
        $result = Get-KeyVaultFindings -Subscription $sub
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    $mappingData = @()
    $anonymousFindings = @()
    $vaultCount = 0
    $issuesCount = 0
    
    try {
        # Scan Key Vaults in deze subscription
        Write-AuditLog "Scanning Key Vaults in subscription: $($Subscription.Name)..." -Level Info
        $keyVaults = Get-AzKeyVault -ErrorAction Stop
        
        if (-not $keyVaults) {
            Write-Host "  [INFO] No Key Vaults found in this subscription" -ForegroundColor Gray
            Write-AuditLog "No Key Vaults found in subscription: $($Subscription.Name)" -Level Warning
            
            return @{
                MappingData       = @()
                AnonymousFindings = @()
                VaultCount        = 0
                IssuesCount       = 0
            }
        }
        
        foreach ($vault in $keyVaults) {
            try {
                $vaultCount++
                
                # Get detailed vault configuration
                # Note: Get-AzKeyVault returns basic info, but we need NetworkAcls
                $vaultDetail = Get-AzKeyVault -VaultName $vault.VaultName -ErrorAction Stop
                
                # Voer security checks uit
                $securityCheck = Test-KeyVaultSecurity -KeyVault $vaultDetail
                
                # Alleen findings bewaren als er issues zijn
                if ($securityCheck.Issues.Count -gt 0) {
                    $issuesCount++
                    
                    # Genereer Random GUID (Zero-Crypto!)
                    $randomId = (New-Guid).ToString()
                    
                    # CONFIDENTIAL MAPPING
                    $mappingEntry = [PSCustomObject]@{
                        RandomId         = $randomId
                        RealResourceName = $vault.VaultName
                        ResourceType     = "KeyVault"
                        RealSubscription = $Subscription.Name
                        RealLocation     = $vault.Location
                    }
                    $mappingData += $mappingEntry
                    
                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousEntry = [PSCustomObject]@{
                        RandomId     = $randomId
                        ResourceType = "KeyVault"
                        Location     = $vault.Location
                        Issues       = $securityCheck.Issues
                        Severity     = $securityCheck.Severity
                        Details      = $securityCheck.Config
                    }
                    $anonymousFindings += $anonymousEntry
                    
                    Write-AuditLog "Security issue(s) found in KeyVault $($vault.VaultName): $($securityCheck.Issues -join ', ')" -Level Warning
                }
                
                # Console output (alleen bij issues of niet-quiet mode)
                if (-not $script:QuietMode -or $securityCheck.Issues.Count -gt 0) {
                    $status = if ($securityCheck.Issues.Count -gt 0) { "[!] UNSAFE" } else { "[OK] SAFE" }
                    $statusColor = if ($securityCheck.Issues.Count -gt 0) { 'Yellow' } else { 'Green' }
                    
                    Write-Host "  $status $($vault.VaultName) (Location: $($vault.Location))" -ForegroundColor $statusColor
                    
                    if ($securityCheck.Issues.Count -gt 0) {
                        foreach ($issue in $securityCheck.Issues) {
                            Write-Host "           - [!] $issue" -ForegroundColor Yellow
                        }
                        Write-Host "           - Random ID: $randomId" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-AuditLog "Error processing Key Vault $($vault.VaultName): $($_.Exception.Message)" -Level Error
                continue
            }
        }
        
        Write-Host "  [OK] Scanned $vaultCount Key Vault(s)" -ForegroundColor Green
        Write-AuditLog "Successfully scanned $vaultCount Key Vault(s) in $($Subscription.Name)" -Level Success
    }
    catch {
        Write-AuditLog "Azure API error while scanning Key Vaults in $($Subscription.Name): $($_.Exception.Message)" -Level Error
        Write-Host "  [ERROR] Error scanning Key Vaults in this subscription (API error)" -ForegroundColor Red
    }
    
    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        VaultCount        = $vaultCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-SqlServer.ps1
# SQL Server audit module
# ============================================================================

function Test-SqlServerSecurity {
    <#
    .SYNOPSIS
        Voert security checks uit op een enkele SQL Server
    
    .DESCRIPTION
        Controleert SQL Server configuratie tegen OWASP Top 10 en Azure best practices:
        
        CRITICAL CHECKS:
        - Public network access (OWASP A01: Broken Access Control)
        - TLS/SSL enforcement (OWASP A02: Cryptographic Failures)
        - Azure AD authentication (OWASP A07: Authentication Failures)
        
        HIGH/MEDIUM CHECKS:
        - Firewall configuration (OWASP A05: Security Misconfiguration)
        - Microsoft Defender for SQL (OWASP A09: Security Logging)
        - Transparent Data Encryption - TDE (OWASP A02: Cryptographic Failures)
        - Audit logging (OWASP A09: Security Logging and Monitoring)
    
    .PARAMETER SqlServer
        Het SQL Server object van Get-AzSqlServer
    
    .OUTPUTS
        PSCustomObject met Issues en Severity
    
    .EXAMPLE
        $result = Test-SqlServerSecurity -SqlServer $server
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$SqlServer
    )
    
    $issues = @()
    $severity = "Low"
    
    # ========================================================================
    # CRITICAL CHECKS (Network & Authentication)
    # ========================================================================
    
    # Check 1: Public Network Access (OWASP A01: Broken Access Control)
    # SQL Servers should use Private Endpoints or strict firewall rules
    $publicNetworkAccess = $SqlServer.PublicNetworkAccess
    
    if ($publicNetworkAccess -eq "Enabled" -or -not $publicNetworkAccess) {
        # SQL Server is publicly accessible - check firewall mitigation
        try {
            $firewallRules = Get-AzSqlServerFirewallRule -ServerName $SqlServer.ServerName -ResourceGroupName $SqlServer.ResourceGroupName -ErrorAction SilentlyContinue
            
            # Check for "Allow All" rule (0.0.0.0 - 255.255.255.255)
            $allowAllRule = $firewallRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "255.255.255.255" }
            
            if ($allowAllRule) {
                $issues += "Public network access with 'Allow All IPs' firewall rule (unrestricted internet exposure)"
                $severity = "Critical"
            }
            elseif (-not $firewallRules -or $firewallRules.Count -eq 0) {
                # No firewall rules but public access enabled - likely Private Endpoint or misconfiguration
                $issues += "Public network access enabled without firewall rules (verify Private Endpoint configuration)"
                if ($severity -eq "Low") { $severity = "Medium" }
            }
            else {
                # Has firewall rules but still public
                $issues += "Public network access enabled (consider Private Endpoint for zero-trust architecture)"
                if ($severity -eq "Low") { $severity = "Medium" }
            }
        }
        catch {
            Write-AuditLog "Unable to retrieve firewall rules for SQL Server $($SqlServer.ServerName): $($_.Exception.Message)" -Level Warning
        }
    }
    
    # Check 2: TLS/SSL Minimum Version (OWASP A02: Cryptographic Failures)
    # TLS 1.2 is minimum for secure database connections
    $minTlsVersion = $SqlServer.MinimalTlsVersion
    
    if (-not $minTlsVersion -or $minTlsVersion -lt "1.2") {
        $tlsValue = if ($minTlsVersion) { $minTlsVersion } else { "Not Set (allows TLS 1.0/1.1)" }
        $issues += "Insecure TLS version: $tlsValue (required: 1.2 or higher)"
        
        if ($severity -ne "Critical") { $severity = "High" }
    }
    
    # Check 3: Azure AD Authentication (OWASP A07: Authentication Failures)
    # Azure AD provides MFA and Conditional Access capabilities
    $hasAzureADAdmin = $false
    
    try {
        $azureADAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $SqlServer.ServerName -ResourceGroupName $SqlServer.ResourceGroupName -ErrorAction SilentlyContinue
        
        if ($azureADAdmin) {
            $hasAzureADAdmin = $true
        }
        else {
            $issues += "Azure AD authentication not configured (SQL auth only - no MFA support)"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
    }
    catch {
        Write-AuditLog "Unable to check Azure AD admin for SQL Server $($SqlServer.ServerName): $($_.Exception.Message)" -Level Warning
    }
    
    # ========================================================================
    # HIGH/MEDIUM CHECKS (Security Features)
    # ========================================================================
    
    # Check 4: Microsoft Defender for SQL (OWASP A09: Security Logging and Monitoring)
    # Advanced Threat Protection for SQL databases
    try {
        $defenderSettings = Get-AzSqlServerAdvancedThreatProtectionSetting -ServerName $SqlServer.ServerName -ResourceGroupName $SqlServer.ResourceGroupName -ErrorAction SilentlyContinue
        
        if (-not $defenderSettings -or $defenderSettings.ThreatDetectionState -ne "Enabled") {
            $issues += "Microsoft Defender for SQL disabled (no advanced threat detection)"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
    }
    catch {
        # Defender might not be available in all SKUs
        Write-AuditLog "Unable to check Defender for SQL on server $($SqlServer.ServerName): $($_.Exception.Message)" -Level Warning
    }
    
    # Check 5: Audit Logging (OWASP A09: Security Logging and Monitoring Failures)
    try {
        $auditSettings = Get-AzSqlServerAudit -ServerName $SqlServer.ServerName -ResourceGroupName $SqlServer.ResourceGroupName -ErrorAction SilentlyContinue
        
        if (-not $auditSettings -or $auditSettings.BlobStorageTargetState -ne "Enabled" -and $auditSettings.EventHubTargetState -ne "Enabled" -and $auditSettings.LogAnalyticsTargetState -ne "Enabled") {
            $issues += "SQL Server auditing not configured (no audit trail for security events)"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
    }
    catch {
        Write-AuditLog "Unable to check audit settings for SQL Server $($SqlServer.ServerName): $($_.Exception.Message)" -Level Warning
    }
    
    # Check 6: Firewall Rule Count (Informational for overly permissive configurations)
    try {
        $firewallRules = Get-AzSqlServerFirewallRule -ServerName $SqlServer.ServerName -ResourceGroupName $SqlServer.ResourceGroupName -ErrorAction SilentlyContinue
        $firewallRuleCount = if ($firewallRules) { $firewallRules.Count } else { 0 }
        
        # Note: High firewall rule count might indicate overly complex or permissive setup
        # But this is informational, not necessarily a security issue
    }
    catch {
        $firewallRuleCount = 0
    }
    
    return [PSCustomObject]@{
        Issues   = $issues
        Severity = $severity
        Config   = @{
            # Network Security
            PublicNetworkAccess  = if ($publicNetworkAccess) { $publicNetworkAccess } else { "Enabled (default)" }
            FirewallRuleCount    = $firewallRuleCount
            
            # Encryption & Authentication
            MinimalTlsVersion    = if ($minTlsVersion) { $minTlsVersion } else { "Not Set" }
            AzureADAuthEnabled   = $hasAzureADAdmin
            
            # Security Features
            DefenderEnabled      = if ($defenderSettings) { $defenderSettings.ThreatDetectionState } else { "Unknown" }
            AuditingEnabled      = if ($auditSettings) { 
                ($auditSettings.BlobStorageTargetState -eq "Enabled" -or 
                 $auditSettings.EventHubTargetState -eq "Enabled" -or 
                 $auditSettings.LogAnalyticsTargetState -eq "Enabled")
            } else { $false }
            
            # Metadata
            ServerVersion        = $SqlServer.ServerVersion
            Location             = $SqlServer.Location
        }
    }
}

function Get-SqlServerFindings {
    <#
    .SYNOPSIS
        Scant alle SQL Servers in een subscription
    
    .DESCRIPTION
        Haalt alle SQL Servers op in de huidige Azure context (subscription)
        en voert security checks uit. Genereert anonieme findings met Random GUIDs.
    
    .PARAMETER Subscription
        Het Azure Subscription object
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, ServerCount, IssuesCount
    
    .EXAMPLE
        $result = Get-SqlServerFindings -Subscription $sub
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    $mappingData = @()
    $anonymousFindings = @()
    $serverCount = 0
    $issuesCount = 0
    
    try {
        # Scan SQL Servers in deze subscription
        Write-AuditLog "Scanning SQL Servers in subscription: $($Subscription.Name)..." -Level Info
        $sqlServers = Get-AzSqlServer -ErrorAction Stop
        
        if (-not $sqlServers) {
            Write-Host "  [INFO] No SQL Servers found in this subscription" -ForegroundColor Gray
            Write-AuditLog "No SQL Servers found in subscription: $($Subscription.Name)" -Level Warning
            
            return @{
                MappingData       = @()
                AnonymousFindings = @()
                ServerCount       = 0
                IssuesCount       = 0
            }
        }
        
        foreach ($server in $sqlServers) {
            try {
                $serverCount++
                
                # Voer security checks uit
                $securityCheck = Test-SqlServerSecurity -SqlServer $server
                
                # Alleen findings bewaren als er issues zijn
                if ($securityCheck.Issues.Count -gt 0) {
                    $issuesCount++
                    
                    # Genereer Random GUID (Zero-Crypto!)
                    $randomId = (New-Guid).ToString()
                    
                    # CONFIDENTIAL MAPPING
                    $mappingEntry = [PSCustomObject]@{
                        RandomId         = $randomId
                        RealResourceName = $server.ServerName
                        ResourceType     = "SqlServer"
                        RealSubscription = $Subscription.Name
                        RealLocation     = $server.Location
                    }
                    $mappingData += $mappingEntry
                    
                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousEntry = [PSCustomObject]@{
                        RandomId     = $randomId
                        ResourceType = "SqlServer"
                        Location     = $server.Location
                        Issues       = $securityCheck.Issues
                        Severity     = $securityCheck.Severity
                        Details      = $securityCheck.Config
                    }
                    $anonymousFindings += $anonymousEntry
                    
                    Write-AuditLog "Security issue(s) found in SQL Server $($server.ServerName): $($securityCheck.Issues -join ', ')" -Level Warning
                }
                
                # Console output (alleen bij issues of niet-quiet mode)
                if (-not $script:QuietMode -or $securityCheck.Issues.Count -gt 0) {
                    $status = if ($securityCheck.Issues.Count -gt 0) { "[!] UNSAFE" } else { "[OK] SAFE" }
                    $statusColor = if ($securityCheck.Issues.Count -gt 0) { 'Yellow' } else { 'Green' }
                    
                    Write-Host "  $status $($server.ServerName) (Location: $($server.Location))" -ForegroundColor $statusColor
                    
                    if ($securityCheck.Issues.Count -gt 0) {
                        foreach ($issue in $securityCheck.Issues) {
                            Write-Host "           - [!] $issue" -ForegroundColor Yellow
                        }
                        Write-Host "           - Random ID: $randomId" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-AuditLog "Error processing SQL Server $($server.ServerName): $($_.Exception.Message)" -Level Error
                continue
            }
        }
        
        Write-Host "  [OK] Scanned $serverCount SQL Server(s)" -ForegroundColor Green
        Write-AuditLog "Successfully scanned $serverCount SQL Server(s) in $($Subscription.Name)" -Level Success
    }
    catch {
        Write-AuditLog "Azure API error while scanning SQL Servers in $($Subscription.Name): $($_.Exception.Message)" -Level Error
        Write-Host "  [ERROR] Error scanning SQL Servers in this subscription (API error)" -ForegroundColor Red
    }
    
    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        ServerCount       = $serverCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-NetworkSecurityGroup.ps1
# Network Security Group audit module
# ============================================================================

function Test-NetworkSecurityGroupRules {
    <#
    .SYNOPSIS
        Voert security checks uit op een enkele NSG
    
    .DESCRIPTION
        Controleert NSG rules tegen OWASP Top 10 en Azure best practices:
        
        CRITICAL CHECKS:
        - RDP (3389) open naar internet (OWASP A01 + A05: Broken Access Control)
        - SSH (22) open naar internet (OWASP A01 + A05: Broken Access Control)
        - Database poorten open naar internet (OWASP A01: Data exposure)
        
        HIGH CHECKS:
        - Management poorten (WinRM, PowerShell Remoting)
        - Overly permissive source IP ranges
        - "Allow All" rules
    
    .PARAMETER NSG
        Het NSG object van Get-AzNetworkSecurityGroup
    
    .OUTPUTS
        PSCustomObject met Issues en Severity
    
    .EXAMPLE
        $result = Test-NetworkSecurityGroupRules -NSG $nsg
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$NSG
    )
    
    $issues = @()
    $severity = "Low"
    $dangerousRules = @()
    
    # Dangerous ports mapping (port -> description)
    $criticalPorts = @{
        3389 = "RDP (Remote Desktop)"
        22   = "SSH (Secure Shell)"
    }
    
    $highRiskPorts = @{
        1433 = "SQL Server"
        3306 = "MySQL"
        5432 = "PostgreSQL"
        27017 = "MongoDB"
        6379 = "Redis"
        5985 = "WinRM HTTP"
        5986 = "WinRM HTTPS"
    }
    
    # ========================================================================
    # CRITICAL CHECKS (Management Port Exposure to Internet)
    # ========================================================================
    
    foreach ($rule in $NSG.SecurityRules) {
        # Only check inbound Allow rules
        if ($rule.Direction -ne "Inbound" -or $rule.Access -ne "Allow") {
            continue
        }
        
        # Check if source is internet (0.0.0.0/0, *, Internet, Any)
        $isInternetSource = $false
        
        if ($rule.SourceAddressPrefix) {
            $source = $rule.SourceAddressPrefix
            if ($source -in @("*", "Internet", "0.0.0.0/0", "0.0.0.0", "<nw>/0", "Any")) {
                $isInternetSource = $true
            }
        }
        
        # Also check SourceAddressPrefixes (array)
        if ($rule.SourceAddressPrefixes) {
            foreach ($source in $rule.SourceAddressPrefixes) {
                if ($source -in @("*", "Internet", "0.0.0.0/0", "0.0.0.0", "<nw>/0", "Any")) {
                    $isInternetSource = $true
                    break
                }
            }
        }
        
        if (-not $isInternetSource) {
            continue
        }
        
        # Get destination ports
        $destPorts = @()
        if ($rule.DestinationPortRange) {
            if ($rule.DestinationPortRange -eq "*") {
                $destPorts += "ALL"
            }
            else {
                $destPorts += $rule.DestinationPortRange
            }
        }
        
        if ($rule.DestinationPortRanges) {
            $destPorts += $rule.DestinationPortRanges
        }
        
        # Check for dangerous ports
        foreach ($port in $destPorts) {
            # Check for "ALL ports" rule
            if ($port -eq "*" -or $port -eq "ALL") {
                $issues += "CRITICAL: Rule '$($rule.Name)' allows ALL ports from Internet (priority: $($rule.Priority))"
                $severity = "Critical"
                $dangerousRules += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Port = "ALL"
                    Protocol = $rule.Protocol
                    Priority = $rule.Priority
                    Risk = "Critical"
                }
                continue
            }
            
            # Check critical management ports (RDP, SSH)
            foreach ($criticalPort in $criticalPorts.Keys) {
                if ($port -eq $criticalPort.ToString() -or $port -match "^$criticalPort-") {
                    $portDesc = $criticalPorts[$criticalPort]
                    $issues += "CRITICAL: Rule '$($rule.Name)' allows $portDesc (port $criticalPort) from Internet (common attack vector)"
                    $severity = "Critical"
                    $dangerousRules += [PSCustomObject]@{
                        RuleName = $rule.Name
                        Port = $criticalPort
                        Protocol = $rule.Protocol
                        Priority = $rule.Priority
                        Risk = "Critical"
                    }
                }
            }
            
            # Check high-risk database/service ports
            foreach ($highPort in $highRiskPorts.Keys) {
                if ($port -eq $highPort.ToString() -or $port -match "^$highPort-") {
                    $portDesc = $highRiskPorts[$highPort]
                    $issues += "HIGH RISK: Rule '$($rule.Name)' allows $portDesc (port $highPort) from Internet (data exposure risk)"
                    if ($severity -ne "Critical") { $severity = "High" }
                    $dangerousRules += [PSCustomObject]@{
                        RuleName = $rule.Name
                        Port = $highPort
                        Protocol = $rule.Protocol
                        Priority = $rule.Priority
                        Risk = "High"
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # MEDIUM/LOW CHECKS (Informational)
    # ========================================================================
    
    # Check for overly permissive CIDR ranges (informational)
    $broadRanges = 0
    foreach ($rule in $NSG.SecurityRules) {
        if ($rule.Direction -ne "Inbound" -or $rule.Access -ne "Allow") {
            continue
        }
        
        # Check for broad CIDR ranges (e.g., /8, /16 from public IPs)
        if ($rule.SourceAddressPrefix -and $rule.SourceAddressPrefix -match '/([0-9]+)$') {
            $cidr = [int]$matches[1]
            if ($cidr -le 16) {
                $broadRanges++
            }
        }
    }
    
    if ($broadRanges -gt 0 -and $severity -eq "Low") {
        # Only mention if no critical issues found
        # This is informational, not a blocking issue
    }
    
    return [PSCustomObject]@{
        Issues   = $issues
        Severity = $severity
        Config   = @{
            # Rule Statistics
            TotalRules          = $NSG.SecurityRules.Count
            InboundAllowRules   = ($NSG.SecurityRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" }).Count
            DangerousRulesCount = $dangerousRules.Count
            DangerousRules      = $dangerousRules
            
            # Metadata
            Location            = $NSG.Location
            ResourceGroup       = $NSG.ResourceGroupName
        }
    }
}

function Get-NetworkSecurityGroupFindings {
    <#
    .SYNOPSIS
        Scant alle Network Security Groups in een subscription
    
    .DESCRIPTION
        Haalt alle NSGs op in de huidige Azure context (subscription)
        en voert security checks uit. Genereert anonieme findings met Random GUIDs.
    
    .PARAMETER Subscription
        Het Azure Subscription object
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, NSGCount, IssuesCount
    
    .EXAMPLE
        $result = Get-NetworkSecurityGroupFindings -Subscription $sub
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    $mappingData = @()
    $anonymousFindings = @()
    $nsgCount = 0
    $issuesCount = 0
    
    try {
        # Scan NSGs in deze subscription
        Write-AuditLog "Scanning Network Security Groups in subscription: $($Subscription.Name)..." -Level Info
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop
        
        if (-not $nsgs) {
            Write-Host "  [INFO] No Network Security Groups found in this subscription" -ForegroundColor Gray
            Write-AuditLog "No NSGs found in subscription: $($Subscription.Name)" -Level Warning
            
            return @{
                MappingData       = @()
                AnonymousFindings = @()
                NSGCount          = 0
                IssuesCount       = 0
            }
        }
        
        foreach ($nsg in $nsgs) {
            try {
                $nsgCount++
                
                # Voer security checks uit
                $securityCheck = Test-NetworkSecurityGroupRules -NSG $nsg
                
                # Alleen findings bewaren als er issues zijn
                if ($securityCheck.Issues.Count -gt 0) {
                    $issuesCount++
                    
                    # Genereer Random GUID (Zero-Crypto!)
                    $randomId = (New-Guid).ToString()
                    
                    # CONFIDENTIAL MAPPING
                    $mappingEntry = [PSCustomObject]@{
                        RandomId         = $randomId
                        RealResourceName = $nsg.Name
                        ResourceType     = "NetworkSecurityGroup"
                        RealSubscription = $Subscription.Name
                        RealLocation     = $nsg.Location
                    }
                    $mappingData += $mappingEntry
                    
                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousEntry = [PSCustomObject]@{
                        RandomId     = $randomId
                        ResourceType = "NetworkSecurityGroup"
                        Location     = $nsg.Location
                        Issues       = $securityCheck.Issues
                        Severity     = $securityCheck.Severity
                        Details      = $securityCheck.Config
                    }
                    $anonymousFindings += $anonymousEntry
                    
                    Write-AuditLog "Security issue(s) found in NSG $($nsg.Name): $($securityCheck.Issues -join ', ')" -Level Warning
                }
                
                # Console output (alleen bij issues of niet-quiet mode)
                if (-not $script:QuietMode -or $securityCheck.Issues.Count -gt 0) {
                    $status = if ($securityCheck.Issues.Count -gt 0) { "[!] UNSAFE" } else { "[OK] SAFE" }
                    $statusColor = if ($securityCheck.Issues.Count -gt 0) { 'Red' } else { 'Green' }
                    
                    Write-Host "  $status $($nsg.Name) (Location: $($nsg.Location))" -ForegroundColor $statusColor
                    
                    if ($securityCheck.Issues.Count -gt 0) {
                        foreach ($issue in $securityCheck.Issues) {
                            Write-Host "           - [!] $issue" -ForegroundColor Red
                        }
                        Write-Host "           - Random ID: $randomId" -ForegroundColor Gray
                    }
                }
            }
            catch {
                Write-AuditLog "Error processing NSG $($nsg.Name): $($_.Exception.Message)" -Level Error
                continue
            }
        }
        
        Write-Host "  [OK] Scanned $nsgCount Network Security Group(s)" -ForegroundColor Green
        Write-AuditLog "Successfully scanned $nsgCount NSG(s) in $($Subscription.Name)" -Level Success
    }
    catch {
        Write-AuditLog "Azure API error while scanning NSGs in $($Subscription.Name): $($_.Exception.Message)" -Level Error
        Write-Host "  [ERROR] Error scanning NSGs in this subscription (API error)" -ForegroundColor Red
    }
    
    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        NSGCount          = $nsgCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-Monitoring.ps1
# Monitoring and Logging audit module
# ============================================================================

function Get-ExpectedLogCategories {
    <#
    .SYNOPSIS
        Retourneert verwachte kritieke log categorieÃ«n per resource type
    
    .DESCRIPTION
        Definieert welke log categorieÃ«n essentieel zijn voor security monitoring
        per Azure resource type. Gebaseerd op compliance vereisten (GDPR, NIS2).
    
    .PARAMETER ResourceType
        Azure resource type (bijv. Microsoft.KeyVault/vaults)
    
    .OUTPUTS
        String array met verwachte log categorieÃ«n
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceType
    )
    
    switch ($ResourceType) {
        "Microsoft.KeyVault/vaults" {
            # Secret access tracking is compliance vereiste
            return @("AuditEvent")
        }
        
        "Microsoft.Storage/storageAccounts" {
            # Data loss/breach detectie
            return @("StorageWrite", "StorageDelete")
        }
        
        "Microsoft.Web/sites" {
            # Security events + traffic analysis
            return @("AppServiceAuditLogs", "AppServiceHTTPLogs", "AppServiceConsoleLogs")
        }
        
        "Microsoft.Sql/servers" {
            # Database access audit (compliance)
            return @("SQLSecurityAuditEvents", "DevOpsOperationsAudit")
        }
        
        default {
            # Generieke audit logs
            return @("AuditEvent", "Administrative")
        }
    }
}

function Test-ResourceMonitoring {
    <#
    .SYNOPSIS
        Controleert Diagnostic Settings voor Ã©Ã©n Azure resource
    
    .DESCRIPTION
        Voert OWASP A09 compliance checks uit op Diagnostic Settings:
        
        CRITICAL:
        - Geen enkele Diagnostic Setting geconfigureerd (geen audit trail)
        
        HIGH:
        - Logs worden niet naar Log Analytics Workspace gestuurd
        - Alleen opslag in Storage Account (niet queryable voor security analysis)
        
        MEDIUM:
        - Kritieke log categorieÃ«n niet ingeschakeld
        - Log retention < 90 dagen (GDPR/NIS2 non-compliant)
    
    .PARAMETER ResourceId
        Azure Resource ID van de te controleren resource
    
    .PARAMETER ResourceType
        Azure resource type (voor expected log categories)
    
    .PARAMETER ResourceName
        Naam van de resource (voor logging)
    
    .OUTPUTS
        PSCustomObject met Issues en Severity (of $null indien compliant)
    
    .EXAMPLE
        $check = Test-ResourceMonitoring -ResourceId $resource.ResourceId -ResourceType "Microsoft.KeyVault/vaults" -ResourceName $vault.Name
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceName
    )
    
    $issues = @()
    $severity = "Low"
    
    # ========================================================================
    # CRITICAL CHECK: Diagnostic Settings aanwezig?
    # ========================================================================
    
    try {
        $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction SilentlyContinue
    }
    catch {
        # Resource type ondersteunt mogelijk geen diagnostic settings
        Write-AuditLog -Level Info -Message "  > Resource type $ResourceType heeft geen diagnostic settings support"
        return $null
    }
    
    # Check 1: Bestaat er Ã¼berhaupt een Diagnostic Setting?
    if (-not $diagnosticSettings -or $diagnosticSettings.Count -eq 0) {
        $issues += "No Diagnostic Settings configured - no audit trail (OWASP A09 compliance violation)"
        return [PSCustomObject]@{
            Issues   = $issues
            Severity = "Critical"
        }
    }
    
    # ========================================================================
    # HIGH CHECK: Log Analytics Workspace als destination
    # ========================================================================
    
    # Check 2: Worden logs naar Log Analytics Workspace gestuurd?
    # (Storage Account alone = niet queryable voor security analysis)
    $hasLogAnalytics = $false
    foreach ($setting in $diagnosticSettings) {
        if ($setting.WorkspaceId) {
            $hasLogAnalytics = $true
            break
        }
    }
    
    if (-not $hasLogAnalytics) {
        $issues += "Logs not sent to Log Analytics Workspace - only Storage Account (not queryable for security analysis)"
        $severity = "High"
    }
    
    # ========================================================================
    # MEDIUM CHECKS: Log categorieÃ«n en retention
    # ========================================================================
    
    # Check 3: Zijn kritieke log categorieÃ«n enabled?
    $expectedCategories = Get-ExpectedLogCategories -ResourceType $ResourceType
    $allEnabledCategories = @()
    
    foreach ($setting in $diagnosticSettings) {
        $enabledLogs = $setting.Logs | Where-Object { $_.Enabled -eq $true }
        foreach ($log in $enabledLogs) {
            $allEnabledCategories += $log.Category
        }
    }
    
    $missingCategories = $expectedCategories | Where-Object { $_ -notin $allEnabledCategories }
    
    if ($missingCategories -and $missingCategories.Count -gt 0) {
        $issues += "Missing critical log categories: $($missingCategories -join ', ') (incomplete audit trail)"
        if ($severity -eq "Low") { $severity = "Medium" }
    }
    
    # Check 4: Retention policy (90 dagen voor GDPR/NIS2)
    $hasInsufficientRetention = $false
    foreach ($setting in $diagnosticSettings) {
        foreach ($log in $setting.Logs) {
            if ($log.Enabled -and $log.RetentionPolicy) {
                if ($log.RetentionPolicy.Enabled -and $log.RetentionPolicy.Days -lt 90) {
                    $hasInsufficientRetention = $true
                    break
                }
            }
        }
        if ($hasInsufficientRetention) { break }
    }
    
    if ($hasInsufficientRetention) {
        $issues += "Log retention < 90 days (GDPR/AVG and NIS2 compliance risk)"
        if ($severity -eq "Low") { $severity = "Medium" }
    }
    
    # Als geen issues, return null (compliant)
    if ($issues.Count -eq 0) {
        return $null
    }
    
    return [PSCustomObject]@{
        Issues   = $issues
        Severity = $severity
    }
}

function Get-MonitoringFindings {
    <#
    .SYNOPSIS
        Scant alle kritieke resources in een subscription op Diagnostic Settings
    
    .DESCRIPTION
        Controleert Diagnostic Settings voor:
        - Storage Accounts
        - Web Apps
        - SQL Servers
        - Key Vaults
        
        Focus op OWASP A09: Security Logging and Monitoring Failures
        Compliance met GDPR/AVG en NIS2 richtlijnen (90 dagen retention)
    
    .PARAMETER Subscription
        Azure Subscription object van Get-AzSubscription
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, MonitoredResourceCount, IssuesCount
    
    .EXAMPLE
        $result = Get-MonitoringFindings -Subscription $subscription
        Write-Host "Found $($result.IssuesCount) monitoring issues across $($result.MonitoredResourceCount) resources"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    Write-AuditLog -Level Info -Message "`n=== MONITORING AUDIT (OWASP A09: Logging Failures) ==="
    Write-AuditLog -Level Info -Message "Scanning Diagnostic Settings for critical resources...`n"
    
    $mappingData = @()
    $anonymousFindings = @()
    $totalResourceCount = 0
    $issuesCount = 0
    
    # Definieer kritieke resource types (MVP scope: 4 pilaren)
    $criticalResourceTypes = @(
        @{
            Type         = "Microsoft.Storage/storageAccounts"
            FriendlyName = "Storage Account"
        },
        @{
            Type         = "Microsoft.Web/sites"
            FriendlyName = "Web App"
        },
        @{
            Type         = "Microsoft.Sql/servers"
            FriendlyName = "SQL Server"
        },
        @{
            Type         = "Microsoft.KeyVault/vaults"
            FriendlyName = "Key Vault"
        }
    )
    
    # Scan elke resource type
    foreach ($resourceTypeInfo in $criticalResourceTypes) {
        $resourceType = $resourceTypeInfo.Type
        $friendlyName = $resourceTypeInfo.FriendlyName
        
        Write-AuditLog -Level Info -Message "Checking $friendlyName resources..."
        
        try {
            $resources = Get-AzResource -ResourceType $resourceType -ErrorAction Stop
            
            if (-not $resources -or $resources.Count -eq 0) {
                Write-AuditLog -Level Info -Message "  > No $friendlyName resources found"
                continue
            }
            
            Write-AuditLog -Level Info -Message "  > Found $($resources.Count) $friendlyName resource(s)"
            
            foreach ($resource in $resources) {
                $totalResourceCount++
                
                # Voer monitoring check uit
                $securityCheck = Test-ResourceMonitoring -ResourceId $resource.ResourceId -ResourceType $resourceType -ResourceName $resource.Name
                
                if ($securityCheck) {
                    # Issue gevonden - maak Random ID (Zero-Crypto)
                    $randomId = (New-Guid).ToString()
                    
                    # Console output (geel voor warning)
                    $severityColor = switch ($securityCheck.Severity) {
                        "Critical" { "Red" }
                        "High" { "Red" }
                        "Medium" { "Yellow" }
                        default { "Yellow" }
                    }
                    
                    Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
                    Write-Host "$($resource.Name) - " -NoNewline
                    Write-Host "[$($securityCheck.Severity)] " -ForegroundColor $severityColor -NoNewline
                    Write-Host "Monitoring issues detected"
                    
                    foreach ($issue in $securityCheck.Issues) {
                        Write-Host "      - $issue" -ForegroundColor DarkGray
                    }
                    
                    # Mapping data (confidential)
                    $mappingData += [PSCustomObject]@{
                        RandomId     = $randomId
                        ResourceName = $resource.Name
                        ResourceType = $friendlyName
                        ResourceId   = $resource.ResourceId
                        Location     = $resource.Location
                        Severity     = $securityCheck.Severity
                        Issues       = $securityCheck.Issues -join "; "
                    }
                    
                    # Anonymous findings (safe voor transmit)
                    $anonymousFindings += [PSCustomObject]@{
                        RandomId         = $randomId
                        ResourceType     = $friendlyName
                        Location         = $resource.Location
                        Severity         = $securityCheck.Severity
                        IssueCount       = $securityCheck.Issues.Count
                        Issues           = $securityCheck.Issues
                        OWASP            = "A09"
                        ComplianceImpact = "GDPR/AVG, NIS2"
                    }
                    
                    $issuesCount++
                }
                else {
                    # Compliant
                    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
                    Write-Host "$($resource.Name) - Monitoring configuration compliant"
                }
            }
        }
        catch {
            Write-AuditLog -Level Warning -Message "  > Error scanning $friendlyName resources: $($_.Exception.Message)"
        }
    }
    
    # Summary
    Write-AuditLog -Level Info -Message "`n--- Monitoring Audit Summary ---"
    Write-AuditLog -Level Info -Message "Total resources scanned: $totalResourceCount"
    Write-AuditLog -Level Info -Message "Resources with monitoring issues: $issuesCount"
    
    if ($issuesCount -gt 0) {
        Write-Host "`n[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "Action Required: Configure Diagnostic Settings to send logs to Log Analytics Workspace" -ForegroundColor Yellow
        Write-Host "    Compliance: OWASP A09, GDPR/AVG, NIS2 (90-day retention minimum)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "`n[OK] " -ForegroundColor Green -NoNewline
        Write-Host "All monitored resources have proper diagnostic settings configured"
    }
    
    return @{
        MappingData            = $mappingData
        AnonymousFindings      = $anonymousFindings
        MonitoredResourceCount = $totalResourceCount
        IssuesCount            = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-Compliance.ps1
# Defender for Cloud CSPM compliance module
# ============================================================================

# ============================================================================
# HELPER: OWASP mapping op basis van assessment naam en categorie
# ============================================================================

function Get-OWASPCategoryFromAssessment {
    <#
    .SYNOPSIS
        Mapt een Defender assessment naar de meest relevante OWASP Top 10 categorie

    .PARAMETER DisplayName
        Naam van het assessment zoals teruggegeven door Defender for Cloud

    .PARAMETER Categories
        Komma-gescheiden categorie string (bijv. "Compute, Data")

    .OUTPUTS
        String: OWASP categorie code (bijv. "A01")
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [string]$Categories = ""
    )

    $text = "$DisplayName $Categories".ToLower()

    # A01: Broken Access Control
    if ($text -match "admin|owner|rbac|permission|access control|privileged|public access|unrestricted|exposure|internet.facing") {
        return "A01"
    }
    # A02: Cryptographic Failures
    if ($text -match "encrypt|tls|ssl|https|certificate|key|secret|crypto|secure transfer") {
        return "A02"
    }
    # A06: Vulnerable and Outdated Components
    if ($text -match "vulnerabilit|patch|update|outdated|version|endpoint protection|antimalware|defender") {
        return "A06"
    }
    # A07: Identification and Authentication Failures
    if ($text -match "mfa|multi-factor|authenticat|password|credential|login|identity") {
        return "A07"
    }
    # A09: Security Logging and Monitoring Failures
    if ($text -match "log|monitor|audit|diagnos|threat|alert|siem") {
        return "A09"
    }
    # A05: Security Misconfiguration (default voor CSPM bevindingen)
    return "A05"
}

# ============================================================================
# HELPER: Friendly resource type uit Azure Resource ID
# ============================================================================

function Get-FriendlyResourceType {
    <#
    .SYNOPSIS
        Extraheert een leesbaar resource type uit een Azure Resource ID
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceId = ""
    )

    if (-not $ResourceId) { return "Azure Resource" }

    if ($ResourceId -match "/providers/[^/]+/([^/]+)/") {
        $typeKey = $Matches[1].ToLower()

        $friendlyMap = @{
            "virtualmachines"       = "Virtual Machine"
            "storageaccounts"       = "Storage Account"
            "sites"                 = "Web App"
            "vaults"                = "Key Vault"
            "servers"               = "SQL Server"
            "networkinterfaces"     = "Network Interface"
            "publicipaddresses"     = "Public IP"
            "virtualnetworks"       = "Virtual Network"
            "networksecuritygroups" = "NSG"
            "sqlpools"              = "SQL Pool"
            "databaseaccounts"      = "Cosmos DB"
            "workspaces"            = "Log Analytics"
            "clusters"              = "AKS Cluster"
            "registries"            = "Container Registry"
            "namespaces"            = "Service Bus / Event Hub"
            "accounts"              = "Cognitive / Batch Account"
        }

        if ($friendlyMap.ContainsKey($typeKey)) {
            return $friendlyMap[$typeKey]
        }

        # Fallback: zet camelCase om naar leesbare tekst
        return ($Matches[1] -creplace '([A-Z])', ' $1').Trim()
    }

    return "Azure Resource"
}

# ============================================================================
# HELPER: Compliance framework detectie
# ============================================================================

function Get-ComplianceFrameworks {
    <#
    .SYNOPSIS
        Heuristisch: bepaalt aan welke compliance frameworks een assessment gerelateerd is

    .DESCRIPTION
        Gebaseerd op Defender category en display name keywords.
        Terugkerende mapping in MCSB / NIS2 / ISO 27001 (geen directe API per assessment).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$DisplayName = "",
        [string]$Categories  = ""
    )

    $frameworks = [System.Collections.Generic.List[string]]::new()
    $text = "$DisplayName $Categories".ToLower()

    # MCSB is altijd van toepassing (Microsoft Cloud Security Benchmark)
    $frameworks.Add("MCSB")

    # NIS2: netwerk, identity, logging (operationele weerbaarheid)
    if ($text -match "network|firewall|access|identity|log|monitor|backup|incident|resilience|patch") {
        $frameworks.Add("NIS2")
    }

    # ISO 27001: brede security controls
    if ($text -match "encrypt|access|audit|asset|risk|physical|backup|continuity|incident|policy") {
        $frameworks.Add("ISO 27001")
    }

    return $frameworks -join ", "
}

# ============================================================================
# MAIN: Get-ComplianceFindings
# ============================================================================

function Get-ComplianceFindings {
    <#
    .SYNOPSIS
        Scant Defender for Cloud assessments en compliance scores voor een subscription

    .DESCRIPTION
        Twee databronnen worden gecombineerd:

        1. ASSESSMENTS (resource-level):
           Get-AzSecurityAssessment -> filter Unhealthy -> map OWASP + compliance
           Gecapped op de 50 meest kritieke bevindingen om output beheersbaar te houden.

        2. REGULATORY COMPLIANCE SCORES (subscription-level):
           Get-AzSecurityRegulatoryComplianceStandard -> per standaard score
           Geeft een compliance % per framework (NIS2, ISO 27001, ASB, MCSB).

        Beide secties hebben graceful degradation.

    .PARAMETER Subscription
        Azure Subscription object van Get-AzSubscription

    .OUTPUTS
        Hashtable:
        - MappingData          : confidential resource details
        - AnonymousFindings     : privacy-safe payload voor de backend
        - AssessmentCount       : totaal unhealthy assessments gevonden
        - IssuesCount           : totaal findings (assessments + compliance scores)

    .EXAMPLE
        $result = Get-ComplianceFindings -Subscription $subscription
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )

    Write-AuditLog -Level Info -Message "`n=== COMPLIANCE AUDIT (Defender for Cloud / CSPM) ==="
    Write-AuditLog -Level Info -Message "Scanning security assessments and regulatory compliance scores...`n"

    $mappingData      = @()
    $anonymousFindings = @()
    $assessmentCount  = 0
    $issuesCount      = 0

    # -------------------------------------------------------------------------
    # PRE-CHECK: Is Az.Security module beschikbaar?
    # -------------------------------------------------------------------------

    $securityModuleAvailable = Get-Module -ListAvailable -Name "Az.Security" -ErrorAction SilentlyContinue

    if (-not $securityModuleAvailable) {
        Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
        Write-Host "Compliance audit skipped - Az.Security module not installed"
        Write-Host "         Install with: Install-Module Az.Security -Scope CurrentUser" -ForegroundColor DarkGray
        Write-AuditLog -Level Info -Message "Az.Security module not available - compliance audit skipped"

        return @{
            MappingData       = @()
            AnonymousFindings = @()
            AssessmentCount   = 0
            IssuesCount       = 0
        }
    }

    # =========================================================================
    # SECTIE 0: PRICING TIER CHECK (Foundational vs. Defender CSPM)
    # =========================================================================

    Write-AuditLog -Level Info -Message "Checking Defender for Cloud pricing tier (CloudPosture)..."

    try {
        $cloudPosturePricing = Get-AzSecurityPricing -Name "CloudPosture" -ErrorAction Stop

        $pricingTier = if ($cloudPosturePricing.PricingTier) { $cloudPosturePricing.PricingTier } else { "Free" }

        if ($pricingTier -eq "Standard") {
            # Betaald Defender CSPM plan actief
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline
            Write-Host "Defender CSPM: Standard plan active (~`$5/resource/month)"
            Write-Host "       Attack Path Analysis, NIS2/ISO 27001 compliance tracking enabled" -ForegroundColor DarkGray
            Write-AuditLog -Level Info -Message "Defender CSPM: Standard (paid) plan active"
        }
        else {
            # Foundational CSPM (gratis) â€” genereer finding
            $randomId = (New-Guid).ToString()
            $issuesCount++

            $issueText       = "Foundational CSPM (Free) in gebruik. Geavanceerde compliance tracking voor NIS2/ISO en Attack Path Analysis zijn uitgeschakeld."
            $recommendText   = "Upgrade naar Defender CSPM voor volledige ondersteuning van de Microsoft Cloud Security Benchmark en NIS2-compliance."

            Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
            Write-Host "[Medium] " -ForegroundColor Yellow -NoNewline
            Write-Host "Defender for Cloud: Foundational CSPM (Free plan)"
            Write-Host "      - $issueText" -ForegroundColor DarkGray
            Write-Host "      - Recommendation: $recommendText" -ForegroundColor DarkGray
            Write-AuditLog -Level Info -Message "Defender CSPM: Free (Foundational) plan detected"

            # CONFIDENTIAL MAPPING
            $mappingData += [PSCustomObject]@{
                RandomId             = $randomId
                RealResourceId       = "/subscriptions/$($Subscription.Id)/providers/Microsoft.Security/pricings/CloudPosture"
                RealResourceType     = "Defender CSPM Plan"
                RealAssessmentName   = "Foundational CSPM (Free) detected"
                RealSubscriptionName = $Subscription.Name
                Severity             = "Medium"
                DefenderSeverity     = "Medium"
                StatusDescription    = $recommendText
                ComplianceFrameworks = "NIS2, ISO 27001, MCSB"
            }

            # SAFE ANONYMOUS PAYLOAD
            $anonymousFindings += [PSCustomObject]@{
                RandomId             = $randomId
                ResourceType         = "Defender CSPM Plan"
                Location             = "Global"
                Severity             = "Medium"
                Issues               = @($issueText)
                OWASP                = "A05"
                ComplianceFrameworks = "NIS2, ISO 27001, MCSB"
                DefenderCategory     = "Pricing"
                PricingTier          = $pricingTier
                Recommendation       = $recommendText
            }
        }
    }
    catch {
        # Geen rechten of pricing API niet beschikbaar - non-fatal
        Write-AuditLog -Level Warning -Message "Pricing tier check skipped (non-fatal): $($_.Exception.Message)"
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
        Write-Host "Pricing tier check skipped (insufficient permissions or API unavailable)"
    }

    # =========================================================================
    # SECTIE 1: UNHEALTHY ASSESSMENTS
    # =========================================================================

    Write-AuditLog -Level Info -Message "Fetching unhealthy security assessments..."

    try {
        $allAssessments = Get-AzSecurityAssessment -ErrorAction Stop

        if (-not $allAssessments -or $allAssessments.Count -eq 0) {
            Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
            Write-Host "No assessments returned - Defender for Cloud (CSPM) may not be enabled"
            Write-Host "         Enable via: Azure Portal > Defender for Cloud > Environment Settings" -ForegroundColor DarkGray
            Write-AuditLog -Level Info -Message "No assessments returned - Defender for Cloud possibly not active"
        }
        else {
            # Filter op unhealthy
            $unhealthyAssessments = $allAssessments | Where-Object {
                $_.Status.Code -eq "Unhealthy"
            }

            if ($unhealthyAssessments) {
                # Sorteer: High eerst, dan Medium, dan Low
                $severityOrder = @{ "High" = 1; "Medium" = 2; "Low" = 3 }

                $sortedAssessments = $unhealthyAssessments | Sort-Object {
                    $s = $_.Metadata.Severity
                    if ($severityOrder.ContainsKey($s)) { $severityOrder[$s] } else { 4 }
                }

                # Cap op 50 meest kritieke bevindingen (performance + output beheersbaar)
                $assessmentsToProcess = $sortedAssessments | Select-Object -First 50

                Write-AuditLog -Level Info -Message "  > Found $($unhealthyAssessments.Count) unhealthy assessment(s) - processing top $($assessmentsToProcess.Count)"

                foreach ($assessment in $assessmentsToProcess) {
                    $assessmentCount++

                    # Defensief: properties kunnen null zijn
                    $displayName    = if ($assessment.DisplayName)            { $assessment.DisplayName }            else { "Unknown Assessment" }
                    $defenderSev    = if ($assessment.Metadata.Severity)      { $assessment.Metadata.Severity }      else { "Low" }
                    $categoriesRaw  = if ($assessment.Metadata.Categories)    { $assessment.Metadata.Categories }    else { @() }
                    $resourceId     = if ($assessment.ResourceDetails.Id)     { $assessment.ResourceDetails.Id }     else { "" }
                    $statusDesc     = if ($assessment.Status.Description)     { $assessment.Status.Description }     else { "" }

                    # Severity doorvertalen naar Catching Moles niveaus
                    $severity = switch ($defenderSev) {
                        "High"   { "High" }
                        "Medium" { "Medium" }
                        "Low"    { "Low" }
                        default  { "Low" }
                    }

                    # Category als string
                    $categoriesStr = ($categoriesRaw -join ", ")

                    # OWASP mapping
                    $owaspCategory = Get-OWASPCategoryFromAssessment -DisplayName $displayName -Categories $categoriesStr

                    # Compliance frameworks (heuristisch)
                    $complianceFrameworks = Get-ComplianceFrameworks -DisplayName $displayName -Categories $categoriesStr

                    # Resource type (privacy-safe)
                    $resourceTypeFriendly = Get-FriendlyResourceType -ResourceId $resourceId

                    # Privacy-safe resource ID suffix (laatste 8 tekens = geen volledige PII)
                    $resourceIdSuffix = if ($resourceId.Length -ge 8) {
                        $resourceId.Substring($resourceId.Length - 8)
                    } else { "unknown" }

                    # Random GUID (Zero-Crypto)
                    $randomId = (New-Guid).ToString()
                    $issuesCount++

                    # Console output
                    $severityColor = switch ($severity) {
                        "High"   { "Red" }
                        "Medium" { "Yellow" }
                        default  { "DarkYellow" }
                    }

                    Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
                    Write-Host "$resourceTypeFriendly - " -NoNewline
                    Write-Host "[$severity] " -ForegroundColor $severityColor -NoNewline
                    Write-Host "$displayName"

                    if ($statusDesc) {
                        Write-Host "      - $statusDesc" -ForegroundColor DarkGray
                    }

                    # CONFIDENTIAL MAPPING (bevat echte resource ID)
                    $mappingData += [PSCustomObject]@{
                        RandomId             = $randomId
                        RealResourceId       = $resourceId
                        RealResourceType     = $resourceTypeFriendly
                        RealAssessmentName   = $displayName
                        RealSubscriptionName = $Subscription.Name
                        Severity             = $severity
                        DefenderSeverity     = $defenderSev
                        StatusDescription    = $statusDesc
                        ComplianceFrameworks = $complianceFrameworks
                    }

                    # SAFE ANONYMOUS PAYLOAD
                    $anonymousFindings += [PSCustomObject]@{
                        RandomId             = $randomId
                        ResourceType         = $resourceTypeFriendly
                        Location             = "Global"
                        Severity             = $severity
                        Issues               = @($displayName)
                        OWASP                = $owaspCategory
                        ComplianceFrameworks = $complianceFrameworks
                        DefenderCategory     = $categoriesStr
                        ResourceIdSuffix     = $resourceIdSuffix  # Privacy-safe (geen volledige ID)
                    }
                }

                Write-Host ""
                Write-AuditLog -Level Info -Message "Assessment scan complete: $assessmentCount unhealthy findings processed"
            }
            else {
                Write-Host "  [OK] " -ForegroundColor Green -NoNewline
                Write-Host "No unhealthy security assessments found - security posture is clean"
                Write-AuditLog -Level Info -Message "No unhealthy assessments found"
            }
        }
    }
    catch {
        Write-AuditLog -Level Warning -Message "Assessment scan failed (non-fatal): $($_.Exception.Message)"
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
        Write-Host "Assessment scan skipped: $($_.Exception.Message)"
    }

    # =========================================================================
    # SECTIE 2: REGULATORY COMPLIANCE SCORES
    # =========================================================================

    Write-AuditLog -Level Info -Message "Fetching regulatory compliance scores..."

    # Standaarden die we willen rapporteren (flexibele matching)
    $targetStandards = @(
        @{ Match = "nis2";                                  Name = "NIS2" }
        @{ Match = "iso-27001|iso27001";                    Name = "ISO 27001" }
        @{ Match = "mcsb|microsoft-cloud-security";         Name = "MCSB" }
        @{ Match = "azure-security-benchmark|asb-v|asb$";   Name = "Azure Security Benchmark" }
        @{ Match = "cis-azure|azure-cis";                   Name = "CIS Azure" }
    )

    try {
        $complianceStandards = Get-AzSecurityRegulatoryComplianceStandard -ErrorAction Stop

        if ($complianceStandards -and $complianceStandards.Count -gt 0) {
            Write-AuditLog -Level Info -Message "  > Found $($complianceStandards.Count) compliance standard(s)"

            foreach ($target in $targetStandards) {
                $matched = $complianceStandards | Where-Object { $_.Name -match $target.Match }

                foreach ($standard in $matched) {
                    $passed  = [int]($standard.PassedControls)
                    $failed  = [int]($standard.FailedControls)
                    $skipped = [int]($standard.SkippedControls)
                    $total   = $passed + $failed

                    if ($total -eq 0) { continue }

                    $failedPct = [math]::Round(($failed / $total) * 100)
                    $passedPct = 100 - $failedPct

                    # Severity op basis van compliance percentage
                    $compSeverity = if ($failedPct -gt 50) { "High" }
                                    elseif ($failedPct -gt 25) { "Medium" }
                                    else { "Low" }

                    $complianceName = $target.Name
                    $scoreText      = "$passedPct% compliant ($passed/$total controls passed, $failed failed)"

                    # Alleen rapporteren als er failed controls zijn
                    if ($failed -gt 0) {
                        $randomId = (New-Guid).ToString()
                        $issuesCount++

                        $severityColor = switch ($compSeverity) {
                            "High"   { "Red" }
                            "Medium" { "Yellow" }
                            default  { "DarkYellow" }
                        }

                        Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
                        Write-Host "Compliance Score - " -NoNewline
                        Write-Host "[$compSeverity] " -ForegroundColor $severityColor -NoNewline
                        Write-Host "$complianceName : $scoreText"

                        # CONFIDENTIAL MAPPING
                        $mappingData += [PSCustomObject]@{
                            RandomId             = $randomId
                            RealResourceId       = "/subscriptions/$($Subscription.Id)"
                            RealResourceType     = "Compliance Score"
                            RealAssessmentName   = "$complianceName - $scoreText"
                            RealSubscriptionName = $Subscription.Name
                            Severity             = $compSeverity
                            DefenderSeverity     = $compSeverity
                            StatusDescription    = "$failed controls failed out of $total"
                            ComplianceFrameworks = $complianceName
                        }

                        # SAFE ANONYMOUS PAYLOAD
                        $anonymousFindings += [PSCustomObject]@{
                            RandomId             = $randomId
                            ResourceType         = "Compliance Score"
                            Location             = "Global"
                            Severity             = $compSeverity
                            Issues               = @("$complianceName : $scoreText")
                            OWASP                = "A05"
                            ComplianceFrameworks = $complianceName
                            DefenderCategory     = "Regulatory Compliance"
                            PassedControls       = $passed
                            FailedControls       = $failed
                            TotalControls        = $total
                            CompliancePercentage = $passedPct
                        }
                    }
                    else {
                        Write-Host "  [OK] " -ForegroundColor Green -NoNewline
                        Write-Host "Compliance Score - $complianceName : $scoreText"
                    }
                }
            }
        }
        else {
            Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
            Write-Host "No regulatory compliance standards found (Defender CSPM plan may not be active)"
            Write-AuditLog -Level Info -Message "No compliance standards returned by Defender"
        }
    }
    catch {
        Write-AuditLog -Level Warning -Message "Regulatory compliance score scan failed (non-fatal): $($_.Exception.Message)"
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
        Write-Host "Compliance score scan skipped: $($_.Exception.Message)"
    }

    # =========================================================================
    # SUMMARY
    # =========================================================================

    Write-AuditLog -Level Info -Message "`n--- Compliance Audit Summary ---"
    Write-AuditLog -Level Info -Message "Unhealthy assessments processed : $assessmentCount"
    Write-AuditLog -Level Info -Message "Total findings (incl. scores)   : $issuesCount"

    if ($issuesCount -gt 0) {
        Write-Host "`n[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "Action Required: Review Defender for Cloud recommendations" -ForegroundColor Yellow
        Write-Host "    Portal: https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade" -ForegroundColor DarkGray
        Write-Host "    Compliance: OWASP A05, NIS2, ISO 27001, MCSB" -ForegroundColor DarkGray
    }
    else {
        Write-Host "`n[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Defender for Cloud: no critical findings or compliance violations"
    }

    return @{
        MappingData       = $mappingData
        AnonymousFindings = $anonymousFindings
        AssessmentCount   = $assessmentCount
        IssuesCount       = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-RBAC.ps1
# RBAC audit module (God-mode detection)
# ============================================================================

function Test-SubscriptionRBAC {
    <#
    .SYNOPSIS
        Voert RBAC security checks uit op Ã©Ã©n subscription
    
    .DESCRIPTION
        Controleert role assignments tegen privilege escalation best practices:
        
        CRITICAL:
        - Owner role sprawl (>2-3 assignments = security risk)
        - Wildcard scope assignments (/* = dangerous)
        
        HIGH:
        - Contributor role assignments (breed access monitoring)
        - Service Principal Owner/Contributor roles (automation met te veel rechten)
        
        MEDIUM:
        - Custom roles met wildcard permissions (Actions contains *)
    
    .PARAMETER SubscriptionId
        Azure Subscription ID voor RBAC scan
    
    .OUTPUTS
        PSCustomObject met Issues, Severity, OwnerCount, ContributorCount
    
    .EXAMPLE
        $result = Test-SubscriptionRBAC -SubscriptionId $subscription.Id
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    $issues = @()
    $severity = "Low"
    $ownerAssignments = @()
    $contributorAssignments = @()
    $wildcardAssignments = @()
    $servicePrincipalPrivileged = @()
    
    try {
        # Get all role assignments for this subscription
        $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop
        
        if (-not $roleAssignments -or $roleAssignments.Count -eq 0) {
            Write-AuditLog "No role assignments found (unusual)" -Level Warning
            return [PSCustomObject]@{
                Issues = @()
                Severity = "Low"
                OwnerCount = 0
                ContributorCount = 0
                TotalAssignments = 0
            }
        }
        
        # ========================================================================
        # CRITICAL CHECK: Owner Role Sprawl (OWASP A01)
        # ========================================================================
        
        # Owner is God-mode in Azure - should be limited to 2-3 break-glass accounts
        $owners = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }
        
        if ($owners) {
            $ownerCount = ($owners | Measure-Object).Count
            
            # Store for anonymous payload (ObjectId only - no PII)
            foreach ($owner in $owners) {
                $ownerAssignments += @{
                    ObjectId = $owner.ObjectId
                    ObjectType = $owner.ObjectType  # User, Group, ServicePrincipal
                    Scope = $owner.Scope
                }
            }
            
            # Severity based on Microsoft best practices (2026)
            if ($ownerCount -gt 5) {
                $issues += "Excessive Owner assignments: $ownerCount principals (critical sprawl - recommended: 2-3)"
                $severity = "Critical"
            }
            elseif ($ownerCount -gt 2) {
                $issues += "High Owner count: $ownerCount principals (recommended: 2-3 for break-glass scenarios)"
                if ($severity -eq "Low") { $severity = "High" }
            }
        }
        
        # ========================================================================
        # HIGH CHECK: Contributor Role Monitoring
        # ========================================================================
        
        # Contributor = full access minus RBAC changes (still very broad)
        $contributors = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" }
        
        if ($contributors) {
            $contributorCount = ($contributors | Measure-Object).Count
            
            foreach ($contributor in $contributors) {
                $contributorAssignments += @{
                    ObjectId = $contributor.ObjectId
                    ObjectType = $contributor.ObjectType
                    Scope = $contributor.Scope
                }
            }
            
            # Warn if excessive (MKB best practice)
            if ($contributorCount -gt 10) {
                $issues += "High Contributor count: $contributorCount principals (consider least-privilege alternatives)"
                if ($severity -eq "Low") { $severity = "Medium" }
            }
        }
        
        # ========================================================================
        # CRITICAL CHECK: Wildcard Scope Assignments
        # ========================================================================
        
        # Assignments at root scope (/) = ALL subscriptions in tenant
        $wildcardScopes = $roleAssignments | Where-Object { $_.Scope -match "^/$|^/\*$" }
        
        if ($wildcardScopes) {
            foreach ($wildcard in $wildcardScopes) {
                $wildcardAssignments += @{
                    RoleName = $wildcard.RoleDefinitionName
                    ObjectId = $wildcard.ObjectId
                    ObjectType = $wildcard.ObjectType
                }
            }
            
            $issues += "Wildcard scope assignments detected: $($wildcardScopes.Count) role(s) at root (/) scope (tenant-wide access)"
            $severity = "Critical"
        }
        
        # ========================================================================
        # HIGH CHECK: Service Principal Privilege Escalation
        # ========================================================================
        
        # Service Principals (automation accounts) with Owner/Contributor = high risk if compromised
        $spOwners = $owners | Where-Object { $_.ObjectType -eq "ServicePrincipal" }
        $spContributors = $contributors | Where-Object { $_.ObjectType -eq "ServicePrincipal" }
        
        if ($spOwners -or $spContributors) {
            $spPrivilegedCount = ($spOwners | Measure-Object).Count + ($spContributors | Measure-Object).Count
            
            foreach ($sp in $spOwners) {
                $servicePrincipalPrivileged += @{
                    ObjectId = $sp.ObjectId
                    Role = "Owner"
                }
            }
            foreach ($sp in $spContributors) {
                $servicePrincipalPrivileged += @{
                    ObjectId = $sp.ObjectId
                    Role = "Contributor"
                }
            }
            
            $issues += "Service Principals with Owner/Contributor: $spPrivilegedCount (automation privilege escalation risk)"
            if ($severity -eq "Low") { $severity = "High" }
        }
        
        # ========================================================================
        # MEDIUM CHECK: Custom Roles with Wildcard Permissions
        # ========================================================================
        
        # Custom roles with Actions = "*" bypass least-privilege principle
        $customRoles = $roleAssignments | Where-Object { 
            $_.RoleDefinitionName -notmatch "^(Owner|Contributor|Reader|.*Administrator)$" 
        }
        
        if ($customRoles) {
            $customRoleCount = ($customRoles | Measure-Object).Count
            
            # Note: We can't check Actions without Get-AzRoleDefinition per role (performance hit)
            # Flag for manual review instead
            if ($customRoleCount -gt 5) {
                $issues += "Custom role assignments detected: $customRoleCount (review for wildcard permissions)"
                if ($severity -eq "Low") { $severity = "Medium" }
            }
        }
        
    }
    catch {
        Write-AuditLog "Error scanning RBAC assignments: $($_.Exception.Message)" -Level Error
        return [PSCustomObject]@{
            Issues = @("RBAC scan failed: $($_.Exception.Message)")
            Severity = "Unknown"
            OwnerCount = 0
            ContributorCount = 0
            TotalAssignments = 0
        }
    }
    
    return [PSCustomObject]@{
        Issues = $issues
        Severity = $severity
        OwnerCount = ($ownerAssignments | Measure-Object).Count
        ContributorCount = ($contributorAssignments | Measure-Object).Count
        TotalAssignments = ($roleAssignments | Measure-Object).Count
        OwnerAssignments = $ownerAssignments
        ContributorAssignments = $contributorAssignments
        WildcardAssignments = $wildcardAssignments
        ServicePrincipalPrivileged = $servicePrincipalPrivileged
    }
}

function Get-RBACFindings {
    <#
    .SYNOPSIS
        Scant RBAC configuratie voor alle subscriptions
    
    .DESCRIPTION
        Voert privilege escalation checks uit op subscription-level RBAC.
        Focus op OWASP A01: Broken Access Control
        
        SECURITY FOCUS:
        - Owner/Contributor sprawl detection
        - Service Principal privilege escalation
        - Wildcard scope assignments
        
        PRIVACY BY DESIGN:
        - ObjectId only in anonymous findings (GEEN DisplayName/Email)
        - Principal names alleen in confidential mapping
    
    .PARAMETER Subscription
        Azure Subscription object van Get-AzSubscription
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, SubscriptionCount, IssuesCount
    
    .EXAMPLE
        $result = Get-RBACFindings -Subscription $subscription
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    Write-AuditLog -Level Info -Message "`n=== RBAC AUDIT (OWASP A01: God-Mode Detection) ==="
    Write-AuditLog -Level Info -Message "Scanning subscription role assignments...`n"
    
    $mappingData = @()
    $anonymousFindings = @()
    $issuesCount = 0
    
    try {
        # Voer RBAC check uit op deze subscription
        $rbacCheck = Test-SubscriptionRBAC -SubscriptionId $Subscription.Id
        
        if ($rbacCheck.Issues.Count -gt 0) {
            # Issue gevonden - maak Random ID (Zero-Crypto)
            $randomId = (New-Guid).ToString()
            $issuesCount++
            
            # Console output met severity-based coloring
            $severityColor = switch ($rbacCheck.Severity) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                default { "Yellow" }
            }
            
            Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
            Write-Host "$($Subscription.Name) - " -NoNewline
            Write-Host "[$($rbacCheck.Severity)] " -ForegroundColor $severityColor -NoNewline
            Write-Host "RBAC issues detected"
            
            foreach ($issue in $rbacCheck.Issues) {
                Write-Host "      - $issue" -ForegroundColor DarkGray
            }
            
            # CONFIDENTIAL MAPPING (with PII for internal use)
            $mappingData += [PSCustomObject]@{
                RandomId = $randomId
                SubscriptionName = $Subscription.Name
                SubscriptionId = $Subscription.Id
                Severity = $rbacCheck.Severity
                OwnerCount = $rbacCheck.OwnerCount
                ContributorCount = $rbacCheck.ContributorCount
                TotalAssignments = $rbacCheck.TotalAssignments
                Issues = $rbacCheck.Issues -join "; "
            }
            
            # SAFE ANONYMOUS PAYLOAD (ObjectId only - NO PII)
            $anonymousFindings += [PSCustomObject]@{
                RandomId = $randomId
                ResourceType = "Subscription RBAC"
                Location = "Global"  # Subscription-scoped (geen fysieke locatie)
                Severity = $rbacCheck.Severity
                IssueCount = $rbacCheck.Issues.Count
                Issues = $rbacCheck.Issues
                OwnerCount = $rbacCheck.OwnerCount
                ContributorCount = $rbacCheck.ContributorCount
                TotalAssignments = $rbacCheck.TotalAssignments
                # Privacy-safe role details (ObjectId only)
                OwnerObjectIds = $rbacCheck.OwnerAssignments | ForEach-Object { $_.ObjectId }
                ServicePrincipalPrivilegedCount = ($rbacCheck.ServicePrincipalPrivileged | Measure-Object).Count
                WildcardScopeCount = ($rbacCheck.WildcardAssignments | Measure-Object).Count
                OWASP = "A01"
                Impact = "Privilege Escalation"
            }
        }
        else {
            # Compliant
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline
            Write-Host "$($Subscription.Name) - RBAC configuration compliant"
            Write-Host "       Owners: $($rbacCheck.OwnerCount), Contributors: $($rbacCheck.ContributorCount), Total: $($rbacCheck.TotalAssignments)" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-AuditLog -Level Error -Message "Error scanning RBAC for subscription: $($_.Exception.Message)"
        Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline
        Write-Host "$($Subscription.Name) - RBAC scan failed"
    }
    
    # Summary
    Write-AuditLog -Level Info -Message "`n--- RBAC Audit Summary ---"
    Write-AuditLog -Level Info -Message "Subscription: $($Subscription.Name)"
    Write-AuditLog -Level Info -Message "RBAC issues found: $issuesCount"
    
    if ($issuesCount -gt 0) {
        Write-Host "`n[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "Action Required: Review Owner/Contributor assignments - apply least-privilege principle" -ForegroundColor Yellow
        Write-Host "    Best Practice: Max 2-3 Owners for break-glass scenarios only" -ForegroundColor DarkGray
        Write-Host "    Compliance: OWASP A01 (Broken Access Control)" -ForegroundColor DarkGray
    }
    
    return @{
        MappingData = $mappingData
        AnonymousFindings = $anonymousFindings
        SubscriptionScanned = 1
        IssuesCount = $issuesCount
    }
}


# ============================================================================
# SOURCE: modules\Audit-VNetTopology.ps1
# VNet Topology audit module (Network exposure + Cost)
# ============================================================================

function Test-PublicIPSecurity {
    <#
    .SYNOPSIS
        Controleert security configuratie van Ã©Ã©n Public IP
    
    .DESCRIPTION
        CRITICAL:
        - Orphaned Public IP (geen attached NIC/LB - attack surface + kosten)
        
        HIGH:
        - Public IP zonder NSG protection (direct exposed)
        - Public IP met oude Basic SKU (Standard = DDoS protection)
    
    .PARAMETER PublicIP
        Public IP object van Get-AzPublicIpAddress
    
    .OUTPUTS
        PSCustomObject met Issues, Severity, IsOrphaned, IPAddress (hashed)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$PublicIP
    )
    
    $issues = @()
    $severity = "Low"
    $isOrphaned = $false
    
    # ========================================================================
    # CRITICAL CHECK: Orphaned Public IP (OWASP A01 + Cost Optimization)
    # ========================================================================
    
    # Public IP without attached resource = unused attack surface + monthly cost
    if (-not $PublicIP.IpConfiguration -and -not $PublicIP.NatGateway) {
        $issues += "Orphaned Public IP - not attached to any resource (attack surface + ~$4/month waste)"
        $severity = "Critical"
        $isOrphaned = $true
    }
    
    # ========================================================================
    # HIGH CHECK: NSG Protection
    # ========================================================================
    
    # Public IP should be protected by NSG (unless it's a managed service like Azure Firewall)
    if ($PublicIP.IpConfiguration) {
        $attachedResourceType = $PublicIP.IpConfiguration.Id -replace ".*/([^/]+)/.*", '$1'
        
        # Check if attached to unprotected resource type
        if ($attachedResourceType -eq "networkInterfaces") {
            # NIC should have NSG - but we can't check from Public IP object alone
            # This is a heuristic check - actual NSG validation is in NSG module
            $issues += "Public IP attached to Network Interface - verify NSG protection"
            if ($severity -eq "Low") { $severity = "Medium" }
        }
    }
    
    # ========================================================================
    # MEDIUM CHECK: Basic SKU vs Standard
    # ========================================================================
    
    # Basic SKU lacks DDoS protection and zone redundancy
    if ($PublicIP.Sku.Name -eq "Basic") {
        $issues += "Basic SKU Public IP (no DDoS protection - upgrade to Standard recommended)"
        if ($severity -eq "Low") { $severity = "Medium" }
    }
    
    # ========================================================================
    # Privacy-Safe IP Address Hashing
    # ========================================================================
    
    # Hash last octet for anonymous payload: 20.50.100.123 â†’ 20.50.100.xxx
    $ipAddress = $PublicIP.IpAddress
    $hashedIP = if ($ipAddress) {
        $octets = $ipAddress -split '\.'
        if ($octets.Count -eq 4) {
            "$($octets[0]).$($octets[1]).$($octets[2]).xxx"
        } else {
            "IPv6-xxxxx"  # IPv6 support
        }
    } else {
        "Not-Allocated"
    }
    
    return [PSCustomObject]@{
        Issues = $issues
        Severity = $severity
        IsOrphaned = $isOrphaned
        IPAddressHashed = $hashedIP
        SKU = $PublicIP.Sku.Name
        AllocationMethod = $PublicIP.PublicIpAllocationMethod
        Location = $PublicIP.Location
    }
}

function Test-VNetPeeringSecurity {
    <#
    .SYNOPSIS
        Controleert VNet peering configuratie op isolation breaches
    
    .DESCRIPTION
        HIGH:
        - Peering tussen Dev en Prod VNets (environment isolation breach)
        - Peering met AllowGatewayTransit (network boundary violation)
    
    .PARAMETER VNet
        VNet object van Get-AzVirtualNetwork
    
    .OUTPUTS
        PSCustomObject met Issues, Severity, PeeringCount, RiskyPeerings
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$VNet
    )
    
    $issues = @()
    $severity = "Low"
    $riskyPeerings = @()
    
    if (-not $VNet.VirtualNetworkPeerings -or $VNet.VirtualNetworkPeerings.Count -eq 0) {
        # No peerings = isolated (good)
        return [PSCustomObject]@{
            Issues = @()
            Severity = "Low"
            PeeringCount = 0
            RiskyPeerings = @()
        }
    }
    
    # ========================================================================
    # HIGH CHECK: Dev-Prod Isolation Breach
    # ========================================================================
    
    # Heuristic: Detect environment names in VNet names
    $vnetName = $VNet.Name.ToLower()
    $currentEnv = $null
    
    if ($vnetName -match "prod|production|prd") {
        $currentEnv = "Production"
    }
    elseif ($vnetName -match "dev|development|test|tst|acc|acceptance") {
        $currentEnv = "Non-Production"
    }
    
    if ($currentEnv) {
        foreach ($peering in $VNet.VirtualNetworkPeerings) {
            # Extract remote VNet name from ID
            $remoteVNetName = ($peering.RemoteVirtualNetwork.Id -split '/')[-1].ToLower()
            
            # Check for environment mismatch
            if ($currentEnv -eq "Production" -and $remoteVNetName -match "dev|development|test|tst|acc") {
                $riskyPeerings += @{
                    Type = "Dev-Prod Isolation Breach"
                    RemoteVNet = "Dev/Test environment"
                    Status = $peering.PeeringState
                }
                $issues += "Production VNet peered with Dev/Test environment (isolation breach - security risk)"
                if ($severity -eq "Low") { $severity = "High" }
            }
            elseif ($currentEnv -eq "Non-Production" -and $remoteVNetName -match "prod|production|prd") {
                $riskyPeerings += @{
                    Type = "Dev-Prod Isolation Breach"
                    RemoteVNet = "Production environment"
                    Status = $peering.PeeringState
                }
                $issues += "Dev/Test VNet peered with Production (isolation breach - data leakage risk)"
                if ($severity -eq "Low") { $severity = "High" }
            }
        }
    }
    
    # ========================================================================
    # MEDIUM CHECK: Gateway Transit Permissions
    # ========================================================================
    
    # AllowGatewayTransit = allows remote VNet to use local VPN/ExpressRoute
    $gatewayTransitPeerings = $VNet.VirtualNetworkPeerings | Where-Object { 
        $_.AllowGatewayTransit -eq $true 
    }
    
    if ($gatewayTransitPeerings) {
        $issues += "VNet peering with Gateway Transit enabled: $($gatewayTransitPeerings.Count) peering(s) (review network boundary)"
        if ($severity -eq "Low") { $severity = "Medium" }
    }
    
    return [PSCustomObject]@{
        Issues = $issues
        Severity = $severity
        PeeringCount = $VNet.VirtualNetworkPeerings.Count
        RiskyPeerings = $riskyPeerings
    }
}

function Get-VNetTopologyFindings {
    <#
    .SYNOPSIS
        Scant VNet topology en Public IPs voor alle subscriptions
    
    .DESCRIPTION
        Voert network topology security checks uit:
        - Orphaned Public IPs (attack surface + cost waste)
        - Public IPs zonder NSG protection
        - VNet peerings tussen Dev/Prod
        
        PRIVACY BY DESIGN:
        - Public IP addresses hashed (last octet replaced with xxx)
        - Random GUID voor resource mappings
    
    .PARAMETER Subscription
        Azure Subscription object van Get-AzSubscription
    
    .OUTPUTS
        Hashtable met MappingData, AnonymousFindings, ResourceCount, IssuesCount
    
    .EXAMPLE
        $result = Get-VNetTopologyFindings -Subscription $subscription
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Subscription
    )
    
    Write-AuditLog -Level Info -Message "`n=== VNET TOPOLOGY AUDIT (Network Exposure + Cost Optimization) ==="
    Write-AuditLog -Level Info -Message "Scanning Public IPs and VNet peerings...`n"
    
    $mappingData = @()
    $anonymousFindings = @()
    $totalResourceCount = 0
    $issuesCount = 0
    
    # ========================================================================
    # SCAN 1: Public IP Addresses
    # ========================================================================
    
    Write-AuditLog -Level Info -Message "Checking Public IP addresses..."
    
    try {
        $publicIPs = Get-AzPublicIpAddress -ErrorAction Stop
        
        if ($publicIPs -and $publicIPs.Count -gt 0) {
            Write-AuditLog -Level Info -Message "  > Found $($publicIPs.Count) Public IP(s)"
            
            foreach ($pip in $publicIPs) {
                $totalResourceCount++
                
                # Voer security check uit
                $pipCheck = Test-PublicIPSecurity -PublicIP $pip
                
                if ($pipCheck.Issues.Count -gt 0) {
                    # Issue gevonden
                    $randomId = (New-Guid).ToString()
                    $issuesCount++
                    
                    # Console output met severity coloring
                    $severityColor = switch ($pipCheck.Severity) {
                        "Critical" { "Red" }
                        "High" { "Red" }
                        "Medium" { "Yellow" }
                        default { "Yellow" }
                    }
                    
                    Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
                    Write-Host "$($pip.Name) - " -NoNewline
                    Write-Host "[$($pipCheck.Severity)] " -ForegroundColor $severityColor -NoNewline
                    
                    if ($pipCheck.IsOrphaned) {
                        Write-Host "ORPHANED (Cost Saving Opportunity!)" -ForegroundColor Magenta
                        Write-Host "      [COST] Delete to save ~$4/month" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "Security issue detected"
                    }
                    
                    foreach ($issue in $pipCheck.Issues) {
                        Write-Host "      - $issue" -ForegroundColor DarkGray
                    }
                    
                    # CONFIDENTIAL MAPPING
                    $mappingData += [PSCustomObject]@{
                        RandomId = $randomId
                        ResourceName = $pip.Name
                        ResourceType = "Public IP"
                        ResourceId = $pip.Id
                        Location = $pip.Location
                        IPAddress = $pip.IpAddress  # Real IP in mapping (confidential)
                        Severity = $pipCheck.Severity
                        Issues = $pipCheck.Issues -join "; "
                    }
                    
                    # SAFE ANONYMOUS PAYLOAD (IP hashed)
                    $anonymousFindings += [PSCustomObject]@{
                        RandomId = $randomId
                        ResourceType = "Public IP"
                        Severity = $pipCheck.Severity
                        IssueCount = $pipCheck.Issues.Count
                        Issues = $pipCheck.Issues
                        IsOrphaned = $pipCheck.IsOrphaned
                        IPAddressHashed = $pipCheck.IPAddressHashed  # Privacy-safe
                        SKU = $pipCheck.SKU
                        AllocationMethod = $pipCheck.AllocationMethod
                        Location = $pipCheck.Location
                        OWASP = "A01+A05"
                        CostImpact = if ($pipCheck.IsOrphaned) { "~$4/month" } else { "N/A" }
                    }
                }
                else {
                    # Compliant
                    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
                    Write-Host "$($pip.Name) - Public IP configuration compliant"
                }
            }
        }
        else {
            Write-AuditLog -Level Info -Message "  > No Public IPs found"
        }
    }
    catch {
        Write-AuditLog -Level Error -Message "Error scanning Public IPs: $($_.Exception.Message)"
    }
    
    # ========================================================================
    # SCAN 2: Virtual Network Peerings
    # ========================================================================
    
    Write-AuditLog -Level Info -Message "`nChecking VNet peerings..."
    
    try {
        $vnets = Get-AzVirtualNetwork -ErrorAction Stop
        
        if ($vnets -and $vnets.Count -gt 0) {
            Write-AuditLog -Level Info -Message "  > Found $($vnets.Count) VNet(s)"
            
            foreach ($vnet in $vnets) {
                # Only check VNets with peerings
                if ($vnet.VirtualNetworkPeerings -and $vnet.VirtualNetworkPeerings.Count -gt 0) {
                    $totalResourceCount++
                    
                    # Voer peering security check uit
                    $peeringCheck = Test-VNetPeeringSecurity -VNet $vnet
                    
                    if ($peeringCheck.Issues.Count -gt 0) {
                        # Issue gevonden
                        $randomId = (New-Guid).ToString()
                        $issuesCount++
                        
                        $severityColor = if ($peeringCheck.Severity -eq "High") { "Red" } else { "Yellow" }
                        
                        Write-Host "  [!] " -ForegroundColor $severityColor -NoNewline
                        Write-Host "$($vnet.Name) - " -NoNewline
                        Write-Host "[$($peeringCheck.Severity)] " -ForegroundColor $severityColor -NoNewline
                        Write-Host "VNet peering issues"
                        
                        foreach ($issue in $peeringCheck.Issues) {
                            Write-Host "      - $issue" -ForegroundColor DarkGray
                        }
                        
                        # CONFIDENTIAL MAPPING
                        $mappingData += [PSCustomObject]@{
                            RandomId = $randomId
                            ResourceName = $vnet.Name
                            ResourceType = "VNet Peering"
                            ResourceId = $vnet.Id
                            Location = $vnet.Location
                            Severity = $peeringCheck.Severity
                            PeeringCount = $peeringCheck.PeeringCount
                            Issues = $peeringCheck.Issues -join "; "
                        }
                        
                        # SAFE ANONYMOUS PAYLOAD (no VNet names)
                        $anonymousFindings += [PSCustomObject]@{
                            RandomId = $randomId
                            ResourceType = "VNet Peering"
                            Severity = $peeringCheck.Severity
                            IssueCount = $peeringCheck.Issues.Count
                            Issues = $peeringCheck.Issues
                            PeeringCount = $peeringCheck.PeeringCount
                            RiskyPeeringTypes = $peeringCheck.RiskyPeerings | ForEach-Object { $_.Type }
                            Location = $vnet.Location
                            OWASP = "A01"
                            Impact = "Environment Isolation Breach"
                        }
                    }
                    else {
                        Write-Host "  [OK] " -ForegroundColor Green -NoNewline
                        Write-Host "$($vnet.Name) - VNet peering configuration compliant ($($peeringCheck.PeeringCount) peering(s))"
                    }
                }
            }
        }
        else {
            Write-AuditLog -Level Info -Message "  > No VNets found"
        }
    }
    catch {
        Write-AuditLog -Level Error -Message "Error scanning VNets: $($_.Exception.Message)"
    }
    
    # Summary
    Write-AuditLog -Level Info -Message "`n--- VNet Topology Summary ---"
    Write-AuditLog -Level Info -Message "Resources scanned: $totalResourceCount"
    Write-AuditLog -Level Info -Message "Issues found: $issuesCount"
    
    if ($issuesCount -gt 0) {
        Write-Host "`n[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "Action Required: Review network topology and remove orphaned resources" -ForegroundColor Yellow
        Write-Host "    Cost Impact: Orphaned Public IPs waste ~$4/month each" -ForegroundColor Cyan
        Write-Host "    Security: Dev-Prod peerings create data leakage risks" -ForegroundColor DarkGray
    }
    
    return @{
        MappingData = $mappingData
        AnonymousFindings = $anonymousFindings
        ResourceCount = $totalResourceCount
        IssuesCount = $issuesCount
    }
}


# ============================================================================
# SOURCE: Invoke-CatchingMoles.ps1
# Orchestrator / Controller
# ============================================================================

# ============================================================================
# ORCHESTRATOR - MAIN EXECUTION
# ============================================================================

try {
    # Set global quiet mode flag
    $script:QuietMode = $QuietMode.IsPresent
    
    # Detect Cloud Shell and enable quiet mode automatically
    if ((Test-CloudShellEnvironment) -and -not $script:QuietMode) {
        Write-Host "INFO: Cloud Shell detected - enabling Quiet Mode" -ForegroundColor Cyan
        $script:QuietMode = $true
    }
    
    Write-Host "`n[Catching Moles Security Auditor v2.0.0]" -ForegroundColor Cyan
    Write-Host "Architecture: Zero-Crypto / Random ID" -ForegroundColor Gray
    Write-Host ""
    
    # ========================================================================
    # PHASE 1: INFRASTRUCTURE VALIDATION
    # ========================================================================
    
    # 1. Check Azure PowerShell module
    Write-AuditLog "Checking Azure PowerShell module..." -Level Info
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "ERROR: Az.Accounts module not found!" -ForegroundColor Red
        Write-Host "   Install with: Install-Module -Name Az -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
    
    # 2. Check Azure authentication
    Write-AuditLog "Checking Azure authentication..." -Level Info
    $context = Get-AzContext -ErrorAction SilentlyContinue
    
    if (-not $context) {
        Write-Host "WARNING: Not logged in to Azure!" -ForegroundColor Yellow
        
        if (Test-CloudShellEnvironment) {
            Write-Host "ERROR: Cloud Shell detected but no Azure context found." -ForegroundColor Red
            Write-Host "   This is unexpected. Try restarting Cloud Shell." -ForegroundColor Yellow
            exit 1
        }
        else {
            Write-Host "   Automatic login not possible in script mode." -ForegroundColor Yellow
            Write-Host "   Please login first with: Connect-AzAccount" -ForegroundColor Yellow
            exit 1
        }
    }
    
    Write-AuditLog "Authenticated as: $($context.Account.Id)" -Level Success
    
    # 3. Get all subscriptions
    Write-AuditLog "Retrieving subscriptions..." -Level Info
    $subscriptions = Get-AzSubscription
    
    if (-not $subscriptions) {
        Write-Host "ERROR: No Azure subscriptions found!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`nTENANT-WIDE SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host "Total Subscriptions: $($subscriptions.Count)" -ForegroundColor White
    
    if ($EnableComplianceCheck.IsPresent -and $AllowedRegions.Count -gt 0) {
        Write-Host "Compliance Check: ENABLED" -ForegroundColor Green
        Write-Host "Allowed Regions: $($AllowedRegions -join ', ')" -ForegroundColor White
    }
    else {
        Write-Host "Compliance Check: DISABLED (location auditable only)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # ========================================================================
    # PHASE 2: AGGREGATE RESULTS INITIALIZATION
    # ========================================================================
    
    $allMappingData = @()
    $allAnonymousFindings = @()
    $totalAccountCount = 0
    $totalIssuesCount = 0
    
    # ========================================================================
    # PHASE 3: SUBSCRIPTION ORCHESTRATION LOOP
    # ========================================================================
    
    Write-Host "[SUBSCRIPTION-SCOPED] Resource Security Audits" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Gray
    
    $subIndex = 0
    foreach ($subscription in $subscriptions) {
        $subIndex++
        
        try {
            Write-Host "[$subIndex/$($subscriptions.Count)] Subscription: $($subscription.Name)" -ForegroundColor White
            Write-Host "            Subscription ID: $($subscription.Id)" -ForegroundColor Gray
            Write-AuditLog "Auditing subscription $subIndex/$($subscriptions.Count): $($subscription.Name)" -Level Info
            
            # Set context to this subscription
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Storage Account Security
            # ----------------------------------------------------------------
            $subResult = Get-StorageAccountFindings -Subscription $subscription -EnableCompliance $EnableComplianceCheck.IsPresent -AllowedRegions $AllowedRegions
            
            # Aggregate Storage results
            $allMappingData += $subResult.MappingData
            $allAnonymousFindings += $subResult.AnonymousFindings
            $totalAccountCount += $subResult.AccountCount
            $totalIssuesCount += $subResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Web App Security
            # ----------------------------------------------------------------
            $webAppResult = Get-WebAppFindings -Subscription $subscription
            
            # Aggregate WebApp results
            $allMappingData += $webAppResult.MappingData
            $allAnonymousFindings += $webAppResult.AnonymousFindings
            $totalAccountCount += $webAppResult.AppCount
            $totalIssuesCount += $webAppResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Key Vault Security
            # ----------------------------------------------------------------
            $keyVaultResult = Get-KeyVaultFindings -Subscription $subscription
            
            # Aggregate KeyVault results
            $allMappingData += $keyVaultResult.MappingData
            $allAnonymousFindings += $keyVaultResult.AnonymousFindings
            $totalAccountCount += $keyVaultResult.VaultCount
            $totalIssuesCount += $keyVaultResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: SQL Server Security
            # ----------------------------------------------------------------
            $sqlServerResult = Get-SqlServerFindings -Subscription $subscription
            
            # Aggregate SQL Server results
            $allMappingData += $sqlServerResult.MappingData
            $allAnonymousFindings += $sqlServerResult.AnonymousFindings
            $totalAccountCount += $sqlServerResult.ServerCount
            $totalIssuesCount += $sqlServerResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Network Security Group Security
            # ----------------------------------------------------------------
            $nsgResult = Get-NetworkSecurityGroupFindings -Subscription $subscription
            
            # Aggregate NSG results
            $allMappingData += $nsgResult.MappingData
            $allAnonymousFindings += $nsgResult.AnonymousFindings
            $totalAccountCount += $nsgResult.NSGCount
            $totalIssuesCount += $nsgResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Monitoring & Logging (OWASP A09)
            # ----------------------------------------------------------------
            $monitoringResult = Get-MonitoringFindings -Subscription $subscription
            
            # Aggregate Monitoring results
            $allMappingData += $monitoringResult.MappingData
            $allAnonymousFindings += $monitoringResult.AnonymousFindings
            $totalAccountCount += $monitoringResult.MonitoredResourceCount
            $totalIssuesCount += $monitoringResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: Compliance (Defender for Cloud CSPM)
            # ----------------------------------------------------------------
            $complianceResult = Get-ComplianceFindings -Subscription $subscription
            
            # Aggregate Compliance results
            $allMappingData += $complianceResult.MappingData
            $allAnonymousFindings += $complianceResult.AnonymousFindings
            $totalAccountCount += $complianceResult.AssessmentCount
            $totalIssuesCount += $complianceResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: RBAC (OWASP A01: God-Mode Detection)
            # ----------------------------------------------------------------
            $rbacResult = Get-RBACFindings -Subscription $subscription
            
            # Aggregate RBAC results
            $allMappingData += $rbacResult.MappingData
            $allAnonymousFindings += $rbacResult.AnonymousFindings
            $totalAccountCount += $rbacResult.SubscriptionScanned
            $totalIssuesCount += $rbacResult.IssuesCount
            
            # ----------------------------------------------------------------
            # MODULE EXECUTION: VNet Topology (Network Exposure + Cost)
            # ----------------------------------------------------------------
            $vnetResult = Get-VNetTopologyFindings -Subscription $subscription
            
            # Aggregate VNet Topology results
            $allMappingData += $vnetResult.MappingData
            $allAnonymousFindings += $vnetResult.AnonymousFindings
            $totalAccountCount += $vnetResult.ResourceCount
            $totalIssuesCount += $vnetResult.IssuesCount
        }
        catch {
            Write-AuditLog "Error processing subscription (skipping): $($_.Exception.Message)" -Level Error
            continue
        }
    }
    
    # ========================================================================
    # PHASE 4: RESULTS PROCESSING & REPORTING
    # ========================================================================
    
    Write-Host "`n--- AUDIT COMPLETE ---" -ForegroundColor Green
    Write-Host "Total Storage Accounts: $totalAccountCount" -ForegroundColor White
    Write-Host "Total Issues Found: $totalIssuesCount" -ForegroundColor White
    
    if ($totalIssuesCount -gt 0) {
        Write-Host "`nWARNING: $totalIssuesCount issue(s) found!" -ForegroundColor Yellow
        
        # Save files
        $outputDir = New-OutputDirectory
        $mappingFile = Export-MappingCSV -MappingData $allMappingData -OutputDirectory $outputDir
        $payloadFile = Export-TransmitPayload -AnonymousFindings $allAnonymousFindings -OutputDirectory $outputDir
        
        Write-Host "`nFiles created: $outputDir" -ForegroundColor Green
        
        if (Test-CloudShellEnvironment) {
            Write-Host ("`nDownload files with: download """ + $outputDir + """") -ForegroundColor Cyan
        }
        
        # ====================================================================
        # PHASE 5: OPTIONAL TRANSMISSION
        # ====================================================================
        
        if (-not $FunctionUrl) { $FunctionUrl = $env:FUNCTION_APP_URL }
        
        if ($FunctionUrl) {
            $consent = Read-Host "Transmit to Function App? (Y/N)"
            if ($consent -eq 'Y' -or $consent -eq 'y') {
                try {
                    # De ENIGE manier om PowerShell 100% te dwingen een JSON array te maken, zelfs met 1 item:
                    $json = ConvertTo-Json -InputObject @($allAnonymousFindings) -Depth 10 -Compress
                    
                    # Debug: Laat heel even in het grijs zien wat we precies sturen
                    Write-Host "  > Sending JSON: $json" -ForegroundColor DarkGray
                    
                    $response = Invoke-RestMethod -Uri $FunctionUrl -Method Post -Body $json -ContentType "application/json" -TimeoutSec 30
                    Write-Host "`nTransmitted successfully" -ForegroundColor Green
                } 
                catch {
                    # Dit blok "pakt" het Python antwoord uit de HTTP foutmelding
                    $errorMessage = $_.Exception.Message
                    
                    if ($_.ErrorDetails.Message) {
                        $errorMessage = $_.ErrorDetails.Message
                    }
                    elseif ($_.Exception.Response) {
                        $stream = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $errorMessage = $reader.ReadToEnd()
                    }
                    
                    Write-Host "`nERROR 400: Jouw Python backend zegt het volgende:" -ForegroundColor Red
                    Write-Host " $errorMessage" -ForegroundColor Yellow
                }
            }
        }
    }
    else {
        Write-Host "`nNo issues found!" -ForegroundColor Green
    }
}
catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

