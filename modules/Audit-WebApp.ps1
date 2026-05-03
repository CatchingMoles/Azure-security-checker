<#
.SYNOPSIS
    Web App security audit module
    
.DESCRIPTION
    Scant Azure Web Apps op security configuratie issues
#>

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
