<#
.SYNOPSIS
    Monitoring and Logging audit module
    
.DESCRIPTION
    Scant kritieke Azure resources op Diagnostic Settings configuratie
    Focus op OWASP A09: Security Logging and Monitoring Failures
    
    Controleert of logs worden doorgestuurd naar Log Analytics Workspace
    en of kritieke log categorieën zijn ingeschakeld met voldoende retention
#>

function Get-ExpectedLogCategories {
    <#
    .SYNOPSIS
        Retourneert verwachte kritieke log categorieën per resource type
    
    .DESCRIPTION
        Definieert welke log categorieën essentieel zijn voor security monitoring
        per Azure resource type. Gebaseerd op compliance vereisten (GDPR, NIS2).
    
    .PARAMETER ResourceType
        Azure resource type (bijv. Microsoft.KeyVault/vaults)
    
    .OUTPUTS
        String array met verwachte log categorieën
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
        Controleert Diagnostic Settings voor één Azure resource
    
    .DESCRIPTION
        Voert OWASP A09 compliance checks uit op Diagnostic Settings:
        
        CRITICAL:
        - Geen enkele Diagnostic Setting geconfigureerd (geen audit trail)
        
        HIGH:
        - Logs worden niet naar Log Analytics Workspace gestuurd
        - Alleen opslag in Storage Account (niet queryable voor security analysis)
        
        MEDIUM:
        - Kritieke log categorieën niet ingeschakeld
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
    
    # Check 1: Bestaat er überhaupt een Diagnostic Setting?
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
    # MEDIUM CHECKS: Log categorieën en retention
    # ========================================================================
    
    # Check 3: Zijn kritieke log categorieën enabled?
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
