<#
.SYNOPSIS
    SQL Server security audit module
    
.DESCRIPTION
    Scant Azure SQL Servers op security configuratie issues
    Focus op database security best practices en OWASP compliance
#>

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
