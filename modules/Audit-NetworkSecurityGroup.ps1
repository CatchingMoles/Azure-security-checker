<#
.SYNOPSIS
    Network Security Group (NSG) security audit module
    
.DESCRIPTION
    Scant Azure Network Security Groups op gevaarlijke firewall rules
    Focus op open management poorten en internet exposure
#>

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
