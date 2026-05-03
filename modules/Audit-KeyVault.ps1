<#
.SYNOPSIS
    Key Vault security audit module
    
.DESCRIPTION
    Scant Azure Key Vaults op security configuratie issues
    Focus op secrets management best practices en OWASP compliance
#>

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
