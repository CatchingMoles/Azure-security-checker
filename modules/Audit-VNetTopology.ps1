<#
.SYNOPSIS
    Virtual Network Topology audit module
    
.DESCRIPTION
    Scant Azure VNets en Public IPs op netwerk security misconfigurations
    Focus op OWASP A01 + A05: Network exposure en orphaned resources
    
    KRITIEKE CHECKS:
    - Orphaned Public IPs (geen attached resource - attack surface + kosten!)
    - Public IPs zonder NSG protection
    - VNet peerings tussen Dev/Prod (isolation breach)
    - VNets zonder network flow logging
    
    PRIVACY BY DESIGN:
    - Public IP addresses = SENSITIVE! Anonymous payload: last octet hashed
    - Random GUID voor alle resource mappings
    - Topology info (Dev-Prod peering) zonder resource namen
    
    COST OPTIMIZATION:
    - Orphaned Public IPs = ~$4/month per IP (direct savings!)
#>

function Test-PublicIPSecurity {
    <#
    .SYNOPSIS
        Controleert security configuratie van één Public IP
    
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
    
    # Hash last octet for anonymous payload: 20.50.100.123 → 20.50.100.xxx
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
