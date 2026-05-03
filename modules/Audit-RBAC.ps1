<#
.SYNOPSIS
    RBAC (Role-Based Access Control) audit module
    
.DESCRIPTION
    Scant Azure subscription-level role assignments op privilege escalation risks
    Focus op OWASP A01: Broken Access Control - "Who has the keys to the kingdom?"
    
    KRITIEKE CHECKS:
    - Owner role sprawl (God-mode access)
    - Contributor assignments (breed access zonder delete)
    - Wildcard scope assignments (/* = alle subscriptions)
    - Service Principal privilege escalation
    
    PRIVACY BY DESIGN:
    - ObjectId ONLY in anonymous payload (geen DisplayName, geen Email)
    - Principal names alleen in confidential mapping
    - Random GUID voor alle findings
#>

function Test-SubscriptionRBAC {
    <#
    .SYNOPSIS
        Voert RBAC security checks uit op één subscription
    
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
