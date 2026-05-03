<#
.SYNOPSIS
    Storage Account Security Audit Module
    
.DESCRIPTION
    Dit module bevat alle logica voor het scannen van Azure Storage Accounts
    op security issues. Het is een zelfstandige module die kan worden aangeroepen
    door een orchestrator.
    
    Zero-Crypto architectuur: Gebruikt Random GUIDs voor anonimisatie.
#>

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
