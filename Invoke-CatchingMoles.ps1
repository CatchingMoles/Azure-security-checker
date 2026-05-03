<#
.SYNOPSIS
    Catching Moles Security Auditor - Orchestrator / Controller
    
.DESCRIPTION
    Multi-module orchestrator voor Azure Security Auditing.
    Beheert authenticatie, subscription loops, en aggregatie van alle module results.
    
    MVP Features:
    - Storage Account security audit (Public access, TLS, Data residency)
    - Web App security audit (HTTPS, TLS, FTP, Remote debugging, Managed Identity)
    - Key Vault security audit (Soft Delete, Purge Protection, Network access, RBAC)
    - SQL Server security audit (Public access, TLS, Azure AD auth, Defender, Auditing)
    - Network Security Group audit (Open RDP/SSH, Database ports, Internet exposure)
    - Monitoring audit (Diagnostic Settings, Log Analytics, OWASP A09 compliance)
    - RBAC audit (Owner/Contributor sprawl, God-mode detection)
    - VNet Topology audit (Orphaned Public IPs, Dev-Prod peerings, Cost optimization)
    - Compliance audit (Defender for Cloud CSPM, NIS2/ISO 27001/MCSB scores, OWASP mapping)
    - Zero-Crypto architecture (Random GUID anonymization)
    - Cloud Shell compatible
    
.PARAMETER FunctionUrl
    URL van de Azure Function endpoint voor data transmission
    
.PARAMETER EnableComplianceCheck
    Schakel data residency compliance checking in
    
.PARAMETER AllowedRegions
    Array van toegestane Azure regio's
    
.PARAMETER QuietMode
    Verminder console output (automatisch in Cloud Shell)
    
.EXAMPLE
    .\Invoke-CatchingMoles.ps1
    
.EXAMPLE
    .\Invoke-CatchingMoles.ps1 -EnableComplianceCheck -AllowedRegions @('westeurope', 'northeurope')
    
.EXAMPLE
    .\Invoke-CatchingMoles.ps1 -FunctionUrl "https://yourfunction.azurewebsites.net/api/analyze"
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

# COMPILER-MARKER: END-PARAMS

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
