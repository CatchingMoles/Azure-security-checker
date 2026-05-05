<#
.SYNOPSIS
    Defender for Cloud Compliance audit module (CSPM)

.DESCRIPTION
    Scant Microsoft Defender for Cloud Security Posture Management (CSPM) assessments
    op unhealthy resources en regulatory compliance scores.

    Focus op:
    - OWASP A05: Security Misconfiguration (meeste CSPM bevindingen)
    - Compliance scores voor NIS2, ISO 27001, Azure Security Benchmark (ASB), MCSB

    GRACEFUL DEGRADATION:
    - Az.Security module ontbreekt  -> lege resultset, geen crash
    - Defender for Cloud niet actief -> lege resultset, informatieve melding
    - API throttling / partial errors -> partial results, script gaat door

    PRIVACY BY DESIGN:
    - Resource namen ALLEEN in confidential MappingData
    - Anonymous payload: resource type + hashed resource ID suffix
    - Random GUID per bevinding (Zero-Crypto principe)
#>

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
        [string]$Categories = ""
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

    $mappingData = @()
    $anonymousFindings = @()
    $assessmentCount = 0
    $issuesCount = 0

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
    # SECTIE 0: PRICING TIER CHECK (Feature Discovery)
    # =========================================================================

    Write-AuditLog -Level Info -Message "Checking Defender for Cloud pricing tier (CloudPosture)..."

    $isPaidPlan = $false  # Default: assume Foundational (Free) plan

    try {
        $cloudPosturePricing = Get-AzSecurityPricing -Name "CloudPosture" -ErrorAction Stop
        $pricingTier = if ($cloudPosturePricing.PricingTier) { $cloudPosturePricing.PricingTier } else { "Free" }
        $isPaidPlan = ($pricingTier -eq "Standard")

        if ($isPaidPlan) {
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline
            Write-Host "Defender CSPM: Standard plan active (~`$5/resource/month)"
            Write-Host "       Attack Path Analysis, NIS2/ISO 27001 compliance tracking enabled" -ForegroundColor DarkGray
            Write-AuditLog -Level Info -Message "Defender CSPM: Standard (paid) plan active"
        }
        else {
            Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
            Write-Host "Defender CSPM: Foundational (Free) plan detected - advanced compliance tracking will be skipped"
            Write-AuditLog -Level Info -Message "Defender CSPM: Free (Foundational) plan detected"
        }
    }
    catch {
        # Geen rechten of pricing API niet beschikbaar - non-fatal, ga door met basis-assessments
        Write-AuditLog -Level Warning -Message "Pricing tier check failed (non-fatal): $($_.Exception.Message) - assuming Free plan"
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
        Write-Host "Pricing tier check skipped (insufficient permissions) - proceeding with basic assessments"
        $isPaidPlan = $false
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
                    if ($s -and $severityOrder.ContainsKey($s)) { $severityOrder[$s] } else { 4 }
                }

                # Cap op 50 meest kritieke bevindingen (performance + output beheersbaar)
                $assessmentsToProcess = $sortedAssessments | Select-Object -First 50

                Write-AuditLog -Level Info -Message "  > Found $($unhealthyAssessments.Count) unhealthy assessment(s) - processing top $($assessmentsToProcess.Count)"

                foreach ($assessment in $assessmentsToProcess) {
                    $assessmentCount++

                    # Defensief: properties kunnen null zijn
                    $displayName = if ($assessment.DisplayName) { $assessment.DisplayName }            else { "Unknown Assessment" }
                    $defenderSev = if ($assessment.Metadata.Severity) { $assessment.Metadata.Severity }      else { "Low" }
                    $categoriesRaw = if ($assessment.Metadata.Categories) { $assessment.Metadata.Categories }    else { @() }
                    $resourceId = if ($assessment.ResourceDetails.Id) { $assessment.ResourceDetails.Id }     else { "" }
                    $statusDesc = if ($assessment.Status.Description) { $assessment.Status.Description }     else { "" }

                    # Severity doorvertalen naar Catching Moles niveaus
                    $severity = switch ($defenderSev) {
                        "High" { "High" }
                        "Medium" { "Medium" }
                        "Low" { "Low" }
                        default { "Low" }
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
                    }
                    else { "unknown" }

                    # Random GUID (Zero-Crypto)
                    $randomId = (New-Guid).ToString()
                    $issuesCount++

                    # Console output
                    $severityColor = switch ($severity) {
                        "High" { "Red" }
                        "Medium" { "Yellow" }
                        default { "DarkYellow" }
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
    # SECTIE 2: REGULATORY COMPLIANCE SCORES (alleen bij Defender CSPM Standard)
    # =========================================================================

    if ($isPaidPlan) {
        Write-AuditLog -Level Info -Message "Fetching regulatory compliance scores (Defender CSPM Standard)..."

        # Standaarden die we willen rapporteren (flexibele matching)
        $targetStandards = @(
            @{ Match = "nis2"; Name = "NIS2" }
            @{ Match = "iso-27001|iso27001"; Name = "ISO 27001" }
            @{ Match = "mcsb|microsoft-cloud-security"; Name = "MCSB" }
            @{ Match = "azure-security-benchmark|asb-v|asb$"; Name = "Azure Security Benchmark" }
            @{ Match = "cis-azure|azure-cis"; Name = "CIS Azure" }
        )

        try {
            $complianceStandards = Get-AzSecurityRegulatoryComplianceStandard -ErrorAction Stop

            if ($complianceStandards -and $complianceStandards.Count -gt 0) {
                Write-AuditLog -Level Info -Message "  > Found $($complianceStandards.Count) compliance standard(s)"

                foreach ($target in $targetStandards) {
                    $matched = $complianceStandards | Where-Object { $_.Name -match $target.Match }

                    foreach ($standard in $matched) {
                        $passed = [int]($standard.PassedControls)
                        $failed = [int]($standard.FailedControls)
                        $skipped = [int]($standard.SkippedControls)
                        $total = $passed + $failed

                        if ($total -eq 0) { continue }

                        $failedPct = [math]::Round(($failed / $total) * 100)
                        $passedPct = 100 - $failedPct

                        # Severity op basis van compliance percentage
                        $compSeverity = if ($failedPct -gt 50) { "High" }
                        elseif ($failedPct -gt 25) { "Medium" }
                        else { "Low" }

                        $complianceName = $target.Name
                        $scoreText = "$passedPct% compliant ($passed/$total controls passed, $failed failed)"

                        # Alleen rapporteren als er failed controls zijn
                        if ($failed -gt 0) {
                            $randomId = (New-Guid).ToString()
                            $issuesCount++

                            $severityColor = switch ($compSeverity) {
                                "High" { "Red" }
                                "Medium" { "Yellow" }
                                default { "DarkYellow" }
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
    }
    else {
        # Defender CSPM Standard plan niet actief — voeg één Informational finding toe
        Write-AuditLog -Level Info -Message "Compliance score scan skipped - Defender CSPM Standard plan not active"

        $randomId = (New-Guid).ToString()
        $issuesCount++

        $issueText = "Regulatory compliance monitoring (NIS2, ISO 27001, MCSB) is niet beschikbaar. Het Defender CSPM Standard plan is vereist voor compliance score tracking."
        $recommendText = "Upgrade naar Defender CSPM Standard voor volledige compliance tracking (NIS2, ISO 27001, MCSB, Azure Security Benchmark)."

        Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
        Write-Host "Compliance score scan skipped - Defender CSPM Standard plan not active"
        Write-Host "      - $recommendText" -ForegroundColor DarkGray

        # CONFIDENTIAL MAPPING
        $mappingData += [PSCustomObject]@{
            RandomId             = $randomId
            RealResourceId       = "/subscriptions/$($Subscription.Id)/providers/Microsoft.Security/pricings/CloudPosture"
            RealResourceType     = "Defender CSPM Plan"
            RealAssessmentName   = "Advanced compliance monitoring unavailable (Free plan)"
            RealSubscriptionName = $Subscription.Name
            Severity             = "Informational"
            DefenderSeverity     = "Informational"
            StatusDescription    = $recommendText
            ComplianceFrameworks = "NIS2, ISO 27001, MCSB"
        }

        # SAFE ANONYMOUS PAYLOAD
        $anonymousFindings += [PSCustomObject]@{
            RandomId             = $randomId
            ResourceType         = "Defender CSPM Plan"
            Location             = "Global"
            Severity             = "Informational"
            Issues               = @($issueText)
            OWASP                = "A05"
            ComplianceFrameworks = "NIS2, ISO 27001, MCSB"
            DefenderCategory     = "Pricing"
            PricingTier          = "Free"
            Recommendation       = $recommendText
        }
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
