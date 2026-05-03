<#
.SYNOPSIS
    File system utilities voor Catching Moles Security Auditor
    
.DESCRIPTION
    Functies voor directory management en file export (CSV, JSON).
    Alle I/O operaties zijn hier gecentraliseerd.
#>

# Configuratie constante
$script:OUTPUT_DIR_NAME = "CatchingMoles-Rapport"

function New-OutputDirectory {
    <#
    .SYNOPSIS
        Maakt de output directory aan in de huidige werkmap
    
    .DESCRIPTION
        Creëert een directory genaamd 'CatchingMoles-Rapport' in de current working directory.
        Als de directory al bestaat, wordt deze hergebruikt.
    
    .OUTPUTS
        String - Het volledige pad naar de output directory
    
    .EXAMPLE
        $outputDir = New-OutputDirectory
        # Returns: C:\Users\user\CatchingMoles-Rapport
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $outputPath = Join-Path (Get-Location) $script:OUTPUT_DIR_NAME
    
    try {
        if (-not (Test-Path $outputPath)) {
            New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
            Write-AuditLog "Created output directory: $outputPath" -Level Info
        }
        else {
            Write-AuditLog "Using existing output directory: $outputPath" -Level Info
        }
        
        return $outputPath
    }
    catch {
        Write-AuditLog "Failed to create output directory: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-MappingCSV {
    <#
    .SYNOPSIS
        Exporteert de mapping tussen Random IDs en echte resource namen naar CSV
    
    .DESCRIPTION
        ⚠️ CONFIDENTIAL - Dit bestand bevat echte Azure resource namen.
        Exporteert een CSV bestand met de correlatie tussen anonieme Random IDs
        en de werkelijke resource namen voor lokale reference.
    
    .PARAMETER MappingData
        Array van PSCustomObjects met RandomId, RealStorageAccountName, etc.
    
    .PARAMETER OutputDirectory
        Pad waar het CSV bestand wordt opgeslagen
    
    .OUTPUTS
        String - Het volledige pad naar het gegenereerde CSV bestand
    
    .EXAMPLE
        $path = Export-MappingCSV -MappingData $data -OutputDirectory "C:\Output"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$MappingData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )
    
    try {
        $filePath = Join-Path $OutputDirectory "Client_Secret_Mapping.csv"
        
        # Export naar CSV met headers
        $MappingData | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
        
        Write-AuditLog "Secret mapping saved to: $filePath" -Level Success
        return $filePath
    }
    catch {
        Write-AuditLog "Failed to save mapping CSV: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-TransmitPayload {
    <#
    .SYNOPSIS
        Exporteert de anonieme payload voor externe transmissie
    
    .DESCRIPTION
        ✅ SAFE - Dit bestand bevat GEEN gevoelige informatie.
        Exporteert een JSON bestand met alleen Random IDs en generic security findings.
        Dit bestand is veilig om extern te delen.
    
    .PARAMETER AnonymousFindings
        Array van anonieme findings (alleen RandomId, Location, Issues, etc.)
    
    .PARAMETER OutputDirectory
        Pad waar het JSON bestand wordt opgeslagen
    
    .OUTPUTS
        String - Het volledige pad naar het gegenereerde JSON bestand
    
    .EXAMPLE
        $path = Export-TransmitPayload -AnonymousFindings $findings -OutputDirectory "C:\Output"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AnonymousFindings,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )
    
    try {
        $filePath = Join-Path $OutputDirectory "Transmit_Payload.json"
        
        # Export naar JSON met formatting
        $AnonymousFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-AuditLog "Anonymous payload saved to: $filePath" -Level Success
        return $filePath
    }
    catch {
        Write-AuditLog "Failed to save payload JSON: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-CloudShellEnvironment {
    <#
    .SYNOPSIS
        Detecteert of het script draait in Azure Cloud Shell
    
    .DESCRIPTION
        Controleert environment variables die specifiek zijn voor Cloud Shell.
    
    .OUTPUTS
        Boolean - $true als Cloud Shell, $false anders
    
    .EXAMPLE
        if (Test-CloudShellEnvironment) {
            Write-Host "Running in Cloud Shell"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    return ($env:ACC_CLOUD -or $env:AZUREPS_HOST_ENVIRONMENT -eq 'cloud-shell')
}
