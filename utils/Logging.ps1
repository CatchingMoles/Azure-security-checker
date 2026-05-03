<#
.SYNOPSIS
    Logging utilities voor Catching Moles Security Auditor
    
.DESCRIPTION
    Pure logging functies zonder side effects (behalve console output).
    Gebruikt door alle modules voor consistente logging.
#>

function Write-AuditLog {
    <#
    .SYNOPSIS
        Schrijft audit log berichten naar console met timestamp en kleurcodering
    
    .PARAMETER Message
        Het bericht om te loggen
    
    .PARAMETER Level
        Log level: Info, Warning, Error, Success
    
    .EXAMPLE
        Write-AuditLog "Scanning storage accounts..." -Level Info
        Write-AuditLog "Security issue found!" -Level Warning
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    # Skip verbose logging in Quiet Mode (if global variable is set)
    if ($script:QuietMode -and $Level -eq 'Info') {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'Info'    { 'Gray' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}
