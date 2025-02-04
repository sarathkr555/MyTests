function Confirm-NsgRuleName {
    <#
    .Notes
    Author: Sarath K R
    Modified By: Sarath K R

    Last Modified: 2025-01-21
    Changes:    
    - Initial version

    .Synopsis
    Confirm if the NSG rule name exists.

    .Description
    The Confirm-NsgRuleName script confirms if network security rule names exist based on an exact rule name.
    It allows filtering by rule direction (Inbound/Outbound).

    .Parameter NsgName
    The name of the Network Security Group.

    .Parameter ResourceGroupName
    The name of the Resource Group containing the NSG.

    .Parameter RuleName
    The exact name of the rule to check.

    .Parameter Direction
    The direction of the rules to filter. Valid values are "Inbound" and "Outbound". Default is "Inbound".

    .Example
    PS> Confirm-NsgRuleName -NsgName "EUWUEINVOINSG13" -ResourceGroupName "EUWUEINVOIRSG05" -RuleName "IN_ALLOW_CLIENT_SFTP_KISWEL_SDN_BHD_MY0008" -Direction "Inbound"
    # Returns true or false based on rule presence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NsgName,
    
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
    
        [Parameter(Mandatory = $false)]
        [string]$RuleName,
    
        [Parameter(Mandatory = $false)]
        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound"
    )

    # Variable to track script status
    $isFailed = $false
    $writeOutput = @()

    try {
        # Retrieve NSG rules
        $rules = Get-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName |
            Get-AzNetworkSecurityRuleConfig |
            Where-Object {
                $_.Direction -eq $Direction -and 
                (-not $RuleName -or $_.Name -eq $RuleName)
            }

        # Check for matching rules
        if ($rules.Count -gt 0) {
            $writeOutput += "Matching rules found in NSG '$NsgName' for resource group '$ResourceGroupName'."
            return @{
                Result = $true
                
            }
        } else {
            $writeOutput += "No matching rules found in NSG '$NsgName' for resource group '$ResourceGroupName'. Direction: '$Direction'."
            return @{
                Result = $false
                OutputMessage = $writeOutput -join "`n"
            }
        }
    } catch {
        # Handle unexpected errors
        $isFailed = $true
        $errorMessage = "Unexpected error: {0}" -f $_.Exception.Message
        $writeOutput += $errorMessage
        $writeOutput += Write-ScriptStackTrace -PSError $_
    }

    # If script failed, log detailed output
    if ($isFailed) {
        $writeOutput += "Script encountered an unexpected error. Please check the stack trace for details."
        Write-Error ($writeOutput -join "`n")
        return @{
            Result = $false
            ErrorMessage = $writeOutput -join "`n"
        }
    }
}
