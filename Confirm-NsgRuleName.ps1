function Confirm-NsgRuleName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NsgName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $false)]
        [string]$RuleNamePattern,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound"
    )

    # Initialize variables
    $writeOutput = @()
    $isFailed = $false
    $results = @()

    try {
        # Retrieve NSG and filter rules by direction and pattern
        $rules = Get-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName |
            Get-AzNetworkSecurityRuleConfig |
            Where-Object { 
                $_.Direction -eq $Direction -and 
                ($RuleNamePattern -eq $null -or $_.Name -like $RuleNamePattern) 
            } |
            Select-Object Name, Priority, Access, Protocol, Direction, SourceAddressPrefix, DestinationAddressPrefix, SourcePortRange, DestinationPortRange

        if ($rules) {
            $results = $rules
        } else {
            $writeOutput += "No $Direction rules found in NSG '$NsgName' within Resource Group '$ResourceGroupName' matching the pattern '$RuleNamePattern'."
        }
    } catch {
        $isFailed = $true
        $errorMessage = "Unexpected error: {0}" -f $_.Exception.Message
        $writeOutput += $errorMessage
    }

    # Display the results in table format
    if ($results) {
        $results | Format-Table -AutoSize
    }

    # Return structured output
    return [PSCustomObject]@{
        IsFailed = $isFailed
        Output = $writeOutput
        Rules = $results
    }
}
