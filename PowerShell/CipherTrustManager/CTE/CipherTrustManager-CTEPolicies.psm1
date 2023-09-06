#######################################################################################################################
# File:             CipherTrustManager-CTEPolicies.psm1                                                               #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# ENUMS
####
Add-Type -TypeDefinition @"
   public enum CTE_PolicyTypeEnum
   {
      Standard,
      LDT,
      IDT,
      Cloud_Object_Storage,
      CSI
   }
"@
####

####
# Local Variables
####
$target_uri = "/transparent-encryption/policies"
####

<#
    .SYNOPSIS
        Create a new CTE Client Policy
    .DESCRIPTION
        This allows you to create a CTE Client Policy on CipherTrust Manager and control a series of its parameters. Those parameters include: name, policy_type, description, and one of the security/key rules array
    .EXAMPLE
        PS> New-CTEPolicy -name <name> -policy_type <policy_type> -data_transform_rules <data_transform_rules> -security_rules <security_rules>
        This shows the minimum parameters necessary to create a new CTE Policy. Policy Type can be Standard, LDT, IDT, Cloud_Object_Storage, or CSI
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicy {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [CTE_PolicyTypeEnum] $policy_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $data_transform_rules,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $description,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $idt_key_rules,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $key_rules,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $ldt_key_rules,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $metadata,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $never_deny,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $security_rules,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $signature_rules
    )

    Write-Debug "Creating a CTE policy on CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'name'        = $name
        'policy_type' = ([CTE_PolicyTypeEnum]$policy_type).ToString()
    }

    # Optional Parameters
    if ($description) { $body.add('description', $description) }
    if ($never_deny -ne $null) { $body.add('never_deny', $never_deny) }
    if ($data_transform_rules.Length -gt 0) { $body.add('data_transform_rules', $data_transform_rules) }
    if ($idt_key_rules.Length -gt 0) { $body.add('idt_key_rules', $idt_key_rules) }
    if ($key_rules.Length -gt 0) { $body.add('key_rules', $key_rules) }
    if ($ldt_key_rules.Length -gt 0) { $body.add('ldt_key_rules', $ldt_key_rules) }
    if ($security_rules.Length -gt 0) { $body.add('security_rules', $security_rules) }
    if ($signature_rules.Length -gt 0) { $body.add('signature_rules', $signature_rules) }
    if ($metadata) { $body.add('metadata', $metadata) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Write-Debug "Testing JWT"
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $elementId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Resource Set already exists"
            return
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Policy Element created"
    return $elementId
}

<#
    .SYNOPSIS
        Add Data transformation (dataxform) rules to a CTE Client Policy
    .DESCRIPTION
        This allows you to create an array of Data transformation (dataxform) rules consisting of parameters like key and the the resource set
    .EXAMPLE
        PS> $list = New-CTEPolicyDataTxRulesList -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new Data Transformation rule
    .EXAMPLE
        PS> $list = New-CTEPolicyDataTxRulesList -dataTxRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new Data Transformation rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyDataTxRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$dataTxRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $resource_set_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($dataTxRulesList) {
        Write-Debug "array: $($dataTxRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $dataTxRulesList = @()
    }

    $temp_hash = @{}
    
    if ($key_id) {
        $temp_hash.add('key_id', $key_id)
    }
    if ($key_type) {
        $temp_hash.add('key_type', $key_type)
    } 
    if ($resource_set_id) {
        $temp_hash.add('resource_set_id', $resource_set_id)
    }    

    #Add this current policy to the list of user set policies
    $dataTxRulesList += $temp_hash
    Write-Debug "array updated: $($dataTxRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $dataTxRulesList
}

<#
    .SYNOPSIS
        Add In-Place data transformation rules to a CTE Client Policy
    .DESCRIPTION
        This allows you to create an array of In-Place data transformation rules consisting of keys information
    .EXAMPLE
        PS> $list = New-CTEPolicyIDTKeyRulesList -current_key <current_key> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new In-Place data Transformation rule
    .EXAMPLE
        PS> $list = New-CTEPolicyDataTxRulesList -idtKeyRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new In-Place data Transformation rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyIDTKeyRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$idtKeyRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $current_key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $current_key_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $transformation_key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $transformation_key_type
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($idtKeyRulesList) {
        Write-Debug "array: $($idtKeyRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $idtKeyRulesList = @()
    }

    $temp_hash = @{}
    
    if ($current_key) {
        $temp_hash.add('current_key', $current_key)
    }
    if ($current_key_type) {
        $temp_hash.add('current_key_type', $current_key_type)
    } 
    if ($transformation_key) {
        $temp_hash.add('transformation_key', $transformation_key)
    } 
    if ($transformation_key_type) {
        $temp_hash.add('transformation_key_type', $transformation_key_type)
    }    

    #Add this current policy to the list of user set policies
    $idtKeyRulesList += $temp_hash
    Write-Debug "array updated: $($idtKeyRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $idtKeyRulesList
}

<#
    .SYNOPSIS
        Add key rules to a CTE Client Policy
    .DESCRIPTION
        This allows you to create an array of key rules consisting of key and resourceset information
    .EXAMPLE
        PS> $list = New-CTEPolicyKeyRulesList -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new key rule
    .EXAMPLE
        PS> New-CTEPolicyKeyRulesList -keyRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new key rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyKeyRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$keyRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $resource_set_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($keyRulesList) {
        Write-Debug "array: $($keyRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $keyRulesList = @()
    }

    $temp_hash = @{}
    
    if ($key_id) {
        $temp_hash.add('key_id', $key_id)
    }
    if ($key_type) {
        $temp_hash.add('key_type', $key_type)
    } 
    if ($resource_set_id) {
        $temp_hash.add('resource_set_id', $resource_set_id)
    }    

    #Add this current policy to the list of user set policies
    $keyRulesList += $temp_hash
    Write-Debug "array updated: $($keyRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $keyRulesList
}

<#
    .SYNOPSIS
        Add Live Data Transformation (LDT) rules to a CTE Client Policy
    .DESCRIPTION
        This allows you to create an array of Live Data Transformation rules for resources to be protected consisting of current and transformation key as well as the resourceset to be protected
    .EXAMPLE
        PS> $list = New-CTEPolicyLDTKeyRulesList -current_key <current_key> -resource_set_id <resource_set_id> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new LDT rule. Current and transformation key is a HashTable of Key ID and ID type.
    .EXAMPLE
        PS> New-CTEPolicyLDTKeyRulesList -ldtKeyRulesList $list -current_key <current_key> -resource_set_id <resource_set_id> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new LDT rule. Current and transformation key is a HashTable of Key ID and ID type and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyLDTKeyRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$ldtKeyRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $current_key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $transformation_key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $is_exclusion_rule,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $resource_set_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($ldtKeyRulesList) {
        Write-Debug "array: $($ldtKeyRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $ldtKeyRulesList = @()
    }

    $temp_hash = @{}
    
    if ($current_key) {
        $temp_hash.add('current_key', $current_key)
    }
    if ($is_exclusion_rule -ne $null) {
        $temp_hash.add('is_exclusion_rule', $is_exclusion_rule)
    }
    if ($resource_set_id) {
        $temp_hash.add('resource_set_id', $resource_set_id)
    } 
    if ($transformation_key) {
        $temp_hash.add('transformation_key', $transformation_key)
    }    

    #Add this current policy to the list of user set policies
    $ldtKeyRulesList += $temp_hash
    Write-Debug "array updated: $($ldtKeyRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $ldtKeyRulesList
}

<#
    .SYNOPSIS
        Add Security rules to a CTE Client Policy
    .DESCRIPTION
        A security rule defines who can access the data (User or Group), what they can do with the data (Action), which applications or executables have access to the data (Process), where the data is located (Resource), how the data can be accessed (Effect), and whether it can be viewed from the CipherTrust Manager (Browsing). This method allows you to create an array of security rules that can then be associated with a CTE client policy.
    .EXAMPLE
        PS> $list = New-CTEPolicySecurityRulesList -effect <effect> -action <action> -partial_match <partial_match> -resource_set_id <resource_set_id> -exclude_resource_set <exclude_resource_set>
        This shows the parameters to create a new Security rule that allows or blocks access to a particular resource
    .EXAMPLE
        PS> New-CTEPolicySecurityRulesList -securityRulesList $list -effect <effect> -action <action> -partial_match <partial_match> -resource_set_id <resource_set_id> -exclude_resource_set <exclude_resource_set>
        This shows the parameters to create a new Security Rule that allows or blocks access to a particular resource and add the same to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicySecurityRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$securityRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $action,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $effect,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $process_set_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $resource_set_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $user_set_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $exclude_process_set,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $exclude_resource_set,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $exclude_user_set,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $partial_match
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($securityRulesList) {
        Write-Debug "array: $($securityRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $securityRulesList = @()
    }

    $temp_hash = @{}
    
    if ($action) {
        $temp_hash.add('action', $action)
    }
    if ($effect) {
        $temp_hash.add('effect', $effect)
    }
    if ($exclude_process_set -ne $null) {
        $temp_hash.add('exclude_process_set', $exclude_process_set)
    }
    if ($exclude_resource_set -ne $null) {
        $temp_hash.add('exclude_resource_set', $exclude_resource_set)
    }
    if ($exclude_user_set -ne $null) {
        $temp_hash.add('exclude_user_set', $exclude_user_set)
    }
    if ($partial_match -ne $null) {
        $temp_hash.add('partial_match', $partial_match)
    }
    if ($resource_set_id) {
        $temp_hash.add('resource_set_id', $resource_set_id)
    } 
    if ($process_set_id) {
        $temp_hash.add('process_set_id', $process_set_id)
    }
    if ($user_set_id) {
        $temp_hash.add('user_set_id', $user_set_id)
    }    

    #Add this current policy to the list of user set policies
    $securityRulesList += $temp_hash
    Write-Debug "array updated: $($securityRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $securityRulesList
}

<#
    .SYNOPSIS
        Add Signtaure rules to a CTE Client Policy
    .DESCRIPTION
        This method allows you to create an array of signature rules that can then be associated with a CTE client policy.
    .EXAMPLE
        PS> $list = New-CTEPolicySignatureRulesList -signature_set_id <signature_set_id>
        This shows the parameters to create a new signature rule with minimum parameters i.e. signature_set_id
    .EXAMPLE
        PS> New-CTEPolicySignatureRulesList -signatureRulesList $list -signature_set_id <signature_set_id>
        This shows the parameters to create a new signature rule with minimum parameters i.e. signature_set_id and add the same to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicySignatureRulesList {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$signatureRulesList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $signature_set_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($signatureRulesList) {
        Write-Debug "array: $($signatureRulesList)"
    }
    else {
        Write-Debug "array is empty"
        $signatureRulesList = @()
    }

    $temp_hash = @{}
    
    if ($signature_set_id) {
        $temp_hash.add('signature_set_id', $signature_set_id)
    }

    #Add this current policy to the list of user set policies
    $signatureRulesList += $temp_hash
    Write-Debug "array updated: $($signatureRulesList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $signatureRulesList
}

<#
    .SYNOPSIS
        Create new data structure to hold LDT key
    .DESCRIPTION
        This method allows you to create a HashTable that holds key arguments i.e. key_id and key_type.
    .EXAMPLE
        PS> $ldtKey = New-CTELDTKey -key_id <key_id> -key_type 'id'
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTELDTKey {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $key_type
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $response = @{}
    
    if ($key_id) {
        $response.add('key_id', $key_id)
    }
    if ($key_type) {
        $response.add('key_type', $key_type)
    }

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

<#
    .SYNOPSIS
        Create new data structure to hold CTE Policy Metadata
    .DESCRIPTION
        This method allows you to create a HashTable that holds the metadata for CTE Policy
    .EXAMPLE
        PS> $meta = New-CTEPolicyMetadata -restrict_update <restrict_update>
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyMetadata {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $restrict_update
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $response = @{}
    
    if ($restrict_update -ne $null) {
        $response.add('restrict_update', $restrict_update)
    }

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}