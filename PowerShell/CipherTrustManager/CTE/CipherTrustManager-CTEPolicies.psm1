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
    .PARAMETER name
        Name of the policy.
    .PARAMETER policy_type
        Type of the policy. Valid values are:
        Standard
        LDT
        IDT
        Cloud_Object_Storage
        CSI
    .PARAMETER data_transform_rules
        Data transformation rules to link with the policy.
    .PARAMETER description
        Description of the policy.
    .PARAMETER idt_key_rules
        IDT rules to link with the policy.
    .PARAMETER key_rules
        Key rules to link with the policy.
    .PARAMETER ldt_key_rules
        LDT rules to link with the policy. Supported for LDT policies.
    .PARAMETER metadata
        Restrict policy for modification
    .PARAMETER never_deny
        Whether to always allow operations in the policy. By default, it is disabled, that is, operations are not allowed. Supported for Standard, LDT, and Cloud_Object_Storage policies. For Learn Mode activations, never_deny is set to true, by default.
    .PARAMETER security_rules
        Security rules to link with the policy.
    .PARAMETER signature_rules
        Signature rules to link with the policy.
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
    .PARAMETER dataTxRulesList
        List of Data Transformation Rules to which we want to add another rule
    .PARAMETER key_id
        Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string "clear_key" only. Do not specify any other identifier.
    .PARAMETER key_type
        Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
    .PARAMETER resource_set_id
        ID of the resource set linked with the rule.
    .EXAMPLE
        PS> $list = New-CTEDataTxRulesList -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new Data Transformation rule
    .EXAMPLE
        PS> $list = New-CTEDataTxRulesList -dataTxRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new Data Transformation rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEDataTxRulesList {
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
    .PARAMETER idtKeyRulesList
        List of In-Place Data Transformation Rules to which we want to add another rule
    .PARAMETER current_key
        Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string "clear_key" only. Do not specify any other identifier.
    .PARAMETER current_key_type
        Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
    .PARAMETER transformation_key
        Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id.
    .PARAMETER transformation_key_type
        Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
    .EXAMPLE
        PS> $list = New-CTEIDTKeyRulesList -current_key <current_key> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new In-Place data Transformation rule
    .EXAMPLE
        PS> $list = New-CTEIDTKeyRulesList -idtKeyRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new In-Place data Transformation rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEIDTKeyRulesList {
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
    .PARAMETER keyRulesList
        List of Key Rules to which we want to add another rule
    .PARAMETER key_id
        Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string "clear_key" only. Do not specify any other identifier.
    .PARAMETER key_type
        Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
    .PARAMETER resource_set_id
        ID of the resource set to link with the rule. Supported for Standard, LDT and IDT policies.
    .EXAMPLE
        PS> $list = New-CTEKeyRulesList -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new key rule
    .EXAMPLE
        PS> New-CTEKeyRulesList -keyRulesList $list -key_id <key_id> -resource_set_id <resource_set_id>
        This shows the minimum parameters necessary to create a new key rule and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEKeyRulesList {
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
    .PARAMETER ldtKeyRulesList
        List of Live Data Transformation Rules to which we want to add another rule
    .PARAMETER current_key
        Properties of the current key.
    .PARAMETER transformation_key
        Properties of the transformation key.
    .PARAMETER is_exclusion_rule
        Whether this is an exclusion rule. If enabled, no need to specify the transformation rule.
    .PARAMETER resource_set_id
        ID of the resource set to link with the rule.
    .EXAMPLE
        PS> $list = New-CTELDTKeyRulesList -current_key <current_key> -resource_set_id <resource_set_id> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new LDT rule. Current and transformation key is a HashTable of Key ID and ID type.
    .EXAMPLE
        PS> New-CTELDTKeyRulesList -ldtKeyRulesList $list -current_key <current_key> -resource_set_id <resource_set_id> -transformation_key <transformation_key>
        This shows the minimum parameters necessary to create a new LDT rule. Current and transformation key is a HashTable of Key ID and ID type and add to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTELDTKeyRulesList {
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

    #Add this current policy to the list rules
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
    .PARAMETER securityRulesList
        List of Security Rules to which we want to add another rule
    .PARAMETER action
        Actions applicable to the rule. Examples of actions are read, write, all_ops, and key_op.
    .PARAMETER effect
        Effects applicable to the rule. Separate multiple effects by commas. The valid values are:
        permit
        deny
        audit
        applykey
    .PARAMETER process_set_id
        ID of the process set to link to the policy.
    .PARAMETER resource_set_id
        ID of the resource set to link to the policy. Supported for Standard, LDT and IDT policies.
    .PARAMETER user_set_id
        ID of the user set to link to the policy.
    .PARAMETER exclude_process_set
        Process set to exclude. Supported for Standard, LDT and IDT policies.
    .PARAMETER exclude_resource_set
        Resource set to exclude. Supported for Standard, LDT and IDT policies.
    .PARAMETER exclude_user_set
        User set to exclude. Supported for Standard, LDT and IDT policies.
    .PARAMETER partial_match
        Whether to allow partial match operations. By default, it is enabled. Supported for Standard, LDT and IDT policies.
    .EXAMPLE
        PS> $list = New-CTESecurityRulesList -effect <effect> -action <action> -partial_match <partial_match> -resource_set_id <resource_set_id> -exclude_resource_set <exclude_resource_set>
        This shows the parameters to create a new Security rule that allows or blocks access to a particular resource
    .EXAMPLE
        PS> New-CTESecurityRulesList -securityRulesList $list -effect <effect> -action <action> -partial_match <partial_match> -resource_set_id <resource_set_id> -exclude_resource_set <exclude_resource_set>
        This shows the parameters to create a new Security Rule that allows or blocks access to a particular resource and add the same to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTESecurityRulesList {
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

    #Add this current policy to the list of rules
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
    .PARAMETER signatureRulesList
        List of Signature Rules to which we want to add another rule
    .PARAMETER signature_set_id
        List of identifiers of signature sets. This identifier can be the Name, ID (a UUIDv4), URI, or slug of the signature set.
    .EXAMPLE
        PS> $list = New-CTESignatureRulesList -signature_set_id <signature_set_id>
        This shows the parameters to create a new signature rule with minimum parameters i.e. signature_set_id
    .EXAMPLE
        PS> New-CTESignatureRulesList -signatureRulesList $list -signature_set_id <signature_set_id>
        This shows the parameters to create a new signature rule with minimum parameters i.e. signature_set_id and add the same to an array that can be associated with a CTE client policy
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTESignatureRulesList {
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
    .PARAMETER key_id
        Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string "clear_key" only. Do not specify any other identifier.
    .PARAMETER key_type
        Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.
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
    .PARAMETER restrict_update
        To restrict the policy for modification. If its value enabled means user not able to modify the guarded policy.
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

Export-ModuleMember -Function New-CTEPolicy
Export-ModuleMember -Function New-CTEDataTxRulesList
Export-ModuleMember -Function New-CTEIDTKeyRulesList
Export-ModuleMember -Function New-CTEKeyRulesList
Export-ModuleMember -Function New-CTELDTKeyRulesList
Export-ModuleMember -Function New-CTESecurityRulesList
Export-ModuleMember -Function New-CTESignatureRulesList
Export-ModuleMember -Function New-CTELDTKey
Export-ModuleMember -Function New-CTEPolicyMetadata