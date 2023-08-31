#######################################################################################################################
# File:             CipherTrustManager-ResourceSets.psm1                                                             #
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
# ResourceSet Types
Add-Type -TypeDefinition @"
public enum CM_CTEResourceSetTypes {
    Directory,
    Classification
}
"@
# Policy Element Types
Add-Type -TypeDefinition @"
public enum CM_CTEPolicyElementTypes {
    resourcesets,
    usersets,
    processsets,
    signaturesets
}
"@
####

####
# Support Variables
####
# Text string relating to CM_CTEResourceSetTypes enum
$CM_CTEResourceSetTypeDef = @{
    [CM_CTEResourceSetTypes]::Directory      = "Directory" 
    [CM_CTEResourceSetTypes]::Classification = "Classification"
}
#
# Text string relating to CM_CTEPolicyElementTypes enum
$CM_CTEPolicyElementTypeDef = @{
    [CM_CTEPolicyElementTypes]::resourcesets  = "resourcesets" 
    [CM_CTEPolicyElementTypes]::usersets      = "usersets"
    [CM_CTEPolicyElementTypes]::processsets   = "processsets"
    [CM_CTEPolicyElementTypes]::signaturesets = "signaturesets"
}
#
####

####
# Local Variables
####
$target_uri = "/transparent-encryption/policies"
####

<#
    .SYNOPSIS
        Create a new resource set
    .DESCRIPTION
        This allows you to create a resource set on CipherTrust Manager and control a series of its parameters. Those parameters include: type, resources, resourceSetName
    .EXAMPLE
        PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

        This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

        This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

        This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

        This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicy {
    # classification_tags not supported yet
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
        'policy_type' = $policy_type
    }

    # Optional Parameters
    if ($description) { $body.add('description', $description) }

    if ([CM_CTEPolicyElementTypes]::resourcesets -eq $policyElementType) {
        if ($type) { $body.add('type', $type) }
        if ($elementsList.Length -gt 0) { $body.add('resources', $elementsList) }
    } elseif ([CM_CTEPolicyElementTypes]::usersets -eq $policyElementType) {
        if ($elementsList.Length -gt 0) { $body.add('users', $elementsList) }
    } elseif ([CM_CTEPolicyElementTypes]::processsets -eq $policyElementType) {
        if ($source_list.Length -gt 0) { $body.add('source_list', $source_list) }
    } elseif ([CM_CTEPolicyElementTypes]::signaturesets -eq $policyElementType) {
        if ($elementsList.Length -gt 0) { $body.add('processes', $elementsList) }
    }

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
        [bool] $resource_set_id
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
        [bool] $transformation_key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $transformation_key_type
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