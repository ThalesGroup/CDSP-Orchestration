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
# CTE GuardPoint Types
Add-Type -TypeDefinition @"
public enum CTE_GuardPointTypesEnum
{
    directory_auto,
    directory_manual,
    rawdevice_manual,
    rawdevice_auto,
    cloudstorage_auto,
    cloudstorage_manual
}
"@
####

####
# Local Variables
####
$target_uri = "/transparent-encryption/csigroups"
####

<#
    .SYNOPSIS
        Create a new CSI Storage Group
    .DESCRIPTION
        This allows you to create a CTE client on CipherTrust Manager and control a series of its parameters. Those parameters include: type, resources, resourceSetName
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
function New-CTECSIStorageGroup {
    # classification_tags not supported yet
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $k8s_namespace,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $k8s_storage_class,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $client_profile,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $description
    )

    Write-Debug "Creating a CTE CSI Storage Group on CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'k8s_namespace' = $k8s_namespace
        'k8s_storage_class' = $k8s_storage_class
        'name' = $name
    }

    # Optional Parameters
    if ($client_profile) { $body.add('client_profile', $client_profile) }
    if ($description) { $body.add('description', $description) }
    
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): CSI Storage Group already exists"
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
    Write-Debug "CTE Client created"
    return $elementId
}

function Find-CTECSIStorageGroups {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )

    Write-Debug "Getting a List of CSI Storage Groups configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    #$firstset = $false
    if ($name) {
        $endpoint += "?name="
        $endpoint += $name            
    }

    if ($skip) {
        $endpoint += "&skip="
        $endpoint += $skip
    }

    if ($limit) {
        $endpoint += "&limit="
        $endpoint += $limit
    }

    Write-Debug "Endpoint w Query: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of CSI Storage Groups created"
    return $response
}

function Remove-CTECSIStorageGroup {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $sg_id
    )

    Write-Debug "Remove a CSI Storage Group"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $sg_id
    Write-Debug "Endpoint: $($endpoint)"

    Try {
        Write-Debug "Testing JWT"
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "CTE Client GuardPoints Unguarded"
    return $response
}

function New-CTEAddClientsStorageGroup {
    # classification_tags not supported yet
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $sg_id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]] $client_list
    )

    Write-Debug "Add clients to a CTE CSI Storage Group"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $sg_id + "/clients"
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'client_list' = $client_list
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "CTE Clients added to the CSO Storage Group"
    return $elementId
}

function New-CTEAddGuardPoliciesStorageGroup {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $sg_id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]] $policy_list
    )

    Write-Debug "Add Guard Policies to a CTE CSI Storage Group"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $sg_id + "/guardpoints"
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'policy_list' = $policy_list
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "CTE Clients added to the CSI Storage Group"
    return $elementId
}