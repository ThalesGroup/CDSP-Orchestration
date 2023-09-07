#######################################################################################################################
# File:             CipherTrustManager-CSIStorageGroups.psm1                                                          #
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
        This method allows you to manage Storage Group resources related to Kubernetes Container Storage Interface (CSI) and control a series of its parameters. Those parameters include: kubernetes namespace, storage class, and name of the CSI storage group
    .EXAMPLE
        PS> New-CTECSIStorageGroup -k8s_namespace <k8s_namespace> -k8s_storage_class <k8s_storage_class> -name <name> -client_profile <client_profile>
        This shows the minimum parameters necessary to create a CSI Storage Group
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTECSIStorageGroup {
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

<#
    .SYNOPSIS
        Create and returns a list of CTE CSI Storage Groups created on CipherTrust Manager
    .DESCRIPTION
        This method allows you to retrieve a list of CTE CSI Storage Groups created on CipherTrust Manager using filters like name of the storage group
    .EXAMPLE
        PS> Find-CTECSIStorageGroups
        This method will return all the CSI Storage Groups created on the CipherTrust Manager
    .EXAMPLE
        PS> Find-CTECSIStorageGroups -name <name>
        This method will return all the CSI Storage Groups created on the CipherTrust Manager matching the filter "name"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
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

<#
    .SYNOPSIS
        Deletes a CSI Storage Group from CipherTrust Manager
    .DESCRIPTION
        This method allows you to delete a CSI Storage Group from CipherTrust Manager identified by the "sg_id"
    .EXAMPLE
        PS> Remove-CTECSIStorageGroup -sg_id <sg_id>
        This method will delete the CSI Storage Groups with ID "sg_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
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

<#
    .SYNOPSIS
        Add a list of CTE clients to a CSI Storage Group
    .DESCRIPTION
        This method allows you to add a list of CTE Clients to a CSI Storage Group.
    .EXAMPLE
        PS> New-CTEAddClientsStorageGroup -sg_id <sg_id> -client_list <client_list>
        This method will add the elemets of client_list in the CSI Storage Group with ID "sg_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
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

<#
    .SYNOPSIS
        Add a list of CTE Policies to a CSI Storage Group
    .DESCRIPTION
        This method allows you to add a list of CTE Policies to a CSI Storage Group.
    .EXAMPLE
        PS> New-CTEAddGuardPoliciesStorageGroup -sg_id <sg_id> -policy_list <policy_list>
        This method will add the elemets of policy_list in the CSI Storage Group with ID "sg_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
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

Export-ModuleMember -Function New-CTECSIStorageGroup
Export-ModuleMember -Function Find-CTECSIStorageGroups
Export-ModuleMember -Function Remove-CTECSIStorageGroup
Export-ModuleMember -Function New-CTEAddClientsStorageGroup
Export-ModuleMember -Function New-CTEAddGuardPoliciesStorageGroup