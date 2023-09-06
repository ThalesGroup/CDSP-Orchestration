#######################################################################################################################
# File:             CipherTrustManager-CTEClients.psm1                                                                #
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
# CTE Client Types
Add-Type -TypeDefinition @"
using System;
using System.Reflection;
using System.ComponentModel;
public enum CTE_ClientTypesEnum
{
    [DescriptionAttribute("CTE-U")]CTE_U,
    FS
}
"@
# CTE Password Creation Methods
Add-Type -TypeDefinition @"
public enum CTE_PasswordCreationMethodsEnum
{
    MANUAL,
    GENERATE
}
"@
# CTE Client Capabilities
Add-Type -TypeDefinition @"
public enum CTE_ClientCapabilitiesEnum
{
    LDT,
    EKP,
    ES
}
"@
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
$target_uri = "/transparent-encryption/clients"
####

<#
    .SYNOPSIS
        Create a new CTE Client on CipehrTrust Manager
    .DESCRIPTION
        A client is a computer system where the data needs to be protected. A compatible CTE Agent software is installed on the client. The CTE Agent can protect data on the client or devices connected to it. A client can be associated with multiple GuardPoints for encryption of various paths. This method allows you to create a CTE client and control a series of its parameters.
    .EXAMPLE
        PS> New-CTEClient -name <name>
        This shows the minimum parameters necessary to create a CTE client with default client_type FS (FileSystem), client_locked status as False, communication_enabled as False, password_creation_method as GENERATE, registration_allowed as False and system_locked as False.
        You can create CTE client by providing non default values for the above fields.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEClient {
    # classification_tags not supported yet
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $client_locked,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CTE_ClientTypeEnum] $client_type=1,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $communication_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $description,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [securestring] $password,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CTE_PasswordCreationMethodsEnum] $password_creation_method=1,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $profile_identifier,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $registration_allowed,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $system_locked
    )

    Write-Debug "Creating a CTE Client on CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'name' = $name
    }

    # Optional Parameters
    if ($client_locked -ne $null) { $body.add('client_locked', $client_locked) }
    if ($client_type) { $body.add('client_type', ([CTE_ClientTypesEnum]$client_type).ToString()) }
    if ($communication_enabled -ne $null) { $body.add('communication_enabled', $communication_enabled) }
    if ($description) { $body.add('description', $description) }
    if ($password) { $body.add('password', $password) }
    if ($password_creation_method) { $body.add('password_creation_method', ([CTE_PasswordCreationMethodsEnum]$password_creation_method).ToString()) }
    if ($profile_identifier) { $body.add('profile_identifier', $profile_identifier) }
    if ($registration_allowed -ne $null) { $body.add('registration_allowed', $registration_allowed) }
    if ($system_locked -ne $null) { $body.add('system_locked', $system_locked) }

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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Client already exists"
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
        Create and returns a list of CTE clients created on CipherTrust Manager
    .DESCRIPTION
        This method will allow you to retrieve a list of CTE clients that have been configured on the CipherTrust Manager manually or automatically 
    .EXAMPLE
        PS> Find-CTEClients
        This example will return all the CTE clients configured on CipherTrust Manager
    .EXAMPLE
        PS> Find-CTEClients -name <name>
        This example will return all the CTE clients where name matches "name"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CTEClients {
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

    Write-Debug "Getting a List of DPG Policies configured in CM"
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
    Write-Debug "List of CTE Clients created"
    return $response
}

<#
    .SYNOPSIS
        Updates a CTE client
    .DESCRIPTION
        This method will allow you to update the behaviour of a CTE client
    .EXAMPLE
        PS> Update-CTEClient -id <id> -enabled_capabilities 'LDT'
        This example will update the CTE client with id "id" and enable capabilities to allow Live Data Transformation
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CTEClient {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $client_locked,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $client_mfa_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $communication_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $del_client,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $description,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $disable_capability,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $dynamic_parameters,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $enable_domain_sharing,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $enabled_capabilities,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $max_num_cache_log,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $max_space_cache_log,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [securestring] $password,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CTE_PasswordCreationMethodsEnum] $password_creation_method=1,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $profile_identifier,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $registration_allowed,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $system_locked
    )

    Write-Debug "Update a Policy Element by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id"

    Write-Debug "Endpoint with ID: $($endpoint)"

    $body = @{}

    # Optional Parameters
    if ($client_locked -ne $null) { $body.add('client_locked', $client_locked) }
    if ($client_mfa_enabled -ne $null) { $body.add('client_mfa_enabled', $client_mfa_enabled) }
    if ($communication_enabled -ne $null) { $body.add('communication_enabled', $communication_enabled) }
    if ($del_client -ne $null) { $body.add('del_client', $del_client) }
    if ($description) { $body.add('description', $description) }
    if ($disable_capability) { $body.add('disable_capability', $disable_capability) }
    if ($dynamic_parameters) { $body.add('dynamic_parameters', $dynamic_parameters) }
    if ($enable_domain_sharing -ne $null) { $body.add('enable_domain_sharing', $enable_domain_sharing) }
    if ($enabled_capabilities) { $body.add('enabled_capabilities', ([CTE_ClientCapabilitiesEnum]$enabled_capabilities).ToString()) }
    if ($max_num_cache_log) { $body.add('max_num_cache_log', $max_num_cache_log) }
    if ($max_space_cache_log) { $body.add('max_space_cache_log', $max_space_cache_log) }
    if ($password) { $body.add('password', $password) }
    if ($password_creation_method) { $body.add('password_creation_method', ([CTE_PasswordCreationMethodsEnum]$password_creation_method).ToString()) }
    if ($profile_identifier) { $body.add('profile_identifier', $profile_identifier) }    
    if ($registration_allowed -ne $null) { $body.add('registration_allowed', $registration_allowed) }
    if ($system_locked -ne $null) { $body.add('system_locked', $system_locked) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "CTE Client updated"
    return
}

<#
    .SYNOPSIS
        Create a HashTable to store CTE GuarPoint parameters
    .DESCRIPTION
        This method will allow you to creat a HashTable type variable that will store various CTE GuardPoint parameters.
        This HashTable can then be provided to another method i.e. New-CTEClientGuardPoint that allows you to create a new GuardPoint within a CTE client
    .EXAMPLE
        PS> New-CTEGuardPointParams -guard_point_type <guard_point_type> -policy_id <policy_id>
        This example shows minimum parameters required to create a new GuardPoint Params data structure
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEGuardPointParams {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [CTE_GuardPointTypesEnum] $guard_point_type,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policy_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $automount_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $cifs_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $data_classification_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $data_lineage_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $disk_name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $diskgroup_name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $early_access,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $intelligent_protection,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $is_esg_capable_device,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $is_idt_capable_device,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $mfa_enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $network_share_credentials_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $preserve_sparse_regions
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $response = @{}
    
    if ($guard_point_type) { $response.add('guard_point_type', ([CTE_GuardPointTypesEnum]$guard_point_type).ToString()) }
    if ($policy_id) { $response.add('policy_id', $policy_id) }
    if ($automount_enabled -ne $null) { $body.add('automount_enabled', $automount_enabled) }
    if ($cifs_enabled -ne $null) { $body.add('cifs_enabled', $cifs_enabled) }
    if ($data_classification_enabled -ne $null) { $body.add('data_classification_enabled', $data_classification_enabled) }
    if ($data_lineage_enabled -ne $null) { $body.add('data_lineage_enabled', $data_lineage_enabled) }
    if ($disk_name) { $response.add('disk_name', $disk_name) }
    if ($diskgroup_name) { $response.add('diskgroup_name', $diskgroup_name) }
    if ($early_access -ne $null) { $body.add('early_access', $early_access) }
    if ($intelligent_protection -ne $null) { $body.add('intelligent_protection', $intelligent_protection) }
    if ($is_esg_capable_device -ne $null) { $body.add('is_esg_capable_device', $is_esg_capable_device) }
    if ($is_idt_capable_device -ne $null) { $body.add('is_idt_capable_device', $is_idt_capable_device) }
    if ($mfa_enabled -ne $null) { $body.add('mfa_enabled', $mfa_enabled) }
    if ($network_share_credentials_id) { $body.add('network_share_credentials_id', $network_share_credentials_id) }
    if ($preserve_sparse_regions -ne $null) { $body.add('preserve_sparse_regions', $preserve_sparse_regions) }

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

<#
    .SYNOPSIS
        Create a new GuardPoint for a CTE client
    .DESCRIPTION
        A GuardPoint specifies the list of folders that contains paths to be protected. Access to files and encryption of files under the GuardPoint is controlled by security policies. GuardPoints created on a client group are applied to all members of the group.
        This method will allow you to create a new Guard Point for a CTE client and control a series of its parameters.
    .EXAMPLE
        PS> New-CTEClientGuardPoint -guard_paths <guard_paths> -guard_point_params <guard_point_params>
        This example shows minimum parameters required to create a new GuardPoint that includes an array of Guard Paths plus a HashTable type of variable that holds the GuardPoint params
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEClientGuardPoint {
    # classification_tags not supported yet
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $client_id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]] $guard_paths,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [hashtable] $guard_point_params
    )

    Write-Debug "Creating a CTE Client GuardPoint"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $client_id + "/guardpoints"
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'guard_paths' = $guard_paths
        'guard_point_params' = $guard_point_params
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
        # $elementId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Client GuardPoint already exists"
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
    return $response
}

<#
    .SYNOPSIS
        List all guard points for a CTE client
    .DESCRIPTION
        This method will create and return a list of all GuardPoints created within a CTE client
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id>
        This example will return a list of all the GuardPoints within a client i.e. "client_id"
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id> -guard_path <guard_path>
        This example will return a list of all the GuardPoints where guard_path matches "guard_path" and within the client "client_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CTEClientGuardPoints {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $client_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $guard_path, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )

    Write-Debug "Getting a List of CTE Client GuardPoints configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $client_id + "/guardpoints"
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    #$firstset = $false
    if ($name) {
        $endpoint += "?guard_path="
        $endpoint += $guard_path            
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
    Write-Debug "List of CTE Clients created"
    return $response
}

<#
    .SYNOPSIS
        List all guard points for a CTE client
    .DESCRIPTION
        This method will create and return a list of all GuardPoints created within a CTE client
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id>
        This example will return a list of all the GuardPoints within a client i.e. "client_id"
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id> -guard_path <guard_path>
        This example will return a list of all the GuardPoints where guard_path matches "guard_path" and within the client "client_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CTEClientGuardPoint {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $client_id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]] $guard_point_id_list
    )

    Write-Debug "Unguard a set of CTE Client GuardPoints"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $client_id + "/guardpoints/unguard"
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'guard_point_id_list' = $guard_point_id_list
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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