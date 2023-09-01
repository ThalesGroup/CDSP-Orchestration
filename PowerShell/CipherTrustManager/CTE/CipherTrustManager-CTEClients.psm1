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
# CTE Client Types
Add-Type -TypeDefinition @"
public enum CTE_ClientTypesEnum
{
    CTE-U,
    FS
}
"@
# CTE Client Types
Add-Type -TypeDefinition @"
public enum CTE_PasswordCreationMethodsEnum
{
    MANUAL,
    GENERATE
}
"@
# CTE Client Types
Add-Type -TypeDefinition @"
public enum CTE_ClientCapabilitiesEnum
{
    LDT,
    EKP,
    ES
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

function Find-CMDPGPolicies {
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
    Write-Debug "Resource Set updated"
    return
}