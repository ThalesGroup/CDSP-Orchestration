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
    .PARAMETER name
        Name to uniquely identify the client. This name will be visible on the CipherTrust Manager.
    .PARAMETER client_locked
        Whether the CTE client is locked. The default value is false. Enable this option to lock the configuration of the CTE Agent on the client. Set to true to lock the configuration, set to false to unlock. Locking the Agent configuration prevents updates to any policies on the client.
    .PARAMETER client_type
        Type of CTE Client. The default value is FS. Valid values are CTE-U and FS.
    .PARAMETER communication_enabled
        Whether communication with the client is enabled. The default value is false. Can be set to true only if registration_allowed is true.
    .PARAMETER description
        Description to identify the client.
    .PARAMETER password
        Password for the client. Required when password_creation_method is MANUAL.
    .PARAMETER password_creation_method
        Password creation method for the client. Valid values are MANUAL and GENERATE. The default value is GENERATE.
    .PARAMETER profile_identifier
        Identifier of the Client Profile to be associated with the client. If not provided, the default profile will be linked.
    .PARAMETER registration_allowed
        Whether client's registration with the CipherTrust Manager is allowed. The default value is false. Set to true to allow registration.
    .PARAMETER system_locked
        Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.
    .EXAMPLE
        PS> New-CTEClient -name <name>
        This shows the minimum parameters necessary to create a CTE client with default client_type FS (FileSystem), client_locked status as False, communication_enabled as False, password_creation_method as GENERATE, registration_allowed as False and system_locked as False.
        You can create CTE client by providing non default values for the above fields.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEClient {
    # classification_tags not supported yet
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
    '', 
    Justification = 'These are not passwords... these are parameters used in the creation of a password.')]
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
        [CTE_ClientTypesEnum] $client_type=1,
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
    .PARAMETER name
        Unique name for the CTE Client.
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
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
    .PARAMETER id
        Unique ID of a CTE client that needs to be updated
    .PARAMETER client_locked
        Whether the CTE client is locked. The default value is false. Enable this option to lock the configuration of the CTE Agent on the client. Set to true to lock the configuration, set to false to unlock. Locking the Agent configuration prevents updates to any policies on the client.
    .PARAMETER client_mfa_enabled
        Whether MFA is enabled on the client.
    .PARAMETER communication_enabled
        Whether communication with the client is enabled. The default value is false. Can be set to true only if registration_allowed is true.
    .PARAMETER del_client
        Whether to mark the client for deletion from the CipherTrust Manager. The default value is false.
    .PARAMETER description
        Description to identify the client.
    .PARAMETER disable_capability
        Client capability to be disabled. Only EKP - Encryption Key Protection can be disabled.
    .PARAMETER dynamic_parameters
        Array of parameters to be updated after the client is registered. Specify the parameters in the name-value pair JSON format strings. Make sure to specify all the parameters even if you want to update one or more parameters.
        For example, if there are two parameters in the CTE client list and you want to update the value of "param1", then specify the correct value (one from the "allowed_values") in the "current_value" field, and keep the remaining parameters intact.
        
        Example of dynamic parameters:
        "dynamic_parameters": "[{"name":"param1","type":"SingleSelectString", "description":"Enable or disable param1 capability for CTE binaries.", "allowed_values":"enabled^disabled", "default_value":"disabled", "current_value":"enabled"},{"name":"param2", "type":"MultiSelectString","description":"param2 that takes multiple strings as value", "allowed_values":"Option1^Option2^Option3^Option4", "default_value":"Option1^Option2^Option3", "current_value":"Option1^Option2^Option3"}]"
    .PARAMETER enable_domain_sharing
        Whether domain sharing is enabled for the client.
    .PARAMETER enabled_capabilities
        Client capabilities to be enabled. Separate values with comma. Valid values are:
        LDT - Live Data Transformation
        EKP - Encryption Key Protection
        ES - Efficient Storage
    .PARAMETER max_num_cache_log
        Maximum number of logs to cache.
    .PARAMETER max_space_cache_log
        Maximum space for the cached logs.
    .PARAMETER password
        Password for the client. Required when password_creation_method is MANUAL.
    .PARAMETER password_creation_method
        Password creation method for the client. Valid values are MANUAL and GENERATE. The default value is GENERATE.
    .PARAMETER profile_id
        Identifier of the Client Profile to be associated with the client. If not provided, the default profile will be linked.
    .PARAMETER registration_allowed
        Whether client's registration with the CipherTrust Manager is allowed. Applicable to the clients manually created on the CipherTrust Manager. The default value is false. Set to true to allow registration.
    .PARAMETER system_locked
        Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.
    .EXAMPLE
        PS> Update-CTEClient -id <id> -enabled_capabilities 'LDT'
        This example will update the CTE client with id "id" and enable capabilities to allow Live Data Transformation
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CTEClient {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
    '', 
    Justification = 'These are not passwords... these are parameters used in the creation of a password.')]
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
        [string] $profile_id,
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
    if ($profile_id) { $body.add('profile_id', $profile_id) }    
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
    .PARAMETER guard_point_type
        Type of the GuardPoint. The options are:
            directory_auto
            directory_manual
            rawdevice_manual
            rawdevice_auto
            cloudstorage_auto
            cloudstorage_manual
    .PARAMETER policy_id
        ID of the policy applied with this GuardPoint.
    .PARAMETER automount_enabled
        Whether automount is enabled with the GuardPoint. Supported for Standard and LDT policies.
    .PARAMETER cifs_enabled
        Whether to enable CIFS. Available on LDT enabled windows clients only. The default value is false. If you enable the setting, it cannot be disabled. Supported for only LDT policies.
    .PARAMETER data_classification_enabled
        Whether data classification (tagging) is enabled. Enabled by default if the aligned policy contains ClassificationTags. Supported for Standard and LDT policies.
    .PARAMETER data_lineage_enabled
        Whether data lineage (tracking) is enabled. Enabled only if data classification is enabled. Supported for Standard and LDT policies.
    .PARAMETER disk_name
        Name of the disk if the selected raw partition is a member of an Oracle ASM disk group.
    .PARAMETER diskgroup_name
        Name of the disk group if the selected raw partition is a member of an Oracle ASM disk group.
    .PARAMETER early_access
        Whether secure start (early access) is turned on. Secure start is applicable to Windows clients only. Supported for Standard and LDT policies. The default value is false.
    .PARAMETER intelligent_protection
        Flag to enable intelligent protection for this GuardPoint. This flag is valid for GuardPoints with classification based policy only. Can only be set during GuardPoint creation.
    .PARAMETER is_esg_capable_device
        Whether the device where GuardPoint is applied is ESG capable or not. Supported for IDT and Standard policies.
    .PARAMETER is_idt_capable_device
        Whether the device where GuardPoint is applied is IDT capable or not. Supported for IDT policies.
    .PARAMETER mfa_enabled
        Whether MFA is enabled.
    .PARAMETER network_share_credentials_id
        ID/Name of the credentials if the GuardPoint is applied to a network share. Supported for only LDT policies.
    .PARAMETER preserve_sparse_regions
        Whether to preserve sparse file regions. Available on LDT enabled clients only. The default value is true. If you disable the setting, it cannot be enabled again. Supported for only LDT policies.
    .EXAMPLE
        PS> New-CTEGuardPointParams -guard_point_type <guard_point_type> -policy_id <policy_id>
        This example shows minimum parameters required to create a new GuardPoint Params data structure
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEGuardPointParams {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
    '', 
    Justification = 'These are not network passwords... these are the id of a stored password.')]
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
    
    if ($null -ne $guard_point_type) { $response.add('guard_point_type', ([CTE_GuardPointTypesEnum]$guard_point_type).ToString()) }
    if ($null -ne $policy_id) { $response.add('policy_id', $policy_id) }
    if ($automount_enabled -eq $true) { $response.add('automount_enabled', $automount_enabled) }
    if ($cifs_enabled -eq $true) { $response.add('cifs_enabled', $cifs_enabled) }
    if ($data_classification_enabled -eq $true) { $response.add('data_classification_enabled', $data_classification_enabled) }
    if ($data_lineage_enabled -eq $true) { $response.add('data_lineage_enabled', $data_lineage_enabled) }
    if ($null -ne $disk_name) { $response.add('disk_name', $disk_name) }
    if ($null -ne $diskgroup_name) { $response.add('diskgroup_name', $diskgroup_name) }
    if ($early_access -eq $true) { $response.add('early_access', $early_access) }
    if ($intelligent_protection -eq $true) { $response.add('intelligent_protection', $intelligent_protection) }
    if ($is_esg_capable_device -eq $true) { $response.add('is_esg_capable_device', $is_esg_capable_device) }
    if ($is_idt_capable_device -eq $true) { $response.add('is_idt_capable_device', $is_idt_capable_device) }
    if ($mfa_enabled -eq $true) { $response.add('mfa_enabled', $mfa_enabled) }
    if ($null -ne $network_share_credentials_id) { $response.add('network_share_credentials_id', $network_share_credentials_id) }
    if ($preserve_sparse_regions -eq $true) { $response.add('preserve_sparse_regions', $preserve_sparse_regions) }

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

<#
    .SYNOPSIS
        Create a new GuardPoint for a CTE client
    .DESCRIPTION
        A GuardPoint specifies the list of folders that contains paths to be protected. Access to files and encryption of files under the GuardPoint is controlled by security policies. GuardPoints created on a client group are applied to all members of the group.
        This method will allow you to create a new Guard Point for a CTE client and control a series of its parameters.
    .PARAMETER client_id
        CTE Client on which GuardPoint needs to be created
    .PARAMETER guard_paths
        List of GuardPaths to be created.
    .PARAMETER guard_point_params
        Parameters for creating a GuardPoint.
    .EXAMPLE
        PS> New-CTEClientGuardPoint -guard_paths <guard_paths> -guard_point_params <guard_point_params>
        This example shows minimum parameters required to create a new GuardPoint that includes an array of Guard Paths plus a HashTable type of variable that holds the GuardPoint params
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEGuardPoint {
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
    .PARAMETER client_id
        CTE Client ID as search criteria for searching GuardPoints
    .PARAMETER client_id
        Guard Path as search criteria for searching GuardPoints
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id>
        This example will return a list of all the GuardPoints within a client i.e. "client_id"
    .EXAMPLE
        PS> Find-CTEClientGuardPoints -client_id <client_id> -guard_path <guard_path>
        This example will return a list of all the GuardPoints where guard_path matches "guard_path" and within the client "client_id"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CTEGuardPoints {
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

    Write-Debug "Getting a List of CTE GuardPoints configured in CM"
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
        Unguard GuardPoint(s) in a CTE client
    .DESCRIPTION
        This method will unguard GuardPoint(s) in a CTE client
    .PARAMETER client_id
        ID of the CTE client where GuardPoint(s) need to be unguarded
    .PARAMETER guard_point_id_list
        List of the GuardPoint IDs that need to be unguarded
    .EXAMPLE
        PS> Remove-CTEGuardPoint -client_id <client_id> -guard_point_id_list <guard_point_id_list>
        This example will unguard all the GuardPoints in the list guard_point_id_list from the client with ID client_id
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CTEGuardPoint {
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

Export-ModuleMember -Function New-CTEClient
Export-ModuleMember -Function Find-CTEClients
Export-ModuleMember -Function Update-CTEClient
Export-ModuleMember -Function New-CTEGuardPointParams
Export-ModuleMember -Function New-CTEGuardPoint
Export-ModuleMember -Function Find-CTEGuardPoints
Export-ModuleMember -Function Remove-CTEGuardPoint