#######################################################################################################################
# File:             CipherTrustManager-ClientProfiles.psm1                                                            #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# ENUMS
####
#Interface Types
Add-Type -TypeDefinition @"
   public enum CM_LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
}
"@
#Connectors
Add-Type -TypeDefinition @"
   public enum CM_Connectors {
    DPG,
    BDT,
    CADP,
    CRDP
}
"@
####

<#
    .SYNOPSIS
        Add a new interface
    .DESCRIPTION
        This allows you to create a key on CipherTrust Manager and control a series of its parameters. Those parameters include: keyname, usageMask, algo, size, Undeleteable, Unexportable, NoVersionedKey
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
function New-CMClientProfiles {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [int] $nae_iface_port,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_Connectors] $app_connector_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $policy_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $lifetime,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [int] $cert_duration,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [int] $max_clients,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $ca_id = $caId,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_cn,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_country,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_state, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_city,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_org_name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_org_unit,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $csr_email,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $VerifySSLCertificate,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $UsePersistentConnections,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_LogLevel] $log_level,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $TLS_SkipVerify,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $TLS_Enabled,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $auth_method_scheme_name
    )

    Write-Debug "Creating definition of a Client Profile in CM"
    $endpoint = $CM_Session.REST_URL + "/data-protection/client-profiles"
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'name' = $name
        'app_connector_type' = $app_connector_type.ToString()
    }

    # Optional Parameters
    if ($nae_iface_port) { $body.add('nae_iface_port', $nae_iface_port) }
    if ($policy_id) { $body.add('policy_id', $policy_id) }
    if ($lifetime) { $body.add('lifetime', $lifetime) }
    if ($cert_duration) { $body.add('cert_duration', $cert_duration) }
    if ($max_clients) { $body.add('max_clients', $max_clients) }
    if ($ca_id) { $body.add('ca_id', $ca_id) }

    $csr_parameters = @{}
    if ($csr_cn) { $csr_parameters.add('csr_cn', $csr_cn) }
    if ($csr_country) { $csr_parameters.add('csr_country', $csr_country) }
    if ($csr_state) { $csr_parameters.add('csr_state', $csr_state) }
    if ($csr_city) { $csr_parameters.add('csr_city', $csr_city) }
    if ($csr_org_name) { $csr_parameters.add('csr_org_name', $csr_org_name) }
    if ($csr_org_unit) { $csr_parameters.add('csr_org_unit', $csr_org_unit) }
    if ($csr_email) { $csr_parameters.add('csr_email', $csr_email) }
    $body.add('csr_parameters', $csr_parameters)

    $tls_to_appserver = @{}
    if ($TLS_SkipVerify) { $tls_to_appserver.add('tls_skip_verify', $true) }
    if ($TLS_Enabled) { $tls_to_appserver.add('tls_enabled', $true) }

    $configurations = @{}
    if ($VerifySSLCertificate) { 
        $configurations.add('verify_ssl_certificate', $true) 
    }
    else {
        $configurations.add('verify_ssl_certificate', $false) 
    }
    if ($UsePersistentConnections) { $configurations.add('use_persistent_connections', $true) }
    if ($tls_to_appserver) { $configurations.add('tls_to_appserver', $tls_to_appserver) }
    if ($auth_method_scheme_name) {
        $configurations.add('auth_method_used', @{
                'scheme_name' = $auth_method_scheme_name
            }) 
    }
    $body.add('configurations', $configurations)

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)" 
        $regToken = $response.reg_token   
        Write-Debug "Registration Token: $($regToken)" 
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Client Profile already exists"
            return $null
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return $null
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Client Profile created"
    return $regToken
}    

function Find-CMClientProfiles {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $reg_token,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_Connectors] $app_connector_type, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $status, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $sort 
    )

    Write-Debug "Getting a List of Application configured in CM"
    $endpoint = $CM_Session.REST_URL + "/data-protection/client-profiles"
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name            
    }
    if ($reg_token) {
        if ($firstset) {
            $endpoint += "&reg_token="
        }
        else {
            $endpoint += "?reg_token="
            $firstset = $true
        }
        $endpoint += $reg_token
    }
    if ($app_connector_type) {
        if ($firstset) {
            $endpoint += "&app_connector_type="
        }
        else {
            $endpoint += "?app_connector_type="
            $firstset = $true
        }
        $endpoint += $app_connector_type.ToString()
    }
    if ($status) {
        if ($firstset) {
            $endpoint += "&status="
        }
        else {
            $endpoint += "?status="
            $firstset = $true
        }
        $endpoint += $status
    }

    if ($skip) {
        if ($firstset) {
            $endpoint += "&skip="
        }
        else {
            $endpoint += "?skip="
            $firstset = $true
        }
        $endpoint += $skip
    }
    if ($limit) {
        if ($firstset) {
            $endpoint += "&limit="
        }
        else {
            $endpoint += "?limit="
            $firstset = $true
        }
        $endpoint += $limit
    }
    if ($sort) {
        if ($firstset) {
            $endpoint += "&sort="
        }
        else {
            $endpoint += "?sort="
            $firstset = $true
        }
        $endpoint += $sort
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User set already exists"
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
    Write-Debug "List of ClientProfiles created"
    return $response
}    


function Remove-CMClientProfiles {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Deleting a User by ID in CM"
    $endpoint = $CM_Session.REST_URL + "/data-protection/client-profiles"
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id"

    Write-Debug "Endpoint with ID: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User set already exists"
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
    Write-Debug "Application deleted"
    return
}    

Export-ModuleMember -Function Find-CMClientProfiles
Export-ModuleMember -Function New-CMClientProfiles
Export-ModuleMember -Function Remove-CMClientProfiles

