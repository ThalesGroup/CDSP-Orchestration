#######################################################################################################################
# File:             CipherTrustManager-Interfaces.psm1                                                                #
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
   public enum CM_InterfaceTypes {
    nae,
    kmip,
    snmp
}
"@
#
#Interface Modes
# Add-Type -TypeDefinition @"
#    public enum CM_InterfaceModes {
#     no-tls-pw-opt, 
#     no-tls-pw-req, 
#     unauth-tls-pw-opt, 
#     tls-cert-opt-pw-opt, 
#     tls-pw-opt, 
#     tls-pw-req, 
#     tls-cert-pw-opt, 
#     tls-cert-and-pw
# }
# "@
# Cannot use enums with hypens
#
#
#TLS
Add-Type -TypeDefinition @"
   public enum CM_TLSVersion {
    tls_1_0,
    tls_1_1,
    tls_1_2,
    tls_1_3
}
"@
#
#
Add-Type -TypeDefinition @"
   public enum CM_CertUserFieldOptions {
    CN,
    SN,
    E,
    E_ND, 
    UID,
    OU
}
"@
####

####
# Local Variables
####
$target_uri = "/configs/interfaces"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    $PSDefaultParameterValues = @{"Invoke-RestMethod:SkipCertificateCheck"=$True} 
    $PSDefaultParameterValues = @{"ConvertTo-JSON:Depth"=5}
}else{
    $PSDefaultParameterValues = @{"ConvertTo-JSON:Depth"=5}
    # Allow the use of self signed certificates and set TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # C# class to create callback
    $code = @"
    public class SSLHandler
    {
        public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
        {
            return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });
        }
    }
"@
    # Compile the class
    Add-Type -TypeDefinition $code

    #disable checks using new class
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
}


<#
    .SYNOPSIS
        Add a new interface
    .DESCRIPTION
        An interface is an externally exposed service. This API basically opens a new port in the system and starts a service to listen on that port.
        Currently supported interface types are listed in [CM_InterfaceTypes] enum
        NAE by default listens to port 9000 and kmip by default listens to port 5696. This route offers the capability to make nae and kmip listen on additional ports on specific network interfaces and with different settings.
    .PARAMETER port 
        The new interface will listen on the specified port.
        The port number should not be negative, 0 or the one already in-use.
    .PARAMETER auto_gen_ca_id
        Auto-generate a new server certificate on server startup using the identifier (URI) of a Local CA resource if the current server certificate is issued by a different Local CA. 
        This is especially useful when a new node joins the cluster. In this case, the existing data of the joining node is overwritten by the data in the cluster. 
        A new server certificate is generated on the joining node using the existing Local CA of the cluster. 
        Auto-generation of the server certificate can be disabled by setting `auto_gen_ca_id` to an empty string ("") to allow full control over the server certificate.
    .PARAMETER auto_registration
        Set auto registration to allow auto registration of kmip clients. 
    .PARAMETER cert_user_field
        Specifies how the user name is extracted from the client certificate. 
        Allowed values are listed in [CM_CertUserFieldOptions] enum. 
        Refer to the top level discussion of the Interfaces section for more details.
    .PARAMETER custom_uid_size
        This flag is used to define the custom uid size of managed object over the KMIP interface.
    .PARAMETER custom_uid_v2
        This flag specifies which version of custom uid feature is to be used for KMIP interface. If it is set to true, new implementation (i.e. Custom uid version 2) will be used.
    .PARAMETER default_connection
        The default connection may be "local_account" for local authentication or the LDAP domain for LDAP authentication. 
        This value is applied when the username does not embed the connection name (e.g. "jdoe" effectively becomes "local_account|jdoe"). 
        This value only applies to NAE only and is ignored if set for web and KMIP interfaces.
    .PARAMETER interfaceType
        This parameter is used to identify the type of interface, what service to run on the interface.
        Currently supported types are listed in [CM_InterfaceTypes] enum.
        Defaults to `nae` if not specified.
    .PARAMETER kmip_enable_hard_delete
        Enables hard delete of keys on KMIP Destroy operation, that is both meta-data and material will be removed from CipherTrust Manager for the key being deleted. 
        By default, only key material is removed and meta-data is preserved with the updated key state. 
        This setting applies only to KMIP interface. Should be set to 1 for enabling the feature or 0 for returning to default behavior.
    .PARAMETER maximum_tls_version
        Maximum TLS version to be configured for NAE or KMIP interface, default is latest maximum supported protocol.
        Currently supported tls versions are listed in [CM_TLSVersion] enum.
    .PARAMETER nae_mask_system_groups
        Flag for masking system groups in NAE requests
    .PARAMETER minimum_tls_version
        Minimum TLS version to be configured for NAE or KMIP interface, default is v1.2 (tls_1_2).
        Currently supported tls versions are listed in [CM_TLSVersion] enum.
    .PARAMETER mode
        The interface mode can be one of the modes listed in [CM_InterfaceModes] enum. 
        Default mode is `no-tls-pw-opt`. 
        Refer to the top level discussion of the Interface section for further details.
    .PARAMETER name
        The name of the interface. 
        Not valid for interface_type nae.
    .PARAMETER network_interface
        Defines what ethernet adapter the interface should listen to, use "all" for all.
        The available ethernet adapters in the system can for example be retrived from the `GET /v1/system/network/interfaces` route.

        To open the same port on other ethernet adapters it is possible to use the same port on other ethernet adapter.
        Defaults to `all` if not specified.
    .PARAMETER registration_token
        Registration token in case auto registration is true.
    .PARAMETER trusted_cas_local
        Collection of local CA IDs to trust for client authentication. See section "Certificate Authority" for more details.
    .PARAMETER trusted_cas_external
        Collection of external CA IDs to trust for client authentication. See section "Certificate Authority" for more details.
    # .EXAMPLE
    #     PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

    #     This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

    #     This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMInterface {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int] $port, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $auto_gen_ca_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $auto_registration,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_CertUserFieldOptions] $cert_user_field,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $custom_uid_size,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $custom_uid_v2,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $default_connection,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CM_InterfaceTypes] $interfaceType, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $kmip_enable_hard_delete,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_TLSVersion] $maximum_tls_version,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $nae_mask_system_groups,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_TLSVersion] $minimum_tls_version,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $mode,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $network_interface,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $registration_token,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $trusted_cas_local,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $trusted_cas_external
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Adding an Interface in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    $interfaceID = $null
    
    # Mandatory Parameters
    $body = @{
        'port' = $port
    }

    # Optional Parameters
    if ($auto_gen_ca_id) { $body.add('auto_gen_ca_id', $auto_gen_ca_id) }
    if ($auto_registration) { $body.add('auto_registration', $true) } 
    if ($null -ne $cert_user_field) { $body.add('cert_user_field', $cert_user_field.ToString()) }
    if ($auto_registration) { $body.add('custom_uid_size', $custom_uid_size) } 
    if ($custom_uid_v2) { $body.add('custom_uid_v2', $true) }
    if ($default_connection) { $body.add('default_connection', $default_connection) } 
    if ($interfaceType) { $body.add('interfaceType', $interfaceType.ToString()) }
    if ($kmip_enable_hard_delete) { $body.add('kmip_enable_hard_delete', $kmip_enable_hard_delete) }     
    if ($maximum_tls_version) { $body.add('maximum_tls_version', $maximum_tls_version) }
    if ($nae_mask_system_groups) { $body.add('nae_mask_system_groups', $nae_mask_system_groups) } 
    if ($minimum_tls_version) { $body.add('minimum_tls_version', $minimum_tls_version) }
    if ($mode) { $body.add('mode', $mode) } 
    if ($name) { $body.add('name', $name) }
    if ($network_interface) { $body.add('network_interface', $network_interface) } 
    if ($registration_token) { $body.add('registration_token', $registration_token) }

    if ($trusted_cas_local -OR $trusted_cas_external) { 
        $trusted_cas = @{}
        #local cas
        if (($trusted_cas_local -is [String])) { 
            if ($trusted_cas_local) {
                #CA came in as a single string...convert to array
                $trusted_cas.add('local', @($trusted_cas_local)) 
            }
            else {
                #CA is empty...convert to blank array
                $trusted_cas.add('local', @()) 
            }
        }
        else {
            #CA came in as an array
            $trusted_cas.add('local', $trusted_cas_local) 
        } 
        
        #external cas
        if (($trusted_cas_external -is [String])) { 
            if ($trusted_cas_external) {
                #CA came in as a single string...convert to array
                $trusted_cas.add('external', @($trusted_cas_external)) 
            }
            else {
                #CA is empty...convert to blank array
                $trusted_cas.add('external', @()) 
            }
        }
        else {
            #CA came in as an array
            $trusted_cas.add('external', $trusted_cas_external) 
        } 
        $body.add('trusted_cas', $trusted_cas)
    }
    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"    
        $interfaceID = $response.id

    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Interface already exists on that port"
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
    Write-Debug "Interface added"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $interfaceID
}    

<#
    .SYNOPSIS
        Returns a string list of all the interface names
    .PARAMETER name
        Filters results to those with matching names.
    .PARAMETER interface_type
        Filters results by interface_type.
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    # .EXAMPLE
    #     PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

    #     This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

    #     This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMInterfaces {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $interface_type, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting a List of Interfaces configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    $firstset = $false #can skip if there is only one mandatory element
    if ($name) {
        if ($firstset) {
            $endpoint += "&name="
        }
        else {
            $endpoint += "?name="
            $firstset = $true
        }
        $endpoint += $name
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

    Write-Debug "Endpoint w Query: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "List of Interfaces created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    


<#
    .SYNOPSIS
        Delete an interface by name
    .DESCRIPTION
        Delete given interface.

        Interfaces with name web, kmip and nae cannot be deleted.
    .PARAMETER name
        The name of the interface. 
        Not valid for interface_type nae.
    # .EXAMPLE
    #     PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

    #     This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

    #     This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    # .EXAMPLE
    #     PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

    #     This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMInterface {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Deleting a Interface by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$name"

    Write-Debug "Endpoint with ID: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User set already exists"
            return
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::BadRequest) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to find an Interface by that name to delete"
            return
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::NotFound) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to find an Interface by that name to delete"
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

    Write-Debug "Interface deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    

Export-ModuleMember -Function Find-CMInterfaces
Export-ModuleMember -Function New-CMInterface
Export-ModuleMember -Function Remove-CMInterface
