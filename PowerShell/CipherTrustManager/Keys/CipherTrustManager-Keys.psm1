#######################################################################################################################
# File:             CipherTrustManager-Keys.psm1                                                                    #
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
#Usage Masks
[flags()] Enum UsageMaskTable {
    Sign = 1 
    Verify = 2 
    Encrypt = 4
    Decrypt = 8 
    WrapKey = 16 
    UnwrapKey = 32
    Export = 64 
    MACGenerate = 128 
    MACVerify = 256 
    DeriveKey = 512
    ContentCommitment = 1024 
    KeyAgreement = 2048
    CertificateSign = 4096 
    CRLSign = 8192
    GenerateCryptogram = 16384
    ValidateCryptogram = 32768 
    TranslateEncrypt = 65536 
    TranslateDecrypt = 131072 
    TranslateWrap = 262144
    TranslateUnwrap = 524288 
    FPEEncrypt = 1048576
    FPEDecrypt = 2097152 
}
###
# Supported Algorithms
Add-Type -TypeDefinition @"
   public enum KeyAlgorithms {
    aes,
    tdes,
    rsa,
    ec,
    seed,
    aria,
    opaque
}
"@
# Was not able to include in enum due to hyphen
#    hmac-sha1,
#    hmac-sha256,
#    hmac-sha384,
#    hmac-sha512,
#
####



####
# Local Variables
####
$target_uri = "/vault/keys2"
$target_search_uri = "/vault/query-keys/"
####



<#
    .SYNOPSIS
        Create a key in CipherTrust Manager
    .DESCRIPTION
        Keys are the cryptographic material used in crypto operations.

        Keys can be symmetric or asymmetric, in various sizes and algorithms. The crypto endpoints take key identifiers as parameters to specify which key to use. If the key is exportable, the key material can be exported to the caller and used for local encryption.
    .PARAMETER keyname 
        Friendly name. The key name should not contain special characters such as angular brackets (<,>) and backslash ().
    .PARAMETER usageMask 
        Cryptographic usage mask. Add the usage masks to allow certain usages based on [UsageMaskTable] enum 
        Add the usage mask values to allow the usages. To set all usage mask bits, use 4194303.
    .PARAMETER algorithm
        Cryptographic algorithm this key is used with based on [KeyAlgorithms] enum. Defaults to 'aes'
    .PARAMETER size
        Bit length for the key
    .PARAMETER Unexportable
        Key is NOT Exportable. Defaults to false
    .PARAMETER Undeletable   
        Key is NOT Deletable. Defaults to false
    .PARAMETER NoVersionedKey
        Key does not have versioning. This is a fixed key that cannot be rotated. Default is `versioned keys`
    .EXAMPLE
        PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

        This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $name -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

        This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    .EXAMPLE
        PS> New-CMKey -keyname $name -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

        This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $name -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

        This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMKey {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [UsageMaskTable] $usageMask, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("algo")]
        [KeyAlgorithms] $algorithm = "aes", 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int] $size,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $ownerId,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [switch] $Unexportable = $false,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [switch] $Undeletable = $false,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [switch] $NoVersionedKey = $false
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Key in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    $keyID = $null

    $body = @{
        'name'      = "$name"
        'usageMask' = [int]$usageMask
        'algorithm' = "$algorithm"
        'size'      = 256
    }

    # Optional
    if ($Unexportable) { $body.add('unexportable', $true) }
    if ($Undeletable) { $body.add('undeletable', $true) }

    if ($ownerId -OR $versionedKey) { 
        $meta = @{}
        if ($ownerId) {
            $meta.add('ownerId', $ownerId) 
        }
        if (-NOT $NoVersionedKey) { $meta.add('versionedKey', $true) }
        $body.add('meta', $meta)
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer " + $CM_Session.AuthToken
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'Post' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $keyID = $response.id
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Conflict: Key already exists by that name" -ErrorAction Continue
        }
        else {
            Write-Error "Expected 200, got $([int]$StatusCode)" -ErrorAction Stop
        }
    }

    Write-Debug $keyID
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $keyID
}    

#             "uri": [
#                 string
#             ]
#         },
#         "issuerDNFields": {
#             "c": [
#                 string
#             ],
#             "cn": string,
#             "dc": [
#                 string
#             ],
#             "dnq": [
#                 string
#             ],
#             "email": [
#                 string
#             ],
#             "l": [
#                 string
#             ],
#             "o": [
#                 string
#             ],
#             "ou": [
#                 string
#             ],
#             "sn": string,
#             "st": [
#                 string
#             ],
#             "street": [
#                 string
#             ],
#             "t": [
#                 string
#             ],
#             "uid": [
#                 string
#             ]
#         },
#         "serialNumber": string,
#         "subjectANFields": {
#             "dns": [
#                 string
#             ],
#             "emailAddress": [
#                 string
#             ],
#             "ipAddress": [
#                 string
#             ],
#             "uri": [
#                 string
#             ]
#         },
#         "subjectDNFields": {
#             "c": [
#                 string
#             ],
#             "cn": string,
#             "dc": [
#                 string
#             ],
#             "dnq": [
#                 string
#             ],
#             "email": [
#                 string
#             ],
#             "l": [
#                 string
#             ],
#             "o": [
#                 string
#             ],
#             "ou": [
#                 string
#             ],
#             "sn": string,
#             "st": [
#                 string
#             ],
#             "street": [
#                 string
#             ],
#             "t": [
#                 string
#             ],
#             "uid": [
#                 string
#             ]
#         },
#         "x509SerialNumber": string
#     },
#     "compareIDWithUUID": string,
#     "compromiseAfter": string,
#     "compromiseAt": string,
#     "compromiseBefore": string,
#     "compromiseOccurranceAfter": string,
#     "compromiseOccurranceAt": string,
#     "compromiseOccurranceBefore": string,
#     "createdAfter": string,
#     "createdAt": string,
#     "createdBefore": string,
#     "curveIDs": [
#         string
#     ],
#     "deactivationAfter": string,
#     "deactivationAt": string,
#     "deactivationBefore": string,
#     "destroyAfter": string,
#     "destroyAt": string,
#     "destroyBefore": string,
#     "id": string,
#     "labels": {    },
#     "limit": integer,
#     "linkTypes": [
#         string
#     ],
#     "metaContains": string,
#     "neverExportable": boolean,
#     "neverExported": boolean,
#     "objectTypes": [
#         string
#     ],
#     "processStartAfter": string,
#     "processStartAt": string,
#     "processStartBefore": string,
#     "protectStopAfter": string,
#     "protectStopAt": string,
#     "protectStopBefore": string,
#     "returnOnlyIDs": boolean,
#     "revocationReason": string,
#     "revocationReasons": [
#         string
#     ],
#     "rotationDateReached": boolean,
#     "sha1Fingerprint": string,
#     "sha1Fingerprints": [
#         string
#     ],
#     "sha256Fingerprint": string,
#     "sha256Fingerprints": [
#         string
#     ],
#     "size": integer,
#     "sizes": [
#         integer
#     ],
#     "skip": integer,
#     "states": [
#         string
#     ],
#     "unexportable": boolean,
#     "updatedAfter": string,
#     "updatedAt": string,
#     "updatedBefore": string,
#     "uri": string,
#     "usageMasks": [
#         integer
#     ],
#     "version": integer,
#     "versions": [
#         integer
#     ]
# }

<#
    .SYNOPSIS
        Find-CMKeys
    .DESCRIPTION
        This operation uses `query-keys` and searches for keys stored on the CipherTrust Manager. The operation is similar to the list operation. The differences are (a) a lot more search parameters can be passed in, and (b) the search parameters are passed in the body of an HTTP POST request instead of being passed as query parameters in a HTTP GET request. Normally, this operation returns a list of keys, secrets, etc., that satisfy the search criteria. When the returnOnlyIDs input parameter is specified as true, this operation just returns a list of key IDs.
    .PARAMETER keyname
        Filters results to those with matching names.  The '?' and '*' wildcard characters may be used.

    .PARAMETER usageMask
        Deprecated: Use 'usageMasks'.
        Filters results to those with matching Cryptographic usage maskbased on [UsageMaskTable] enum
    .PARAMETER algorithm
        Deprecated: Use 'algorithms'. Filters results to those with matching algorithms based on [KeyAlgorithms] enum.
        The '?' and '*' wildcard characters may be used.
    .PARAMETER size
        Deprecated: Use 'sizes'. Filters results to those with matching size.
    .PARAMETER Unexportable
        Find keys with the specified value of the `unexportable` parameter (opposite of the KMIP `Extractable` parameter).    
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
#    .INPUTS
#    None. You cannot pipe objects to Connect-CipherTrustManager.
#
#    .OUTPUTS
#    None. Connect-CipherTrustManager returns a proxy to this connection.
#
#    .EXAMPLE
#    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


function Find-CMKeys {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [UsageMaskTable] $usageMask, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [Alias("algo")]
        [string] $algorithm, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [int] $size,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [switch] $Unexportable,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )

    Write-Debug "Getting a List of Keys configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_search_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{}

    # Optional Parameters
    if ($name) { $body.add('name', $name) }
    if ($usageMask) { $body.add('usageMask', [int]$usageMask) }
    if ($algorithm) { $body.add('algorithm', $algorithm) }
    if ($size) { $body.add('size', $size) }

    if ($Unexportable) { $body.add('unexportable', $true) }
    
    if ($skip) {
        $endpoint += "&skip="
        $endpoint += $skip
    }

    if ($limit) {
        $endpoint += "&limit="
        $endpoint += $limit
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Headers: $($response)"    
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
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::NotFound) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to find a Key by those parameters to delete"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of Keys created"
    return $response
}    


<#
    .SYNOPSIS
        Remove-CMKey
    .DESCRIPTION
        This operation deletes a key by id.
    .PARAMETER id
        Filters results to those with matching names.  The '?' and '*' wildcard characters may be used.
    .PARAMETER version
        Specifies the key version: Default is latest version
    .PARAMETER type
        Specify the type of the idenfifier specified by the `name` option.
        Must be one of name, id, uri or alias.
        If not specificed, the type of the identifier is inferred
#    .INPUTS
#    None. You cannot pipe objects to Connect-CipherTrustManager.
#
#    .OUTPUTS
#    None. Connect-CipherTrustManager returns a proxy to this connection.
#
#    .EXAMPLE
#    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Remove-CMKey {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [int] $version,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $type
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Deleting a Key by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #set id which is mandatory
    $endpoint += "/$id"

    #Set query
    $firstset = $false
    if ($version) {
        $endpoint += "?version="
        $firstset = $true
        $endpoint += $version            
    }
    if ($type) {
        if ($firstset) {
            $endpoint += "&type="
        }
        else {
            $endpoint += "?type="
            $firstset = $true
        }
        $endpoint += $type
    }

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
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::NotFound) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to find a Key by that ID to delete"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Key deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    


Export-ModuleMember -Function Find-CMKeys
Export-ModuleMember -Function New-CMKey
Export-ModuleMember -Function Remove-CMKey
