#######################################################################################################################
# File:             CipherTrustManager-CAs.psm1                                                                    #
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
#
####

<#
    .SYNOPSIS
        List/Find Local CAs
#    .DESCRIPTION
#        This allows you to create a key on CipherTrust Manager and control a series of its parameters. Those parameters include: keyname, usageMask, algo, size, Undeleteable, Unexportable, NoVersionedKey
#    .EXAMPLE
#        PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>
#
#        This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMCAs {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $subject, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $issuer,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $state,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $cert,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )

    Write-Debug "Listing configured Local CAs"
    $endpoint = $CM_Session.REST_URL + "/ca/local-cas"
    Write-Debug "Endpoint: $($endpoint)"

    # Test that at least ONE of the search parameters was provided
    if (-NOT($subject -OR $issuer -OR $state -OR $cert -OR $id)) {
        throw "One of subject, issuer, state, cert or id must be provided"
    }

    #Set query
    $firstset = $false
    if ($subject) {
        $endpoint += "?subject="
        $firstset = $true
        $endpoint += $subject            
    }
    if ($issuer) {
        if ($firstset) {
            $endpoint += "&issuer="
        }
        else {
            $endpoint += "?issuer="
            $firstset = $true
        }
        $endpoint += $issuer
    }
    if ($state) {
        if ($firstset) {
            $endpoint += "&state="
        }
        else {
            $endpoint += "?state="
            $firstset = $true
        }
        $endpoint += $state
    }
    if ($cert) {
        if ($firstset) {
            $endpoint += "&cert="
        }
        else {
            $endpoint += "?cert="
            $firstset = $true
        }
        $endpoint += $cert
    }
    if ($id) {
        if ($firstset) {
            $endpoint += "&id="
        }
        else {
            $endpoint += "?id="
            $firstset = $true
        }
        $endpoint += $id
    }

    if ($skip) {
        $endpoint += "&skip="
        $endpoint += $skip
    }

    if ($limit) {
        $endpoint += "&limit="
        $endpoint += $limit
    }
            
    Write-Debug "Endpoint: $($endpoint)"    

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        $caID = $response.resources[0].uri
        Write-Debug "CA(s) found: $($caID)"    
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            ##needs to be changed later
            Write-Error "Conflict: Key already exists by that name"
            return
        }
        else {
            Write-Error "Expected 200, got $([int]$StatusCode)" -ErrorAction Stop
            return
        }
    }
    Write-Debug "CA(s) found"
    return "$($caID)"
}    

Export-ModuleMember -Function Find-CMCAs
