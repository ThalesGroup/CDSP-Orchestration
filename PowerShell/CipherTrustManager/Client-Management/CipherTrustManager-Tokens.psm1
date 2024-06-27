#######################################################################################################################
# File:             CipherTrustManager-Tokens.psm1                                                                    #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - ClientMgmt Tokens Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - ClientMgmt Tokens Module"
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

####
# Local Variables
####
$target_uri = "/client-management/regtokens"
####

<#
    .SYNOPSIS
        Get-CM_AuthTokens
    .DESCRIPTION
        Returns a list of refresh tokens. 
#    .PARAMETER server
##    Specifies the IP Address or FQDN of CipherTrust Manager.
#
#    .PARAMETER credential
#    Specifies the "credential (username/password) authorized to connect with CipherTrust manager.
#
#    .INPUTS
#    None. You cannot pipe objects to Connect-CipherTrustManager.
#
#    .OUTPUTS
#    None. Connect-CipherTrustManager returns a proxy to this connection.
#
#    .EXAMPLE
#    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"
#
#    .LINK
#    Online version: <github docs>
#>

function Get-CM_AuthTokens {
    param
    (
        [string] $grant_type = "password", 
        [string] $user = $(Throw "Please specify the username with authorized access to CipherTrust Manager"), 
        [string] $pass = $(Throw "Please specify the password associated with the username") 
    )

    # {
    #     "grant_type": "password",
    #     "username": "steve",
    #     "password": "mysecretword",
    #     "labels": [
    #       "myapp",
    #       "cli"
    #     ]
    #   }

    Write-Debug "Getting token list from CipherTrust Manager..."
    Test-CMJWT
    $CM_Session.REST_URL = "https://" + ($CM_Session.KMS_IP) + "/api/v1"
    #Authenticate with CM, get JWT and set BEARER token in Headers
    return
}

function New-CM_ClientToken {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $ca_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $cert_duration,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $lifetime,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $max_clients,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $name_prefix,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $label        
    )    

    Write-Debug "Creating a new Client Registration Token on CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{}

    # Optional Parameters
    if ($ca_id) { $body.add('ca_id', $ca_id) }
    if ($cert_duration) { $body.add('cert_duration', $cert_duration) }
    if ($label) { $body.add('label', $label) }
    if ($lifetime) { $body.add('lifetime', $lifetime) }
    if ($max_clients) { $body.add('max_clients', $max_clients) }
    if ($name_prefix) { $body.add('name_prefix', $name_prefix) }
    
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
        $elementId = $response.token  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Token already exists"
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
    Write-Debug "Token created"
    return $elementId
}
    
Export-ModuleMember -Function Get-CM_AuthTokens
Export-ModuleMember -Function New-CM_ClientToken