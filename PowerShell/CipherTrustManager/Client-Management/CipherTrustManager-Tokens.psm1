#######################################################################################################################
# File:             CipherTrustManager-Tokens.psm1                                                                    #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

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
    
Export-ModuleMember -Function Get-CM_AuthTokens
