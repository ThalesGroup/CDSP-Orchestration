#######################################################################################################################
# File:             CipherTrustManager.psm1                                                                           #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Usage:            To load this module in your PowerShell:                                                           #
#                   1. Open PowerShell (or PowerShell ISE).                                                           #
#                   2. Run the following commands                                                                     #
#                      Import-Module -Name CipherTrustManager                                                         #
#                      Initialize-CipherTrustManager                                                                  #
#######################################################################################################################

####
# Module Variables
#
$CM_Session = [ordered]@{
    KMS_IP    = $null
    User      = $null
    Pass      = $null
    REST_URL  = $null
    AuthToken = $null
}
#New-Variable -Name CM_Session -Value $CM_Session -Scope Script -Force
New-Variable -Name CM_Session -Value $CM_Session -Scope Global -Force
#
###

####
# Constants
#
$KMS_NAME = "CipherTrust Manager"
####

<#
    .SYNOPSIS
    Create a connection to CipherTrust Manager and store AuthToken for use in future calls

    .DESCRIPTION
    Create a connection to CipherTrust Manager and store AuthToken (JWT) for use in future calls. It uses Get-JWT to manage the lifecycle of your JWT token so it is `set and forget`

    .PARAMETER server
    Specifies the IP Address or FQDN of CipherTrust Manager.

    .PARAMETER user
    Specifies the username for the account authorized to connect with CipherTrust manager.

    .PARAMETER pass
    Specifies the password (in plaintext for now) for the user.

    .INPUTS
    None. You cannot pipe objects to Connect-CipherTrustManager.

    .OUTPUTS
    None. Connect-CipherTrustManager returns a proxy to this connection.

    .EXAMPLE
    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"

    .LINK
    Online version: https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Connect-CipherTrustManager {
    param
    (
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $server, 
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $user,
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)] 
        [string] $pass
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $CM_Session.KMS_IP = $server
    $CM_Session.User = $user
    $CM_Session.Pass = $pass

    Write-Debug "Session Parameters: $($CM_Session)"

    #Invoke API for token generation
    Write-Debug "Getting authentication token from $($KMS_NAME)..."
    
    $CM_Session.REST_URL = "https://" + ($CM_Session.KMS_IP) + "/api/v1"

    #Authenticate with CM, get JWT and set BEARER token in Headers
    Get-CMJWT  

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

###
# Exports
###
#This module
Export-ModuleMember -Function Connect-CipherTrustManager
#Utils
Export-ModuleMember -Function Get-CMJWT
Export-ModuleMember -Function Test-CMJWT
Export-ModuleMember -Function Write-HashtableArray
#Keys
Export-ModuleMember -Function Find-CMKeys
Export-ModuleMember -Function New-CMKey
Export-ModuleMember -Function Remove-CMKey
#Users
Export-ModuleMember -Function Find-CMUsers
Export-ModuleMember -Function New-CMUser
Export-ModuleMember -Function Get-CMUser
Export-ModuleMember -Function Remove-CMUser
#Tokens
Export-ModuleMember -Function Get-CM_AuthTokens
#CAs
Export-ModuleMember -Function Find-CMCAs
#Char Sets
Export-ModuleMember -Function Find-CMCharacterSets
Export-ModuleMember -Function New-CMCharacterSet
Export-ModuleMember -Function Remove-CMCharacterSet
#User Sets
Export-ModuleMember -Function Find-CMUserSets
Export-ModuleMember -Function New-CMUserSet
Export-ModuleMember -Function Remove-CMUserSet
#Masking Formats
Export-ModuleMember -Function Find-CMMaskingFormats
Export-ModuleMember -Function New-CMMaskingFormat
Export-ModuleMember -Function Remove-CMMaskingFormat
#Protection Policies
Export-ModuleMember -Function Find-CMProtectionPolicies
Export-ModuleMember -Function New-CMProtectionPolicy
Export-ModuleMember -Function Remove-CMProtectionPolicy
#Access Policies
Export-ModuleMember -Function Find-CMAccessPolicies
Export-ModuleMember -Function New-CMAccessPolicy
Export-ModuleMember -Function Remove-CMAccessPolicy
Export-ModuleMember -Function New-CMUserSetPolicy
#Interfaces
Export-ModuleMember -Function Find-CMInterfaces
Export-ModuleMember -Function New-CMInterface
Export-ModuleMember -Function Remove-CMInterface
#DPG Policies
Export-ModuleMember -Function Find-CMDPGPolicies
Export-ModuleMember -Function New-CMDPGPolicy
Export-ModuleMember -Function Remove-CMDPGPolicy
Export-ModuleMember -Function New-CMDPGProxyConfig
Export-ModuleMember -Function New-CMDPGJSONRequestResponse
#ClientProfiles
Export-ModuleMember -Function Find-CMClientProfiles
Export-ModuleMember -Function New-CMClientProfiles
Export-ModuleMember -Function Remove-CMClientProfiles
