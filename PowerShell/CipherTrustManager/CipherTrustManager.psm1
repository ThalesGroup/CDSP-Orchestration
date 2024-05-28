#######################################################################################################################
# File:             CipherTrustManager.psm1                                                                           #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Author:           Rick Leon, Professional Services                                                                  #
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
    Domain    = $null
    REST_URL  = $null
    AuthToken = $null
    refresh_token = $null
}
#New-Variable -Name CM_Session -Value $CM_Session -Scope Script -Force
New-Variable -Name CM_Session -Value $CM_Session -Scope Global -Force
#
###

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Main Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Main Module"
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
    Specifies the password (in plaintext for now) for the user. If no password is proivded a prompt will appear.

    .PARAMETER refresh_token
    Specifies the API refresh_token.

    .PARAMETER domain
    (Optional) Specify the desired CipherTrust Manager Domain to work in.

    .INPUTS
    None. You cannot pipe objects to Connect-CipherTrustManager.

    .OUTPUTS
    None. Connect-CipherTrustManager returns a proxy to this connection.

    .EXAMPLE
    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"

    .EXAMPLE
    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1"

    Enter Password : **********

    .LINK
    Online version: https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Connect-CipherTrustManager {
    param
    (
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $server, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $user,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)] 
        [string] $pass,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)] 
        [string] $refresh_token,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)] 
        [string] $domain        
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if(!$server){
        $CM_Session.KMS_IP = Read-Host "Enter CipherTrust Manager IP or FQDN "
    }else{
        $CM_Session.KMS_IP = $server
    }

    if(!$pass){
        if($refresh_token){
            $CM_Session.refresh_token = $refresh_token
        }else{
            if($user){
                $CM_Session.User = $user
            }else{
                $CM_Session.User = Read-Host "Enter user "
            }
            $CM_Session.Pass = Read-Host "Enter password " -AsSecureString
        }
    }else{
        if($user){
            $CM_Session.User = $user
        }else{
            $CM_Session.User = Read-Host "Enter user "
        }
        $CM_Session.Pass = ConvertTo-SecureString -String $pass -AsPlainText -Force
    }

    $CM_Session.Domain = $domain

    Write-Debug "Session Parameters: $($CM_Session | Format-Table | Out-String)"

    #Invoke API for token generation
    Write-Debug "Getting authentication token from $($KMS_NAME)..."
    
    $CM_Session.REST_URL = "https://" + ($CM_Session.KMS_IP) + "/api/v1"

    #Authenticate with CM, get JWT and set BEARER token in Headers
    Get-CMJWT  

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

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

    .PARAMETER domain
    (Optional) Specify the desired CipherTrust Manager Domain to work in.
    
    .INPUTS
    None. You cannot pipe objects to Connect-CipherTrustManager.

    .OUTPUTS
    None. Connect-CipherTrustManager returns a proxy to this connection.

    .EXAMPLE
    PS> Connect-CipherTrustManager -server 10.23.104.40 -user "user1" -pass "P@ssw0rd!"

    .LINK
    Online version: https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Disconnect-CipherTrustManager {
    param()

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $CM_Session.KMS_IP    = $null
    $CM_Session.User      = $null
    $CM_Session.Pass      = $null
    $CM_Session.Domain    = $null
    $CM_Session.REST_URL  = $null
    $CM_Session.AuthToken = $null
    $CM_Session.refresh_token = $null
    
    Write-Debug "Session Variables have been cleared"


    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

###
# Exports
###
#This module
Export-ModuleMember -Function Connect-CipherTrustManager
Export-ModuleMember -Function Disconnect-CipherTrustManager
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
#Info
Export-ModuleMember -Function Get-CMInfo
Export-ModuleMember -Function Get-CMVersion
Export-ModuleMember -Function Set-CMName
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
#CCKM
Export-ModuleMember -Function New-CKSAWSParam
Export-ModuleMember -Function New-CKSLocalHostedParam
Export-ModuleMember -Function New-CKS
Export-ModuleMember -Function Remove-CKS
Export-ModuleMember -Function Edit-CKS
Export-ModuleMember -Function Update-CKSPerformOperation
#Syslog Connections
Export-ModuleMember -Function Find-CMSyslogs
Export-ModuleMember -Function New-CMSyslog
Export-ModuleMember -Function Get-CMSyslog
Export-ModuleMember -Function Remove-CMSyslog
Export-ModuleMember -Function Set-CMSyslog 
#Tokens
Export-ModuleMember -Function Find-CMTokens
Export-ModuleMember -Function New-CMToken
Export-ModuleMember -Function Get-CMToken
Export-ModuleMember -Function Remove-CMToken
Export-ModuleMember -Function Revoke-CMToken
Export-ModuleMember -Function Get-CMSelfDomains
Export-ModuleMember -Function Set-CMAuthKeyRotate
Export-ModuleMember -Function Get-CMAuthKey
Export-ModuleMember -Function New-CMAkeylessToken
Export-ModuleMember -Function Clear-CMRefreshTokens
#Alarms
Export-ModuleMember -Function Find-CMAlarms
Export-ModuleMember -Function Clear-CMAlarm
Export-ModuleMember -Function Ack-CMAlarm
#AkeylessConfiguration
Export-ModuleMember -Function Get-CMAkeylessConfiguration
Export-ModuleMember -Function Set-CMAkeylessConfiguration
#Domains
Export-ModuleMember -Function Find-CMDomains
Export-ModuleMember -Function New-CMDomain
Export-ModuleMember -Function Remove-CMDomain
Export-ModuleMember -Function Get-CMDomainCurrent
Export-ModuleMember -Function Get-CMDomainSyslogRedirection 
Export-ModuleMember -Function Update-CMDomainSyslogRedirection
Export-ModuleMember -Function Find-CMDomainKEKS
Export-ModuleMember -Function Get-CMDomainKEK
Export-ModuleMember -Function Update-CMDomainRotateKEK
#Connections
Export-ModuleMember -Function Find-CMConnections
Export-ModuleMember -Function Remove-CMConnection
Export-ModuleMember -Function New-CMConnectionCSR
#Connections-AWS
Export-ModuleMember -Function Find-CMAWSConnections
Export-ModuleMember -Function New-CMAWSConnection
Export-ModuleMember -Function Get-CMAWSConnection
Export-ModuleMember -Function Update-CMAWSConnection
Export-ModuleMember -Function Remove-CMAWSConnection
Export-ModuleMember -Function Test-CMAWSConnection
Export-ModuleMember -Function Test-CMAWSConnParameters
#Connections-AKeyless
Export-ModuleMember -Function Find-CMAKeylessConnections
Export-ModuleMember -Function New-CMAKeylessConnection
Export-ModuleMember -Function Get-CMAKeylessConnection
Export-ModuleMember -Function Update-CMAKeylessConnection
Export-ModuleMember -Function Remove-CMAKeylessConnection
Export-ModuleMember -Function Test-CMAKeylessConnection
Export-ModuleMember -Function Test-CMAKeylessConnParameters
#Connection Manager - Azure
Export-ModuleMember -Function Find-CMAzureConnections
Export-ModuleMember -Function New-CMAzureConnection
Export-ModuleMember -Function Get-CMAzureConnection
Export-ModuleMember -Function Update-CMAzureConnection
Export-ModuleMember -Function Remove-CMAzureConnection
Export-ModuleMember -Function Test-CMAzureConnection
Export-ModuleMember -Function Test-CMAzureConnParameters
#Connection Manager - Elasticsearch
Export-ModuleMember -Function Find-CMElasticsearchConnections
Export-ModuleMember -Function New-CMElasticsearchConnection
Export-ModuleMember -Function Get-CMElasticsearchConnection
Export-ModuleMember -Function Update-CMElasticsearchConnection
Export-ModuleMember -Function Remove-CMElasticsearchConnection
Export-ModuleMember -Function Test-CMElasticsearchConnection
Export-ModuleMember -Function Test-CMElasticsearchConnParameters
#Connection Manager - Google
Export-ModuleMember -Function Find-CMGCPConnections
Export-ModuleMember -Function New-CMGCPConnection
Export-ModuleMember -Function Get-CMGCPConnection
Export-ModuleMember -Function Update-CMGCPConnection
Export-ModuleMember -Function Remove-CMGCPConnection
Export-ModuleMember -Function Test-CMGCPConnection
Export-ModuleMember -Function Test-CMGCPConnParameters
#Connection Manager - DSM
Export-ModuleMember -Function Find-CMDSMConnections
Export-ModuleMember -Function New-CMDSMConnection
Export-ModuleMember -Function Get-CMDSMConnection
Export-ModuleMember -Function Update-CMDSMConnection
Export-ModuleMember -Function Remove-CMDSMConnection
Export-ModuleMember -Function Test-CMDSMConnection
Export-ModuleMember -Function Test-CMDSMConnParameters
Export-ModuleMember -Function Find-CMDSMConnectionNodes
Export-ModuleMember -Function Add-CMDSMConnectionNode
Export-ModuleMember -Function Get-CMDSMConnectionNode
Export-ModuleMember -Function Update-CMDSMConnectionNode
Export-ModuleMember -Function Remove-CMDSMConnectionNode
#Connection Manager - Hadoop
Export-ModuleMember -Function Find-CMHadoopConnections
Export-ModuleMember -Function New-CMHadoopConnection
Export-ModuleMember -Function Get-CMHadoopConnection
Export-ModuleMember -Function Update-CMHadoopConnection
Export-ModuleMember -Function Remove-CMHadoopConnection
Export-ModuleMember -Function Test-CMHadoopConnection
Export-ModuleMember -Function Test-CMHadoopConnParameters
Export-ModuleMember -Function Find-CMHadoopConnectionNodes
Export-ModuleMember -Function Add-CMHadoopConnectionNode
Export-ModuleMember -Function Get-CMHadoopConnectionNode
Export-ModuleMember -Function Update-CMHadoopConnectionNode
Export-ModuleMember -Function Remove-CMHadoopConnectionNode
#Connection Manager - Loki
Export-ModuleMember -Function Find-CMLokiConnections
Export-ModuleMember -Function New-CMLokiConnection
Export-ModuleMember -Function Get-CMLokiConnection
Export-ModuleMember -Function Update-CMLokiConnection
Export-ModuleMember -Function Remove-CMLokiConnection
Export-ModuleMember -Function Test-CMLokiConnection
Export-ModuleMember -Function Test-CMLokiConnParameters
#Connection Manager - Luna HSM Servers
Export-ModuleMember -Function Find-CMLunaHSMServer
Export-ModuleMember -Function New-CMLunaHSMServer
Export-ModuleMember -Function Get-CMLunaHSMServer
Export-ModuleMember -Function Remove-CMLunaHSMServer
Export-ModuleMember -Function Remove-CMLunaHSMServerInUse
Export-ModuleMember -Function Set-CMLunaHSMServerSTCMode
Export-ModuleMember -Function Get-CMLunaClientInfo
#Connection Manager - Luna HSM Servers
Export-ModuleMember -Function Find-CMLunaHSMConnections
Export-ModuleMember -Function New-CMLunaHSMConnection
Export-ModuleMember -Function Get-CMLunaHSMConnection
Export-ModuleMember -Function Update-CMLunaHSMConnection
Export-ModuleMember -Function Remove-CMLunaHSMConnection
Export-ModuleMember -Function Add-CMLunaHSMConnectionPartition
Export-ModuleMember -Function Remove-CMLunaHSMConnectionPartition
Export-ModuleMember -Function Test-CMLunaHSMConnection
Export-ModuleMember -Function Get-CMLunaHSMConnectionStatus
Export-ModuleMember -Function Test-CMLunaHSMConnectionParameters
#Connection Manager - Luna HSM STC Partitions
Export-ModuleMember -Function Find-CMLunaHSMSTCPartitions
Export-ModuleMember -Function Register-CMLunaHSMSTCPartition
Export-ModuleMember -Function Get-CMLunaHSMSTCPartition
Export-ModuleMember -Function Remove-CMLunaHSMSTCPartition
#Connection Manager - LDAP Connections
Export-ModuleMember -Function Find-CMLDAPConnections
Export-ModuleMember -Function New-CMLDAPConnection
Export-ModuleMember -Function Get-CMLDAPConnection
Export-ModuleMember -Function Update-CMLDAPConnection
Export-ModuleMember -Function Remove-CMLDAPConnection
Export-ModuleMember -Function Test-CMLDAPConnection
Export-ModuleMember -Function Test-CMLDAPConnParameters
#Connection Manager - OIDC Connections
Export-ModuleMember -Function Find-CMOIDCConnections
Export-ModuleMember -Function New-CMOIDCConnection
Export-ModuleMember -Function Get-CMOIDCConnection
Export-ModuleMember -Function Update-CMOIDCConnection
Export-ModuleMember -Function Remove-CMOIDCConnection
#Connection Manager - Oracle Cloud Infrastructure (OCI) Connections
Export-ModuleMember -Function Find-CMOCIConnections
Export-ModuleMember -Function New-CMOCIConnection
Export-ModuleMember -Function Get-CMOCIConnection
Export-ModuleMember -Function Update-CMOCIConnection
Export-ModuleMember -Function Remove-CMOCIConnection
Export-ModuleMember -Function Test-CMOCIConnection
Export-ModuleMember -Function Test-CMOCIConnParameters
#Connection Manager - SAP Data Custodians Connections
Export-ModuleMember -Function Find-CMSAPConnections
Export-ModuleMember -Function New-CMSAPConnection
Export-ModuleMember -Function Get-CMSAPConnection
Export-ModuleMember -Function Update-CMSAPConnection
Export-ModuleMember -Function Remove-CMSAPConnection
Export-ModuleMember -Function Test-CMSAPConnection
Export-ModuleMember -Function Test-CMSAPConnParameters
#Connection Manager - SCP Connections
Export-ModuleMember -Function Find-CMSCPConnections
Export-ModuleMember -Function New-CMSCPConnection
Export-ModuleMember -Function Get-CMSCPConnection
Export-ModuleMember -Function Update-CMSCPConnection
Export-ModuleMember -Function Remove-CMSCPConnection
Export-ModuleMember -Function Test-CMSCPConnection
Export-ModuleMember -Function Test-CMSCPConnParameters
#Connection Manager - SMB Connections
Export-ModuleMember -Function Find-CMSMBConnections
Export-ModuleMember -Function New-CMSMBConnection
Export-ModuleMember -Function Get-CMSMBConnection
Export-ModuleMember -Function Update-CMSMBConnection
Export-ModuleMember -Function Remove-CMSMBConnection
Export-ModuleMember -Function Test-CMSMBConnection
Export-ModuleMember -Function Test-CMSMBConnParameters
#Connection Manager - Salesforce Connections
Export-ModuleMember -Function Find-CMSalesforceConnections
Export-ModuleMember -Function New-CMSalesforceConnection
Export-ModuleMember -Function Get-CMSalesforceConnection
Export-ModuleMember -Function Update-CMSalesforceConnection
Export-ModuleMember -Function Remove-CMSalesforceConnection
Export-ModuleMember -Function Test-CMSalesforceConnection
#Export-ModuleMember -Function Test-CMSalesforceConnParameters
#Connection Manager - Syslog Connections
Export-ModuleMember -Function Find-CMSyslogConnections
Export-ModuleMember -Function New-CMSyslogConnection
Export-ModuleMember -Function Get-CMSyslogConnection
Export-ModuleMember -Function Update-CMSyslogConnection
Export-ModuleMember -Function Remove-CMSyslogConnection
Export-ModuleMember -Function Test-CMSyslogConnection
Export-ModuleMember -Function Test-CMSyslogConnParameters
#Connection Manager - Connections (IdP)
Export-ModuleMember -Function Find-CMIdPConnections
Export-ModuleMember -Function New-CMIdPConnectionLDAP
Export-ModuleMember -Function New-CMIdPConnectionOIDC
Export-ModuleMember -Function Get-CMIdPConnection
Export-ModuleMember -Function Update-CMIdPConnectionLDAP
Export-ModuleMember -Function Update-CMIdPConnectionOIDC
Export-ModuleMember -Function Remove-CMIdPConnection
Export-ModuleMember -Function Remove-CMIdPConnectionLDAPInUse
Export-ModuleMember -Function Test-CMIdPLDAPConnParameters
Export-ModuleMember -Function Get-CMIdPConnectionUsers