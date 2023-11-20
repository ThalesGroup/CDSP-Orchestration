#######################################################################################################################
# File:             CipherTrustManager-AleylessConfiguration.psm1                                                     #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/configs/akeyless"
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


####
# ENUMS
####
####

#/v1/configs/akeyless
#/v1/configs/akeyless-get

<#
    .SYNOPSIS
        List Akeyless Configuration
#    .DESCRIPTION
#       Get the Akeyless gateway configuration parameters.
#    .EXAMPLE
#        PS> Get-CMAkeylessConfiguration
#
#        List configuration
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMAkeylessConfiguration {
    param
    ()

    Write-Debug "Getting Akeyless Configuration in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set Query - None

    Write-Debug "Endpoint w Query: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response was: $($response)"    
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            ##needs to be changed later
            Write-Error "Conflict"
            return
        }
        else {
            Write-Error "Expected 200, got $([int]$StatusCode)" -ErrorAction Stop
            return
        }
    }
    Write-Debug "Akeyless Configuration found"
    return $response
}    

#//v1/configs/akeyless
#/v1/configs/akeyless-patch

<#
    .SYNOPSIS
        Update Akeyless Configuration
    .DESCRIPTION
        Modify the Akeyless configuration. 
        Specify an existing Akeyless connection whose access key-id and access key will be used by the Akeyless gateway. 
        Specify the akeyless access key-id that will be used for SSO.
    .PARAMETER gateway_connection_id
        ID of an existing Akeyless connection
    .PARAMETER sso_connection_id
        ID of an existing Akeyless access key-id that will be used for SSO
    .EXAMPLE
        PS> Clear-CMAlarm -alarm_id <alarm id>

        Clears an alarm by setting clearedAt to the current date, clearedBy to this user and alarm state to off.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMAkeylessConfiguration {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $gateway_connection_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $sso_connection_id    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    # Mandatory Parameters - None
    $body = @{}

    # Optional Parameters    
    #There should be at least ONE parameter to change else why bother
    if ($gateway_connection_id -or $sso_connection_id) {
        if ($gateway_connection_id) { $body.add('gateway_connection_id', $gateway_connection_id) }
        if ($sso_connection_id) { $body.add('sso_connection_id', $sso_connection_id) }
    }
    else {
        Write-Output "At least one parameter should be provided for an update"
        return
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod  -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to update configuration" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): no message" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        elseif ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Akeyless Configuration updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    
####
# Export Module Members
####
#AkeylessConfiguration
#/v1/configs/akeyless
#/v1/configs/akeyless-get
Export-ModuleMember -Function Get-CMAkeylessConfiguration     #Get (get)

#/v1/configs/akeyless
#/v1/configs/akeyless-patch
Export-ModuleMember -Function Set-CMAkeylessConfiguration     #Set (patch)
