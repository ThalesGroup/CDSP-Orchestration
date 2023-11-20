#######################################################################################################################
# File:             CipherTrustManager-Alarms.psm1                                                                    #
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
$target_uri = "/system/alarms"
$target_clear = "/clear"
$target_ack = "/acknowledge"
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
#Alarm Severity Types
Add-Type -TypeDefinition @"
public enum CM_AlarmSeverityTypes {
    emergency,
    alert,
    critical,
    error,
    warning,
    notice,
    info
}
"@

#Source Types
Add-Type -TypeDefinition @"
public enum CM_AlarmSourceTypes {
    server_record,
    client_record
}
"@
####

#/v1/system/alarms
#/v1/system/alarms/-get

<#
    .SYNOPSIS
        List Alarms
#    .DESCRIPTION
#        This allows you to list all alrms.
#        The alarms API displays the state of CipherTrust Manager alarms. Each alarm has a unique name. Examples of alarm state are on, off, unknown, etc. Each alarm has a severity, which are listed below
#        Results can be refined with query params.
#    .EXAMPLE
#        PS> Get-CMAlarms
#
#        Lists alarms. Results can be refined with query params.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMAlarms {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $state,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_AlarmSeverityTypes] $severity,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $source,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_AlarmSourceTypes] $source_type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )

    Write-Debug "Getting a List of Alarms in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name
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
    if ($severity) {
        if ($firstset) {
            $endpoint += "&severity="
        }
        else {
            $endpoint += "?severity="
            $firstset = $true
        }
        $endpoint += $severity.ToString()
    }
    if ($source) {
        if ($firstset) {
            $endpoint += "&source="
        }
        else {
            $endpoint += "?source="
            $firstset = $true
        }
        $endpoint += $source
    }
    if ($source_type) {
        if ($firstset) {
            $endpoint += "&source_type="
        }
        else {
            $endpoint += "?source_type="
            $firstset = $true
        }
        $endpoint += $source_type.ToString()
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
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response was: $($response)"    
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
    Write-Debug "Alarm(s) found"
    return $response
}    

#/v1/system/alarms/{id}/clear
#/v1/system/alarms/{id}/clear-post

<#
    .SYNOPSIS
        Clear alarm by alarmID
    .DESCRIPTION
        Clears an alarm by setting clearedAt to the current date, clearedBy to this user and alarm state to off. The intention behind clear is that when a user clears an alarm it means that the alarm is no longer applicable, was determined not be an issue, etc.
    .PARAMETER alarm_id
        ID of alarm to be cleared. Use Find-CMAlarms to get alarm_id
    .EXAMPLE
        PS> Clear-CMAlarm -alarm_id <alarm id>

        Clears an alarm by setting clearedAt to the current date, clearedBy to this user and alarm state to off.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Clear-CMAlarm {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $alarm_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Clearing speficied Alarm in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $endpoint += "/"
    $endpoint += $alarm_id
    $endpoint += $target_clear

    Write-Debug "Endpoint w Params: $($endpoint)"

    # Mandatory Parameters - None
    $body = @{}

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to clear alarm" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Alarm already cleared" -ErrorAction Continue
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
    Write-Debug "Alarm cleared"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#/v1/system/alarms/{id}/acknowledge
#/v1/system/alarms/{id}/acknowledge-post

<#
    .SYNOPSIS
        Acknowledge alarm by alarmID
    .DESCRIPTION
        Clears an alarm by setting clearedAt to the current date, clearedBy to this user and alarm state to off. 
        The intention behind clear is that when a user clears an alarm it means that the alarm is no longer applicable, was determined not be an issue, etc.
    .PARAMETER alarm_id
        ID of alarm to be cleared. Use Find-CMAlarms to get alarm_id
    .EXAMPLE
        PS> Ack-CMAlarm -alarm_id <alarm id>

       Acknowledges an alarm by setting acknowledgedAt to the current date and acknowledgedBy to this user.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Ack-CMAlarm {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $alarm_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Acknowledging speficied Alarm in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $endpoint += "/"
    $endpoint += $alarm_id
    $endpoint += $target_ack

    Write-Debug "Endpoint w Params: $($endpoint)"

    # Mandatory Parameters - None
    $body = @{}

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to acknowledge alarm" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Alarm already acknowledged" -ErrorAction Continue
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
    Write-Debug "Alarm acknoledged"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

####
# Export Module Members
####
#Alarms
#/v1/system/alarms
#/v1/system/alarms/-get
Export-ModuleMember -Function Find-CMAlarms     #List (get)
#/v1/system/alarms/{id}/clear
#/v1/system/alarms/{id}/clear-post
Export-ModuleMember -Function Clear-CMAlarm     #Clear (post)

#/v1/system/alarms/{id}/acknowledge
#/v1/system/alarms/{id}/acknowledge-post
Export-ModuleMember -Function Ack-CMAlarm       #Ack (post)
