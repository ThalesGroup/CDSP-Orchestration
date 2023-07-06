#######################################################################################################################
# File:             CipherTrustManager-SyslogConnections.psm1                                                                  #
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
   public enum CM_SyslogTransportTypes {
    udp,
    tcp,
    tls
}
"@

####
# Local Variables
####
$target_uri = "/configs/syslogs"
####

#This project mirrors the "Syslog Connections" section of the API Playground of CM (/playground_v2/api/configs/syslogs)

#Syslog Connections
#"#/v1/configs/syslogs/"
#"#/v1/configs/syslogs/-get"
<#
    .SYNOPSIS
        List Syslog Connections
    .DESCRIPTION
        Returns a list of all syslog connections. The results can be filtered, using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters.
    .PARAMETER transport
        Filter by the transport type of the syslog connection ('udp', 'tcp', or 'tls')
    .PARAMETER host
        Filter by the hostname or ip address of the syslog connection
    .PARAMETER port 
        Filter by the port of the syslog connection
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Find-CMSyslogs 

        Returns a list of all syslog connections 
    .EXAMPLE
        PS> Find-CMSyslogs -transport "tls"

        Returns a list of all syslog connections that are using TLS for transport 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMSyslogs {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CM_SyslogTransportTypes] $transport, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $hostname,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $port, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of Syslog Connections in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    # Mandatory Parameters
    $body = @{
        'name' = $name
    }    
    # Optional Parameters
    if ($transport) { $body.add('transport', $transport.ToString()) }
    if ($hostname) { $body.add('host', $hostname) }
    if ($port) { $body.add('port', $port) }
    if ($skip) { $body.add('skip', $skip) }
    if ($limit) { $body.add('limit', $limit) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Write-Debug "Endpoint w Query: $($endpoint)"
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
    }
    Write-Debug "List of users created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#"#/v1/configs/syslogs/-post"
#"#/v1/configs/syslogs/{id}"
#"#/v1/configs/syslogs/{id}-get"
#"#/v1/configs/syslogs/{id}-delete"
#"#/v1/configs/syslogs/{id}-patch"

####
# Export Module Members
####
#Syslog Connections
#"#/v1/configs/syslogs/"
Export-ModuleMember -Function Find-CMSyslogs     #List (get)
Export-ModuleMember -Function New-CMSyslog      #Create (post)

#"#/v1/configs/syslogs/{id}"
Export-ModuleMember -Function Get-CMSyslog      #Get (get)
Export-ModuleMember -Function Remove-CMSyslog   #Delete (delete)
Export-ModuleMember -Function Set-CMSyslog      #Update (patch)