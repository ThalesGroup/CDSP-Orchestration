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
#Transport Types
Add-Type -TypeDefinition @"
public enum CM_SyslogTransportTypes {
    udp,
    tcp,
    tls
}
"@

#Message Format Types
Add-Type -TypeDefinition @"
public enum CM_SyslogMessageFormats {
    rfc5424,
    plain_message,
    cef,
    leef
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
        Currently supported transport types are listed in [CM_SyslogTransportTypes] enum
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

#Syslog Connections
#"#/v1/configs/syslogs/"
#"#/v1/configs/syslogs/-post"

<#
    .SYNOPSIS
        Create a new Syslog Connection
    .DESCRIPTION
        This creates a new syslog connection to stream audit records to. 
        By default audit records are stored in the local database and will continue to do so even if syslog connections are configured. 
        Each audit record will be sent to each configured syslog connection.
        A syslog connection can either use UDP, TCP or TCP + TLS as the transport protocol. When TCP + TLS is used a trusted CA certificate in PEM format must also be provided.
        All syslog messages are generated with facility local0.
        Available log message format are:
            rfc5424 (default)
            plain_message
            cef
            leef
        An example entry looks as follows:
            Plain Message:
                2019-08-12 06:25:12 ciphertrust CipherTrust: 2019-08-12 06:25:12 | 'Update Syslog Connection' succeeded ({"createdAt":"2019-08-12T06:25:12.380743Z","details":{"id":"e847e529-d331-45f9-a494-83ee7ce6ab69"},"message":"Update Syslog Connection","service":"kylo","success":true,"username":"admin","severity":"info","clientIP":"","source":""})
            RFC5424:
                2019-08-12 06:22:16 ciphertrust CipherTrust: <134>1 2019-08-12 06:22:16 ciphertrust CipherTrust - b7999852-dd64-46e9-b924-c3999eca9fad [msg="Update Syslog Connection" sev="6" details="'Update Syslog Connection' succeeded ({"createdAt":"2019-08-12T06:22:16.113081Z","details":{"id":"e847e529-d331-45f9-a494-83ee7ce6ab69"},"message":"Update Syslog Connection","service":"kylo","success":true,"username":"admin","severity":"info","clientIP":"","source":""})"]
            CEF:
                2019-08-05 11:40:19 ciphertrust CipherTrust: 2019-08-05 11:40:19 ciphertrust CEF:0|Thales Group|CipherTrust|Development|34a71dbf-26d2-47ea-b66d-44e38d0f6c99|Update Syslog Connection|6|'Update Syslog Connection' succeeded ({"createdAt":"2019-08-12T06:14:54.762963Z","details":{"id":"e847e529-d331-45f9-a494-83ee7ce6ab69"},"message":"Update Syslog Connection","service":"kylo","success":true,"username":"admin","severity":"info","clientIP":"","source":""})
            LEEF:
                2019-08-05 12:39:03 ciphertrust CipherTrust: 2019-08-05 12:39:03 ciphertrust LEEF:2|Thales Group|CipherTrust|Development|Update Syslog Connection|{"name":"Update Syslog Connection","sev":"6","details":"'Update Syslog Connection' succeeded ({"createdAt":"2019-08-12T06:20:06.926665Z","details":{"id":"e847e529-d331-45f9-a494-83ee7ce6ab69"},"message":"Update Syslog Connection","service":"kylo","success":true,"username":"admin","severity":"info","clientIP":"","source":""})
        The first time stamp is generated and added by syslog and the second time stamp is the time of the actual audit record.
        In a multi-node clustered environment the syslog connections configuration will be automatically synchronized and each node will be aware of all syslog servers. The syslog message will be sent from the currently active node. This means that if an event that results in an audit record is performed on node 1 the syslog message will originate from node 1, in a similar manner if an audit event is performed on node 2 the syslog message will in this case originate from node 2.
        Please note that it can take up to 5 minutes before the syslog connections configuration is applied to all nodes in the cluster.
    .PARAMETER transport
        Transport type of the syslog connection ('udp', 'tcp', or 'tls')
        Currently supported transport types are listed in [CM_SyslogTransportTypes] enum
    .PARAMETER host
        Hostname or ip address of the syslog connection
    .PARAMETER port 
        Port of the syslog connection
    .PARAMETER caCert
        The trusted CA cert in PEM format. Only used in TLS transport mode
    .PARAMETER messageFormat
        The log message format for new log messages:
            rfc5424 (default)
            plain_message
            cef
            leef
        Currently supported transport types are listed in [CM_SyslogMessageFormats] enum
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -ps_creds <PSCredential>

        This creates a User with basic settings using a PSCredential.
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -username <account name> -secure_password <SecureString>

        This creates a User with basic settings. Password is provided in SecureString
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -username <account name> -password <plaintext>

        This creates a User with basic settings. Password is provided in plaintext (least secure)
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMSyslog {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [CM_SyslogTransportTypes] $transport, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $hostname,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $port,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $caCert,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [CM_SyslogMessageFormats] $messageFormat
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Syslog Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'host' = $hostname
        'transport' = $transport.ToString()
    }

    if($caCert -And $transport -eq [CM_SyslogTransportTypes]::tls) {$body.add('caCert',$caCert)}
    if($messageFormat) {$body.add('messageFormat',$messageFormat.ToString())}
    if($port) {$body.add('port',$port)}

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
    }
    Write-Debug "User created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Syslog Connections
#"#/v1/configs/syslogs/{id}"
#"#/v1/configs/syslogs/{id}-get"


#Syslog Connections
#"#/v1/configs/syslogs/{id}"
#"#/v1/configs/syslogs/{id}-delete"


#Syslog Connections
#"#/v1/configs/syslogs/{id}"
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