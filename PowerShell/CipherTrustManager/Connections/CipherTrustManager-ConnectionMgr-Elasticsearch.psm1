#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Elasticsearch.psm1                                               #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

###
# ENUM
###
#Supported Algorithms
Add-Type -TypeDefinition @"
   public enum transportType {
    tcp,
    tls
}
"@

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/log-forwarders/elasticsearch/connections"
$target_uri_test = "/connectionmgmt/services/log-forwarders/elasticsearch/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Elasticsearch Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Elasticsearch Module"
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


#This project mirrors the "Connection Manager - Elasticsearch Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Elasticsearch Connections)

#Connection Manager - CM Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Elastice Search Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Elasticsearch Connections
        #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections-get).   
    .PARAMETER name
        Filter by the Conection name
    .PARAMETER id
        Filter the results based on the connection's ID.
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .PARAMETER sort
        The field, or fields, to order the results by. This should be a comma-delimited list of properties.
        For example, "name,-createdAt" .. will sort the results first by 'name', ascending, then by 'createdAt', descending.
    .PARAMETER products
        Filter the results based on the CipherTrust Manager products associated with the connection. 
        Valid values are "cckm" for AWS, GCP, Azure, and Luna Connections, "ddc", "data discovery" for Hadoop connections, and "cte" for SMB connections.
    .PARAMETER meta_contains
        A valid JSON value. Only resources whose 'meta' attribute contains the JSON value will be returned.
    .PARAMETER createdBefore
        Filters results to those created at or before the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .PARAMETER createdAfter
        Filters results to those created at or after the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .PARAMETER last_connection_ok
        Filter the results based on the last_connection_ok result. (true/false or 'null' for never tested.)
    .PARAMETER last_connection_before
        Filters results to those connected to at or before the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .PARAMETER last_connection_after
        Filters results to those connected to at or after the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .PARAMETER external_certificate_used
        Filter the result based on if an external certificate is used for the connection.
    .EXAMPLE
        PS> Find-CMElastisearchConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMElasticsearchConnections {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter()] [int] $skip,
        [Parameter()] [int] $limit,
        [Parameter()] [string] $sort,
        [Parameter()] [string] $meta_contains, 
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after 
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Elastic Search Connections in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name
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
    if ($sort) {
        if ($firstset) {
            $endpoint += "&sort="
        }
        else {
            $endpoint += "?sort="
            $firstset = $true
        }
        $endpoint += $sort
    }
    if ($meta_contains) {
        if ($firstset) {
            $endpoint += "&meta_contains="
        }
        else {
            $endpoint += "?meta_contains="
            $firstset = $true
        }
        $endpoint += $meta_contains
    }
    if ($createdBefore) {
        if ($firstset) {
            $endpoint += "&createdBefore="
        }
        else {
            $endpoint += "?createdBefore="
            $firstset = $true
        }
        $endpoint += $createdBefore
    }
    if ($createdAfter) {
        if ($firstset) {
            $endpoint += "&createdAfter="
        }
        else {
            $endpoint += "?createdAfter="
            $firstset = $true
        }
        $endpoint += $createdAfter
    }
    if ($last_connection_ok) {
        if ($firstset) {
            $endpoint += "&last_connection_ok="
        }
        else {
            $endpoint += "?last_connection_ok="
            $firstset = $true
        }
        $endpoint += $last_connection_ok
    }
    if ($last_connection_before) {
        if ($firstset) {
            $endpoint += "&last_connection_before="
        }
        else {
            $endpoint += "?last_connection_before="
            $firstset = $true
        }
        $endpoint += $last_connection_before
    }
    if ($last_connection_after) {
        if ($firstset) {
            $endpoint += "&last_connection_after="
        }
        else {
            $endpoint += "?last_connection_after="
            $firstset = $true
        }
        $endpoint += $last_connection_ok
    }
    if ($external_certificate_used) {
        if ($firstset) {
            $endpoint += "&external_certificate_used=true"
        }
        else {
            $endpoint += "?external_certificate_used=true"
            $firstset = $true
        }
    }

    Write-Debug "Endpoint w Query: $($endpoint)"
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of all CM Connections to Elastic Search with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections - post"

<#
    .SYNOPSIS
    Create a new CipherTrust Manager Elasticsearch Connection 
    .DESCRIPTION
    Creates a new Elasticsearch connection. 
    .PARAMETER name
    Unique connection name.
    .PARAMETER target
    IP for Hostname/FQDN of the log-forwarder server.
    .PARAMETER port
    Port of the log-forwarder server.
    .PARAMETER description
    (Optional) Description about the connection.
    .PARAMETER ca_cert
    (Optional) CA certificate in PEM format.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER ca_certfile
    (Optional) Specify the filename for a PEM certificate for Elasticsearch CA certificate. 
    .PARAMETER http_pass
    (Optional) HTTP basic auth password.
    .PARAMETER http_user
    (Optional) HTTP basic auth username.
    .PARAMETER http_securecreds
    (Optional) Pass a PowerShell Credential Object only. Do not specify usersname or password.
    .PARAMETER insecure_tls_skip_verify
    (Optional) In TLS mode, skip server certificate validation. This setting should only be used for testing.     
    .PARAMETER transport
    (Required Transport mode for sending data, supports "tls" and "tcp". "tls" requires either a trusted CA cert or insecure TLS skip verify to be set to true. Default is "tcp".
        - tcp
        - tls
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
    PS> 
    
    .EXAMPLE
    PS> 
    
    This example uses certificate files for the External Certificate. It will import the files and convert to proper JSON format.

    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function New-CMElasticsearchConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory)] [string] $target, 
        [Parameter(Mandatory)] [int] $port, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $ca_cert, 
        [Parameter()] [string] $ca_certfile, 
        [Parameter()] [pscredential] $http_securecreds, 
        [Parameter()] [string] $http_pass,
        [Parameter()] [string] $http_user, 
        [Parameter()] [switch] $insecure_tls_skip_verify, 
        [Parameter()] [transportType] $transport, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Elasticsearch Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if((!$insecure_tls_skip_verify) -and (!$ca_cert -and !$ca_certfile)){
        return "Please provide certificate or client_secret or set insecure_tls_skip_verify to true for testing."
    }
    if ((!$http_user -or !$http_pass) -and !$http_securecreds) { return "Missing Elasticsearch Credentials. Please try again."}


    # Mandatory Parameters
    $body= [ordered] @{
        "name" = $name
        "host" = $target
        "port" = $port
        "products" = @("logger")
        "elasticsearch_params" = @{}
    }

    # Optional Parameters
    if($description){ $body.add('description', $description)}
    if($ca_certfile){ $ca_cert = (Get-Content $ca_certfile -raw)}
        if($ca_cert){ $body.elasticsearch_params.add('ca_cert', $ca_cert)}
    if($http_securecreds){
        Write-Debug "What is my credential user? $($http_securecreds.username)" 
        Write-debug "What is my credential password? $($http_securecreds.password | ConvertFrom-SecureString)"
        $body.elasticsearch_params.add('http_user', $http_securecreds.username)
        $body.elasticsearch_params.add('http_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($http_securecreds.password)))
    }else{
        if($http_pass){ $body.elasticsearch_params.add('http_password', $http_pass)}
        if($http_user){ $body.elasticsearch_params.add('http_user', $http_user)}
    }
    if($insecure_tls_skip_verify){ $body.elasticsearch_params.add('insecure_tls_skip_verify', $true)}
    if($transport){ $body.elasticsearch_params.add('transport', $transport.ToString())}
    if($metadata){
        $body.add('meta',@{})
        $meta_input = $metadata.split(",")
        foreach($pair in $meta_input){
            $body.meta.add($pair.split(":")[0],$pair.split(":")[1])
        }
    }
    
    $jsonBody = $body | ConvertTo-JSON 
    
    # Optional Parameters Complete

    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        #Write-Debug "Insert REST API call Here."
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Connection already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}" - get

<#
    .SYNOPSIS
    Get full details on a CipherTrust Manager Elasticsearch Connection
    .DESCRIPTION
    Retriving the full list of Elasticsearch Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
    The complete name of the Elasticsearch connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMElasticsearchConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Get-CMElasticsearchConnection -name "My Elasticsearch Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Get-CMElasticsearchConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Get-CMElasticsearchConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Elasticsearch Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMElasticsearchConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection details retrieved"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}" - patch

<#
    .SYNOPSIS
    Update an existing a new CipherTrust Manager Elasticsearch Connection 
    .DESCRIPTION
    Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
    Name of the existing CipherTrust Manager Elasticsearch connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Elasticsearch connection.
    .PARAMETER target
    IP for Hostname/FQDN of the log-forwarder server.
    .PARAMETER port
    Port of the log-forwarder server.
    .PARAMETER description
    (Optional) Description about the connection.
    .PARAMETER ca_cert
    (Optional) CA certificate in PEM format.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER ca_certfile
    (Optional) Specify the filename for a PEM certificate for Elasticsearch CA certificate. 
    .PARAMETER http_securecreds
    (Optional) Pass a PowerShell Credential Object only. Do not specify usersname or password.
    .PARAMETER http_pass
    (Optional) HTTP basic auth password.
    .PARAMETER http_user
    (Optional) HTTP basic auth username.
    .PARAMETER insecure_tls_skip_verify
    (Optional) In TLS mode, skip server certificate validation. This setting should only be used for testing.     
    .PARAMETER transport
    (Required Transport mode for sending data, supports "tls" and "tcp". "tls" requires either a trusted CA cert or insecure TLS skip verify to be set to true. Default is "tcp".
        - tcp
        - tls
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    Existing meta data can be changed but no keys can be deleted.
    e.g. -metadata "red:stop,green:go,blue:ocean"

    For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
    PS> Update-CMAzureConnections -name MyElasticsearchConnection -metadata "red:stop,green:go,blue:ocean"
    This will update the metadata of the connection to include the key pairs shown.

    Resulting in:
    {
        "meta": {
            "blue": "ocean",
            "red": "stop",
            "green": "go"
        }
    }
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMElasticsearchConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory)] [string] $target, 
        [Parameter(Mandatory)] [int] $port, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $ca_cert, 
        [Parameter()] [string] $ca_certfile, 
        [Parameter()] [pscredential] $http_securecreds, 
        [Parameter()] [string] $http_pass, 
        [Parameter()] [string] $http_user, 
        [Parameter()] [switch] $insecure_tls_skip_verify, 
        [Parameter()] [transportType] $transport, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on Elasticsearch Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMAzureConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body= [ordered] @{
        "elasticsearch_params" = @{}
    }

    # Optional Parameters
    if($target){ $body.add('host',$target)}
    if($port){ $body.add('port',$port)}
    if($description){ $body.add('description', $description)}
    if($ca_certfile){ $ca_cert = (Get-Content $ca_certfile -raw)}
    if($ca_cert){ $body.elasticsearch_params.add('ca_cert', $ca_cert)}
    if($http_securecreds){
        Write-Debug "What is my credential user? $($http_securecreds.username)" 
        Write-debug "What is my credential password? $($http_securecreds.password | ConvertFrom-SecureString)"
        $body.elasticsearch_params.add('http_user', $http_securecreds.username)
        $body.elasticsearch_params.add('http_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($http_securecreds.password)))
    }else{
        if($http_pass){ $body.elasticsearch_params.add('http_password', $http_pass)}
        if($http_user){ $body.elasticsearch_params.add('http_user', $http_user)}
    }
    if($insecure_tls_skip_verify){ $body.elasticsearch_params.add('insecure_tls_skip_verify', $true)}
    if($transport){ $body.elasticsearch_params.add('transport', $transport.ToString())}
    if($metadata){
        $body.add('meta',@{})
        $meta_input = $metadata.split(",")
        foreach($pair in $meta_input){
            $body.meta.add($pair.split(":")[0],$pair.split(":")[1])
        }
    }

    $jsonBody = $body | ConvertTo-JSON 
    # Optional Parameters Complete
    
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}" - delete

<#
    .SYNOPSIS
    Delete a CipherTrust Manager Elasticsearch Connection
    .DESCRIPTION
    Delete a CipherTrust Manager Elasticsearch Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
    The complete name of the Elasticsearch connection. This parameter is case-sensitive.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMElasticsearchConnections cmdlet to find the appropriate id value.
    .PARAMETER force
    Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
    PS> Remove-CMElasticsearchConnection -name "My Elasticsearch Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Remove-CMElasticsearchConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Using the id of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Remove-CMElasticsearchConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false)]
        [switch] $force
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to remove Elasticsearch Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMElasticsearchConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    IF(!$force){
        $confirmop=""
        while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
            $confirmop = $(Write-Host -ForegroundColor red  "THIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
            if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
                Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
                return "Operation Cancelled"
            }
        }
    }
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        Invoke-RestMethod  -Method 'DELETE' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' | Out-Null
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return "Connection Deleted."
}    
    
#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}"
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}/test" - post

<#
    .SYNOPSIS
    Test existing connection.
    .DESCRIPTION
    Tests that an existing connection with the given name, ID, or URI Elasticsearch target. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
    Name of the existing CipherTrust Manager Elasticsearch connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Elasticsearch connection.
    .PARAMETER target
    IP for Hostname/FQDN of the log-forwarder server.
    .PARAMETER port
    Port of the log-forwarder server.
    .PARAMETER ca_cert
    (Optional) CA certificate in PEM format.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER ca_certfile
    (Optional) Specify the filename for a PEM certificate for Elasticsearch CA certificate. 
    .PARAMETER http_securecreds
    (Optional) Pass a PowerShell Credential Object only. Do not specify usersname or password.
    .PARAMETER http_pass
    (Optional) HTTP basic auth password.
    .PARAMETER http_user
    (Optional) HTTP basic auth username.
    .PARAMETER insecure_tls_skip_verify
    (Optional) In TLS mode, skip server certificate validation. This setting should only be used for testing.     
    .PARAMETER transport
    (Required Transport mode for sending data, supports "tls" and "tcp". "tls" requires either a trusted CA cert or insecure TLS skip verify to be set to true. Default is "tcp".
        - tcp
        - tls
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMElasticsearchConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory)] [string] $target, 
        [Parameter(Mandatory)] [int] $port, 
        [Parameter()] [string] $ca_cert, 
        [Parameter()] [string] $ca_certfile, 
        [Parameter()] [pscredential] $http_securecreds, 
        [Parameter()] [string] $http_pass, 
        [Parameter()] [string] $http_user, 
        [Parameter()] [switch] $insecure_tls_skip_verify, 
        [Parameter()] [transportType] $transport
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if((!$insecure_tls_skip_verify) -and (!$ca_cert -and !$ca_certfile)){
        return "Please provide certificate or client_secret or set insecure_tls_skip_verify to true for testing."
    }
    if ((!$http_user -or !$http_pass) -and !$http_securecreds) { return "Missing Elasticsearch Credentials. Please try again."}

    Write-Debug "Testing Azure Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        $id = (Find-CMAzureConnections -name $name).resources[0].id 
        $endpoint += "/" + $id + "/test"
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    # Mandatory Parameters
    $body= [ordered] @{
        "elasticsearch_params" = @{}
    }

    # Optional Parameters
    if($target){ $body.add('host',$target)}
    if($port){ $body.add('port',$port)}
    if($ca_certfile){ $ca_cert = (Get-Content $ca_certfile -raw)}
    if($ca_cert){ $body.elasticsearch_params.add('ca_cert', $ca_cert)}
    if($http_securecreds){
        Write-Debug "What is my credential user? $($http_securecreds.username)" 
        Write-debug "What is my credential password? $($http_securecreds.password | ConvertFrom-SecureString)"
        $body.elasticsearch_params.add('http_user', $http_securecreds.username)
        $body.elasticsearch_params.add('http_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($http_securecreds.password)))
    }else{
        if($http_pass){ $body.elasticsearch_params.add('http_password', $http_pass)}
        if($http_user){ $body.elasticsearch_params.add('http_user', $http_user)}
    }
    if($insecure_tls_skip_verify){ $body.elasticsearch_params.add('insecure_tls_skip_verify', $true)}
    if($transport){ $body.elasticsearch_params.add('transport', $transport.ToString())}
            
    $jsonBody = $body | ConvertTo-JSON 

    # Optional Parameters Complete
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection tested"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Elasticsearch Connections
#"#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connection-test - post"

<#
    .SYNOPSIS
    Test connection parameters for a non-existent connection. 
    .DESCRIPTION
    Tests that the connection parameters can be used to reach the Elasticsearch log server. This does not create a persistent connection.
    .PARAMETER target
    IP for Hostname/FQDN of the log-forwarder server.
    .PARAMETER port
    Port of the log-forwarder server.
    .PARAMETER ca_cert
    (Optional) CA certificate in PEM format.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER ca_certfile
    (Optional) Specify the filename for a PEM certificate for Elasticsearch CA certificate. 
    .PARAMETER http_securecreds
    (Optional) Pass a PowerShell Credential Object only. Do not specify usersname or password.
    .PARAMETER http_pass
    (Optional) HTTP basic auth password.
    .PARAMETER http_user
    (Optional) HTTP basic auth username.
    .PARAMETER insecure_tls_skip_verify
    (Optional) In TLS mode, skip server certificate validation. This setting should only be used for testing.     
    .PARAMETER transport
    (Required Transport mode for sending data, supports "tls" and "tcp". "tls" requires either a trusted CA cert or insecure TLS skip verify to be set to true. Default is "tcp".
        - tcp
        - tls
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMElasticsearchConnParameters{
    param(
        [Parameter(Mandatory)] [string] $target, 
        [Parameter(Mandatory)] [int] $port, 
        [Parameter()] [string] $ca_cert, 
        [Parameter()] [string] $ca_certfile, 
        [Parameter()] [pscredential] $http_securecreds, 
        [Parameter()] [string] $http_pass, 
        [Parameter()] [string] $http_user, 
        [Parameter()] [switch] $insecure_tls_skip_verify, 
        [Parameter()] [transportType] $transport
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if((!$insecure_tls_skip_verify) -and (!$ca_cert -and !$ca_certfile)){
        return "Please provide certificate or client_secret or set insecure_tls_skip_verify to true for testing."
    }
    if ((!$http_user -or !$http_pass) -and !$http_securecreds) { return "Missing Elasticsearch Credentials. Please try again."}

    Write-Debug "Testing Elasticsearch Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body= [ordered] @{
        "elasticsearch_params" = @{}
    }

    # Optional Parameters
    if($target){ $body.add('host',$target)}
    if($port){ $body.add('port',$port)}
    if($ca_certfile){ $ca_cert = (Get-Content $ca_certfile -raw)}
    if($ca_cert){ $body.elasticsearch_params.add('ca_cert', $ca_cert)}
    if($http_securecreds){
        Write-Debug "What is my credentiasl user? $($http_securecreds.username)" 
        Write-debug "What is my credential password? $($http_securecreds.password | ConvertFrom-SecureString)"
        $body.elasticsearch_params.add('http_user', $http_securecreds.username)
        $body.elasticsearch_params.add('http_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($http_securecreds.password)))
    }else{
        if($http_pass){ $body.elasticsearch_params.add('http_password', $http_pass)}
        if($http_user){ $body.elasticsearch_params.add('http_user', $http_user)}
    }
    if($insecure_tls_skip_verify){ $body.elasticsearch_params.add('insecure_tls_skip_verify', $true)}
    if($transport){ $body.elasticsearch_params.add('transport', $transport.ToString())}
                
    $jsonBody = $body | ConvertTo-JSON 

    # Optional Parameters Complete
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection tested"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}  

####
# Export Module Members
####
#Connection Manager - Elasticsearch
#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/"

Export-ModuleMember -Function Find-CMElasticsearchConnections #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections - get"
Export-ModuleMember -Function New-CMElasticsearchConnection #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections - post"

#Connection Manager - Elasticsearch
#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}"
Export-ModuleMember -Function Get-CMElasticsearchConnection #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id} - get"
Export-ModuleMember -Function Update-CMElasticsearchConnection #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMElasticsearchConnection #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id} - delete"

#Connection Manager - Elasticsearch
#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}/test"
Export-ModuleMember -Function Test-CMElasticsearchConnection #/v1/connectionmgmt/services/log-forwarders/elasticsearch/connections/{id}/test - post"

#Connection Manager - Elasticsearch
#/v1/connectionmgmt/services/log-forwarders/elasticsearch/connection-test"
Export-ModuleMember -Function Test-CMElasticsearchConnParameters #/connectionmgmt/services/log-forwarders/elasticsearch/connection-test - post"
