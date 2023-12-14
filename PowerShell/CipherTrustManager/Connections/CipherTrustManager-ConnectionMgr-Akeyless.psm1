#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Akeyless.psm1                                                    #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/akeyless/connections"
$target_uri_test = "/connectionmgmt/services/akeyless/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Akeyless Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Akeyless Module"
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


#This project mirrors the "Connection Manager - Akeyless Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Akeyless Connections)

#Connection Manager - AKeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections"
#"#/v1/connectionmgmt/services/akeyless/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager AKeyless Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Akeyless Connections#/v1/connectionmgmt/services/akeyless/connections-get).   
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
    .EXAMPLE
        PS> Find-CMAkeylessConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMAkeylessConnections {
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
    
    Write-Debug "Getting a List of all Akeyless Connections in CM"
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
    if ($products) {
        if ($firstset) {
            $endpoint += "&products="
        }
        else {
            $endpoint += "?products="
            $firstset = $true
        }
        $endpoint += $products
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
    if ($is_role_anywhere) {
        if ($firstset) {
            $endpoint += "&is_role_anywhere=true"
        }
        else {
            $endpoint += "?is_role_anywhere=true"
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
    Write-Debug "List of all CM Connections to Akeyless with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections"
#"#/v1/connectionmgmt/services/akeyless/connections - post"

<#
    .SYNOPSIS
    Create a new CipherTrust Manager Akeyless Connection 
    .DESCRIPTION
    Creates a new Akeyless connection. Each Akeyless connection has an access ID, an access key, and a type parameter. There are two types of Akeyless connections. The first type, called gateway, contains the credentials that enable a connection between the Akeyless gateway and the Akeyless server in the cloud. The second type, called sso, contains the credentials that enable a connection between the CM and the Akeyless gateway for SSO.
    The access key is a secret and is protected by the CM.
    .PARAMETER name
    Unique connection name.
    .PARAMETER access_key
    The key used for accessing the Akeyless server.
    .PARAMETER access_key_id
    The ID of a key used for accessing the Akeyless server.
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
    PS> New-CMAkeylessConnection -name MyTestAKeylessConnection -description "This is my Test AKeyless Connection" -access_key_id abc123abc123 --access_key xyz987xyz987 -metadata "red:stop,:green:go,blue:ocean" 
    
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function New-CMAkeylessConnection{
    param(
        [Parameter()] [string] $name, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $access_key, 
        [Parameter()] [string] $access_key_id, 
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Akeyless Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"


    # Mandatory Parameters
    $body = [ordered] @{
        "name" = $name
    }

    # Optional Parameters
    if($access_key){ $body.add('access_key', $access_key)}else{ return "Missing Access Key. Please try again."}
    if($access_key_id){ $body.add('access_key_id', $access_key_id)}else{ return "Missing Access Key ID. Please try again."}
    if($description){ $body.add('description', $description)}
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


#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections/{id}"
#"#/v1/connectionmgmt/services/akeyless/connections/{id} - get"

<#
    .SYNOPSIS
    Get full details on a CipherTrust Manager AKeyless Connection
    .DESCRIPTION
    Returns the details of a connection with the given name, ID, or URI.
    .PARAMETER name
    The complete name of the AKeyless connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMAkeylessConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Get-CMAkeylessConnection -name "MyAkeylessConnection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Get-CMAkeylessConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Get-CMAkeylessConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Akeyless Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMAkeylessConnections -name $name).resources[0].id 
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
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections/{id}"
#"#/v1/connectionmgmt/services/akeyless/connections/{id} - patch"


<#
    .SYNOPSIS
    Update an existing a new CipherTrust Manager Akeyless Connection 
    .DESCRIPTION
    Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
    Name of the existing CipherTrust Manager Akeyless connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing AKeyless connection.
    .PARAMETER access_key
    (Optional) The key used for accessing the Akeyless server.
    .PARAMETER access_key_id
    (Optional) The ID of a key used for accessing the Akeyless server.
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    Existing meta data can be changed but no keys can be deleted.
    e.g. -metadata "red:stop,green:go,blue:ocean"
    
    For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
    PS> Update-CMAkeylessConnections -name MyAkeylessConnection -access_key <NewAccessKey> -access_key <NewAccessKeyID>
    Updates the connection name "MyAkeylessConnection" with a new access_key/key_id keypair.
    .EXAMPLE
    PS> Update-CMAkeylessConnections -name MyAkeylessConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMAkeylessConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $access_key, 
        [Parameter()] [string] $access_key_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on AKeyless Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMAkeylessConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Parameters
    $body = [ordered] @{}

    if($access_key){ $body.add('access_key', $access_key)}
    if($access_key_id){ $body.add('access_key_id', $access_key_id)}
    if($description){ $body.add('description', $description)}
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
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections/{id}"
#"#/v1/connectionmgmt/services/akeyless/connections/{id} - delete"

<#
    .SYNOPSIS
    Delete a CipherTrust Manager Akeyless Connection
    .DESCRIPTION
    Delete a CipherTrust Manager Akeyless Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
    The complete name of the Akeyless connection. This parameter is case-sensitive.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMAkeylessConnections cmdlet to find the appropriate id value.
    .PARAMETER force
    Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
    PS> Remove-CMAkeylessConnection -name "MyAkeylessConnection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Remove-CMAkeylessConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Using the id of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Remove-CMAkeylessConnection{
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

    Write-Debug "Getting details on Akeyless Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMAkeylessConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    if(!$force){
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
    
#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connections/{id}"
#"#/v1/connectionmgmt/services/akeyless/connections/{id}/test - post"

<#
    .SYNOPSIS
    Test existing connection.
    .DESCRIPTION
    Tests that an existing connection with the given name, ID, or URI reaches the Akeyless cloud. If no connection parameters are provided in request, the existing parameters will be used. This does not create a persistent connection.
    .PARAMETER name
    Name of the existing CipherTrust Manager Akeyless connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Akeyless connection.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMAkeylessConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Akeyless Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        $id = (Find-CMAKeylessConnections -name $name).resources[0].id 
        $endpoint += "/" + $id + "/test"
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


#Connection Manager - Akeyless Connections
#"#/v1/connectionmgmt/services/akeyless/connection-test - post"

<#
    .SYNOPSIS
    Test connection parameters for a non-existent connection. 
    .DESCRIPTION
    Tests that the connection parameters can be used to reach the AKeyless account. This does not create a persistent connection.
    .PARAMETER access_key
    The key used for accessing the Akeyless server.
    .PARAMETER access_key_id
    The ID of a key used for accessing the Akeyless server.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMAkeylessConnParameters{
    param(
        [Parameter()] [string] $access_key, 
        [Parameter()] [string] $access_key_id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing AKeyless Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Parameters
    $body = [ordered] @{}

    if($access_key){ $body.add('access_key', $access_key)}else{ return "Missing Access Key. Please try again."}
    if($access_key_id){ $body.add('access_key_id', $access_key_id)}else{ return "Missing Access Key ID. Please try again."}
                
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
#Connection Manager - AKeyless
#/v1/connectionmgmt/services/akeyless/connections"

Export-ModuleMember -Function Find-CMAKeylessConnections #/v1/connectionmgmt/services/akeyless/connections - get"
Export-ModuleMember -Function New-CMAKeylessConnection #/v1/connectionmgmt/services/akeyless/connections - post"

#Connection Manager - AKeyless
#/v1/connectionmgmt/services/akeyless/connections/{id}"
Export-ModuleMember -Function Get-CMAKeylessConnection #/v1/connectionmgmt/services/akeyless/connections/{id} - get"
Export-ModuleMember -Function Update-CMAKeylessConnection #/v1/connectionmgmt/services/akeyless/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMAKeylessConnection #/v1/connectionmgmt/services/akeyless/connections/{id} - delete"

#Connection Manager - AKeyless
#/v1/connectionmgmt/services/akeyless/connections/{id}/test"
Export-ModuleMember -Function Test-CMAKeylessConnection #/v1/connectionmgmt/services/akeyless/connections/{id}/test - post"

#Connection Manager - AKeyless
#/v1/connectionmgmt/services/akeyless/connection-test"
Export-ModuleMember -Function Test-CMAKeylessConnParameters #/v1/connectionmgmt/services/akeyless/connection-test - post"
