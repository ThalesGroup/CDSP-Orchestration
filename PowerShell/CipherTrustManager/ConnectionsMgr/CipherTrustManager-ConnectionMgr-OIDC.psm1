#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-OIDC.psm1                                                        #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/oidc/connections"
$target_uri_test = "/connectionmgmt/services/oidc/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections OIDC Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections OIDC Module"
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


#This project mirrors the "Connection Manager - OIDC Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/OIDC Connections)

#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections"
#"#/v1/connectionmgmt/services/oidc/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager OIDC Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/OIDC Connections).   
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
    .EXAMPLE
        PS> Find-CMOIDCConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMOIDCConnections {
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
        [Parameter()] [string] $products,
        [Parameter()] [string] $meta_contains, 
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all OIDC Connections in CM"
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

    Write-Debug "Endpoint w Query: $($endpoint)"
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
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
    Write-Debug "List of all CM OIDC Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections"
#"#/v1/connectionmgmt/services/oidc/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager OIDC Connection. 
    .DESCRIPTION
        Creates a new OIDC connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER client_id
        OIDC Client ID of the Connection
    .PARAMETER client_secret
        Secret value for the OIDC Connection
    .PARAMETER clientsecureinfo
        PS Credential object containing the Client ID and secret values for the OIDC Connection 
    .PARAMETER url
        Well-Known Configuration Endpoint for the OIDC Connection
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMOIDCConnection -name ricky.oidc -client_id <client_id> -client_secret <client_secret> -url "https://{oauth-provider-hostname}/.well-known/openid-configuration" -products cte
    .EXAMPLE
        PS> New-CMOIDCConnection -name ricky.oidc -clientsecureinfo $clientinfo -url "https://{oauth-provider-hostname}/.well-known/openid-configuration"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMOIDCConnection{
    param(
        [Parameter(Mandatory,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $url,
        [Parameter(Mandatory = $false)] [string] $client_id,
        [Parameter(Mandatory = $false)] [string] $client_secret,
        [Parameter(Mandatory = $false)] [pscredential] $clientsecureinfo,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an LDAP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"      = $name
        "url"       = $url
        "products"  = @("cte")
    }

    if($clientsecureinfo){
        Write-Debug "What is my credential client_id? $($clientsecureinfo.username)" 
        Write-debug "What is my credential client_secret? $($clientsecureinfo.password | ConvertFrom-SecureString)"
        $body.add('client_id', $clientsecureinfo.username)
        $body.add('client_secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientsecureinfo.password)))
    }else{
        if($client_id){ $body.add('client_id', $client_id) }
        if($client_secret){ $body.add('client_secret', $client_secret) }
    }
    
    if($products){ $body.add("products",$products) }
    if($description) { $body.add('description', $description) }
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
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
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
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::UnprocessableEntity) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Invalid JSON.`n$($apiError.Message)" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections/{id}"
#"#/v1/connectionmgmt/services/oidc/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager OIDC Connection
    .DESCRIPTION
        Retriving the full list of OIDC Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the OIDC connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMOIDCConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMOIDCConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMOIDCConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMOIDCConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMOIDCConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOIDCConnections -name $name).resources[0].id 
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
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
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

#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections/{id}"
#"#/v1/connectionmgmt/services/oidc/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager LDAP Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager LDAP connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER client_secret
        Secret value for the OIDC Connection
    .PARAMETER clientsecureinfo
        PS Credential object containing the Client ID and secret values for the OIDC Connection 
    .PARAMETER url
        Well-Known Configuration Endpoint for the OIDC Connection
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        Existing meta data can be changed but no keys can be deleted.
        e.g. -metadata "red:stop,green:go,blue:ocean"

        For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
        PS> Update-CMOIDCConnection -name contoso.com -client_secret <newsecret> -bind_pass <newpass>
    .EXAMPLE
        PS> Update-CMOIDCConnection -name contoso.com -bindsecurecredentials $newcreds
    .EXAMPLE
        PS> Update-CMOIDCConnections -name MyLDAPConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMOIDCConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $url,
        [Parameter()] [string] $client_secret, 
        [Parameter()] [pscredential] $clientsecureinfo,
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on OIDC Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMOIDCConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOIDCConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body = [ordered] @{}
    
    if($clientsecureinfo){
        Write-Debug "What is my credential client_id? $($clientsecureinfo.username)" 
        Write-debug "What is my credential client_secret? $($clientsecureinfo.password | ConvertFrom-SecureString)"
        $body.add('client_secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientsecureinfo.password)))
    }else{
        if($client_id){ $body.add('client_id', $client_id) }
        if($client_secret){ $body.add('client_secret', $client_secret) }
    }
    
    if($description) { $body.add('description', $description) }
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
        $response = Invoke-RestMethod  -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
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


#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections/{id}"
#"#/v1/connectionmgmt/services/oidc/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager OIDC Connection
    .DESCRIPTION
        Delete a CipherTrust Manager OIDC Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the OIDC connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMOIDCConnections cmdlet to find the appropriate id value.
    .PARAMETER inuse
        Removes and In-Use OIDC Connection
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMOIDCConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMOIDCConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMOIDCConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false)]
        [switch] $force,
        [Parameter(Mandatory = $false)]
        [switch] $inuse
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to remove OIDC Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/delete"        
    }elseif($hostname){ 
        if((Find-CMLunaHSMServer -hostname $hostname).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMServer -hostname $hostname).resources[0].id 
        $endpoint += "/" + $id + "/delete"
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    if(!$force){
        $confirmop=""
        while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
            $confirmop = $(Write-Host -ForegroundColor red  "THIS IS REMOVING AN IN-USE LUNA HSM SERVER.`nTHIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
            if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
                Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
                return "Operation Cancelled"
            }
        }
    }
    
    if($inuse){
        $body= @{
            "force" = [bool]$true
        }

        $jsonBody = $body | ConvertTo-Json
    
    }
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError | Out-Null
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
    


####
# Export Module Members
####
#Connection Manager - OIDC
#/v1/connectionmgmt/services/oidc/connections"

Export-ModuleMember -Function Find-CMOIDCConnections #/v1/connectionmgmt/services/oidc/connections - get"
Export-ModuleMember -Function New-CMOIDCConnection #/v1/connectionmgmt/services/oidc/connections - post"

#Connection Manager - OIDC
#/v1/connectionmgmt/services/oidc/connections/{id}"
Export-ModuleMember -Function Get-CMOIDCConnection #/v1/connectionmgmt/services/oidc/connections/{id} - get"
Export-ModuleMember -Function Update-CMOIDCConnection #/v1/connectionmgmt/services/oidc/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMOIDCConnection #/v1/connectionmgmt/services/oidc/connections/{id} - delete"


