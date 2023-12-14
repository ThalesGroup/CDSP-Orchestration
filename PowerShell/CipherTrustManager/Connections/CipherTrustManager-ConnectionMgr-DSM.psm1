########################################################################################################products###############
# File:             CipherTrustManager-ConnectionMgr-DSM.psm1                                                         #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/dsm/connections"
$target_uri_test = "/connectionmgmt/services/dsm/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections DSM Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections DSM Module"
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


#This project mirrors the "Connection Manager - DSM Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/DSM Connections)

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections"
#"#/v1/connectionmgmt/services/dsm/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager DSM Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/DSM Connections).   
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
        PS> Find-CMDSMConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMDSMConnections {
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
    
    Write-Debug "Getting a List of all DSM Connections in CM"
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
    Write-Debug "List of all CM Connections to Google with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections"
#"#/v1/connectionmgmt/services/dsm/connections - post"

<#
    .SYNOPSIS
    Create a new CipherTrust Manager DSM Connection. 
    .DESCRIPTION
    Creates a new DSM connection. 
    .PARAMETER name
    Unique connection name.
    .PARAMETER nodename
    Hostname of the FIRST DSM server in the DSM Cluster being conencted to. Use Add-CMDSMConnectionNode for EACH additional node.
    .PARAMETER dsmcertificate
    Enter the PEM-formatted certificate text for the DSM being connected to.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER dsmcertfile
    Specify a filename for the DSM certificate.
    .PARAMETER dsmuser
    Username for accessing DSM server. 
    .PARAMETER dsmpass
    Password of DSM server
    .PARAMETER dsmsecurecredentials
    Supply a PSCredential object with the DSM username and password
    .PARAMETER domain_id
    (Optional) If DSM user is restricted to a domain, provide domain id.
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
    PS> New-CMDSMConnection -name "MyDSMCluster" -description "This is an Powershell created External DSM Connection" -nodename "dsm1.mydomain.com" -dsmcertificate "<PEM-formatted-certificate>" -dsmuser alladmin -dsmpass Thales123! -metadata "red:stop,green:go"
    .EXAMPLE
    PS> New-CMDSMConnection -name "MyDSMCluster" -description "This is an Powershell created External DSM Connection" -nodename "dsm1.mydomain.com" -dsmcertfile .\dsmnode1cert.pem -dsmuser alladmin -dsmpass Thales123! -metadata "red:stop,green:go"
    .EXAMPLE
    PS> New-CMDSMConnection -name "MyDSMCluster" -nodename "dsm1.mydomain.com" -dsmcertfile .\dsmnode1cert.pem -dsmsecurecredentials [PSCredential]$dsmcreds
    
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function New-CMDSMConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $nodename, 
        [Parameter()] [string] $dsmcertificate, 
        [Parameter()] [string] $dsmcertfile, 
        [Parameter()] [string] $dsmuser, 
        [Parameter()] [string] $dsmpass, 
        [Parameter()] [pscredential] $dsmsecurecredentials, 
        [Parameter()] [string] $domain_id, 
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Google Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if (!$dsmcertificate -and !$dsmcertfile) { return "Missing DSM Certificate. Please try again."}
    if ((!$dsmuser -or !$dsmpass) -and !$dsmsecurecredentials) { return "Missing DSM Credentials. Please try again."}

    # Mandatory Parameters
    $body = [ordered] @{
        "name"      = $name
        "products"  = @( "cckm" )
        "nodes"     = @()
    }
    
    if($dsmsecurecredentials){
        Write-Debug "What is my credential user? $($dsmsecurecredentials.username)" 
        Write-debug "What is my credential password? $($dsmsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $dsmsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dsmsecurecredentials.password)))
    }else{
        if($dsmpass){ $body.add('password', $dsmpass)}
        if($dsmuser){ $body.add('username', $dsmuser)}
    }

    #Build Node dictionary object
    $node = [ordered] @{}
    if($dsmcertfile){ $dsmcertificate = (Get-Content $dsmcertfile -raw) }
        $node.hostname = $nodename
        $node.server_certificate = $dsmcertificate
        $body.nodes += $node
    
    if($description) { $body.add('description', $description)}
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


#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}"
#"#/v1/connectionmgmt/services/dsm/connections/{id} - get"

<#
    .SYNOPSIS
    Get full details on a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Retriving the full list of DSM Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
    The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Get-CMDSMConnection -name "My DSM Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Get-CMDSMConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Get-CMDSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on DSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMDSMConnections -name $name).resources[0].id 
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

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}"
#"#/v1/connectionmgmt/services/dsm/connections/{id} - patch"


<#
    .SYNOPSIS
    Update an existing a new CipherTrust Manager DSM Connection. This is ONLY used to update the DSM Credentials. Use "Update-CMDSMConnectionNode -id {id}" to update node information.
    .DESCRIPTION
    Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
    Name of the existing CipherTrust Manager DSM connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER dsmuser
    Username for accessing DSM server. 
    .PARAMETER dsmpass
    Password of DSM server
    .PARAMETER dsmsecurecredentials
    Supply a PSCredential object with the DSM username and password
    .PARAMETER domain_id
    (Optional) If DSM user is restricted to a domain, provide domain id.
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    Existing meta data can be changed but no keys can be deleted.
    e.g. -metadata "red:stop,green:go,blue:ocean"

    For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
    PS> Update-CMDSMConnections -name MyDSMConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMDSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $dsmuser, 
        [Parameter()] [string] $dsmpass, 
        [Parameter()] [pscredential] $dsmsecurecredentials, 
        [Parameter()] [string] $domain_id, 
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on DSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMDSMConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body = [ordered] @{}
    
    if($dsmsecurecredentials){
        Write-Debug "What is my credential user? $($dsmsecurecredentials.username)" 
        Write-debug "What is my credential password? $($dsmsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $dsmsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dsmsecurecredentials.password)))
    }else{
        if($dsmpass){ $body.add('password', $dsmpass)}
        if($dsmuser){ $body.add('username', $dsmuser)}
    }
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
    Write-Debug "Connection updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}"
#"#/v1/connectionmgmt/services/dsm/connections/{id} - delete"

<#
    .SYNOPSIS
    Delete a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Delete a CipherTrust Manager DSM Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
    The complete name of the DSM connection. This parameter is case-sensitive.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .PARAMETER force
    Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
    PS> Remove-CMDSMConnection -name "My DSM Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Remove-CMDSMConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Using the id of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Remove-CMDSMConnection{
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

    Write-Debug "Preparing to remove DSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMDSMConnections -name $name).resources[0].id 
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
    
#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/test - post"

<#
    .SYNOPSIS
    Test existing connection.
    .DESCRIPTION
    Tests that an existing connection with the given name, ID, or URI reaches the Google cloud. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
    Name of the existing CipherTrust Manager DSM connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Google connection.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMDSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing DSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        $id = (Find-CMDSMConnections -name $name).resources[0].id 
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


#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connection-test - post"

<#
    .SYNOPSIS
    Test connection parameters for a non-existent connection. 
    .DESCRIPTION
    Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER nodename
    Hostname of the DSM server in the DSM Cluster being tested.
    .PARAMETER dsmcertificate
    Enter the PEM-formatted certificate text for the DSM being connected to.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER dsmcertfile
    Specify a filename for the DSM certificate.
    .PARAMETER dsmuser
    Username for accessing DSM server. 
    .PARAMETER dsmpass
    Password of DSM server
    .PARAMETER dsmsecurecredentials
    Supply a PSCredential object with the DSM username and password
    .PARAMETER domain_id
    (Optional) If DSM user is restricted to a domain, provide domain id.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMDSMConnParameters{
    param(
        [Parameter()] [string] $nodename, 
        [Parameter()] [string] $dsmcertificate, 
        [Parameter()] [string] $dsmcertfile, 
        [Parameter()] [string] $dsmuser, 
        [Parameter()] [string] $dsmpass, 
        [Parameter()] [pscredential] $dsmsecurecredentials, 
        [Parameter()] [string] $domain_id 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing DSM Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    if (!$dsmcertificate -and !$dsmcertfile) { return "Missing DSM Certificate. Please try again."}
    if ((!$dsmuser -or !$dsmpass) -and !$dsmsecurecredentials) { return "Missing DSM Credentials. Please try again."}

    # Mandatory Parameters
    $body = [ordered] @{
        "nodes"     = @()
    }
    
    if($dsmsecurecredentials){
        Write-Debug "What is my credential user? $($dsmsecurecredentials.username)" 
        Write-debug "What is my credential password? $($dsmsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $dsmsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dsmsecurecredentials.password)))
    }else{
        if($dsmpass){ $body.add('password', $dsmpass)}
        if($dsmuser){ $body.add('username', $dsmuser)}
    }

    #Build Node dictionary object
    $node = [ordered] @{}
    if($dsmcertfile){ $dsmcertificate = (Get-Content $dsmcertfile -raw) }
        $node.hostname = $nodename
        $node.server_certificate = $dsmcertificate
        $body.nodes += $node
        
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

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes - get"

<#
    .SYNOPSIS
    Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
    The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Find-CMDSMConnectionNodes -name "My DSM Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Find-CMDSMConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
    function Find-CMDSMConnectionNodes{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Getting details on DSM Connection Nodes"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes"
        }elseif($name){ 
            $id = (Find-CMDSMConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes"
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

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes - post"

<#
    .SYNOPSIS
    Add a nodes to a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Add a nodes to a CipherTrust Manager DSM Connection
    .PARAMETER name
    The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .PARAMETER nodename
    Hostname of the DSM server in the DSM Cluster being added.
    .PARAMETER dsmcertificate
    Enter the PEM-formatted certificate text for the DSM being connected to.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER dsmcertfile
    Specify a filename for the DSM certificate.
    .EXAMPLE
    PS> Add-CMDSMConnectionNode -name "My DSM Connection" -nodename "dsm2.mydomain.local" -dsmcertificate <PEM-formatted-certificate-text>
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Add-CMDSMConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodename "dsm2.mydomain.local" -dsmcertfile .\dsm2_cert.pem
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
    function Add-CMDSMConnectionNode{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter()] [string] $nodename, 
            [Parameter()] [string] $dsmcertificate, 
            [Parameter()] [string] $dsmcertfile
    
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Adding new DSM Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes"
        }elseif($name){ 
            $id = (Find-CMDSMConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes"
        }else{
            return "Missing Connection Identifier."
        }

        Write-Debug "Endpoint w Target: $($endpoint)"

        # Mandatory Parameters
        $body = [ordered] @{}
        
        #Build Node dictionary object
        if($dsmcertfile){ $dsmcertificate = (Get-Content $dsmcertfile -raw) }
            $body.add('hostname',$nodename)
            $body.add('server_certificate',$dsmcertificate)

            
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
        Write-Debug "Node added"
        Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    
        return $response
}    

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes - get"

<#
    .SYNOPSIS
    Get detail on an individual node of a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Get detail on an individual node of a CipherTrust Manager DSM Connection
    .PARAMETER name
    The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
    The Node "id" value for the connection.
    Use the Find-CMDSMConnectionNodes cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Get-CMDSMConnectionNode -name "My DSM Connection" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Get-CMDSMConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
    function Get-CMDSMConnectionNodes{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $nodeid
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Getting details on DSM Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }elseif($name){ 
            $id = (Find-CMDSMConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes/" + $nodeid
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
        Write-Debug "Node details retrieved"
        Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    
        return $response
}    


#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes/{nodeid}"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes/{nodeid} - delete"

<#
    .SYNOPSIS
    Delete a node from a CipherTrust Manager DSM Connection.
    .DESCRIPTION
    Delete a node from a CipherTrust Manager DSM Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
    The complete name of the DSM connection. This parameter is case-sensitive.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
    Node ID of the node in the DSM Cluster being removed.
    .PARAMETER force
    Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
    PS> Remove-CMDSMConnection -name "My DSM Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Remove-CMDSMConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Using the id of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
    function Remove-CMDSMConnectionNode{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter(Mandatory = $false)]
            [switch] $force,
            [Parameter()] [string] $nodeid
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Preparing to remove DSM Connection"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid      
        }elseif($name){ 
            $id = (Find-CMDSMConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes/" + $nodeid
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

#Connection Manager - DSM Connections
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/dsm/connections/{id}/nodes - post"

<#
    .SYNOPSIS
    Update an existing node of a CipherTrust Manager DSM Connection
    .DESCRIPTION
    Update an existing node of a CipherTrust Manager DSM Connection
    .PARAMETER name
    The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMDSMConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
    Node ID of the node in the DSM Cluster being updated.
    .PARAMETER dsmcertificate
    Enter the PEM-formatted certificate text for the DSM being connected to.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER dsmcertfile
    Specify a filename for the DSM certificate.
    .EXAMPLE
    PS> Update-CMDSMConnectionNode -name "My DSM Connection" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" -dsmcertificate <PEM-formatted-certificate-text>
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Update-CMDSMConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" -dsmcertfile .\dsm2_cert.pem
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
    function Update-CMDSMConnectionNode{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter()] [string] $nodeid, 
            [Parameter()] [string] $nodename, 
            [Parameter()] [string] $dsmcertificate, 
            [Parameter()] [string] $dsmcertfile
    
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Updating a DSM Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }elseif($name){ 
            $id = (Find-CMDSMConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }else{
            return "Missing Connection Identifier."
        }

        Write-Debug "Endpoint w Target: $($endpoint)"

        # Optional Parameters
        $body = [ordered] @{}
        
        #Build Node dictionary object
        if($dsmcertfile){ $dsmcertificate = (Get-Content $dsmcertfile -raw) }
        if($nodename){ ($body.add('hostname',$nodename)) }
        if($dsmcertificate){ $body.add('server_certificate',$dsmcertificate) }

            
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
        Write-Debug "Node added"
        Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    
        return $response
}    


####
# Export Module Members
####
#Connection Manager - DSM
#/v1/connectionmgmt/services/dsm/connections"

Export-ModuleMember -Function Find-CMDSMConnections #/v1/connectionmgmt/services/dsm/connections - get"
Export-ModuleMember -Function New-CMDSMConnection #/v1/connectionmgmt/services/dsm/connections - post"

#Connection Manager - DSM
#/v1/connectionmgmt/services/dsm/connections/{id}"
Export-ModuleMember -Function Get-CMDSMConnection #/v1/connectionmgmt/services/dsm/connections/{id} - get"
Export-ModuleMember -Function Update-CMDSMConnection #/v1/connectionmgmt/services/dsm/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMDSMConnection #/v1/connectionmgmt/services/dsm/connections/{id} - delete"

#Connection Manager - DSM
#/v1/connectionmgmt/services/dsm/connections/{id}/test"
Export-ModuleMember -Function Test-CMDSMConnection #/v1/connectionmgmt/services/dsm/connections/{id}/test - post"

#Connection Manager - DSM
#/v1/connectionmgmt/services/dsm/connection-test"
Export-ModuleMember -Function Test-CMDSMConnParameters #/v1/connectionmgmt/services/dsm/connection-test - post"

#Connection Manager - DSM
#/v1/connectionmgmt/services/dsm/connections/{id}/nodes"
Export-ModuleMember -Function Find-CMDSMConnectionNodes #/v1/connectionmgmt/services/dsm/connections/{id}/nodes - get"
Export-ModuleMember -Function Add-CMDSMConnectionNode #/v1/connectionmgmt/services/dsm/connections/{id}/nodes - post"
Export-ModuleMember -Function Get-CMDSMConnectionNode #/v1/connectionmgmt/services/dsm/connections/{id}/nodes/{node_id} - get"
Export-ModuleMember -Function Update-CMDSMConnectionNode #/v1/connectionmgmt/services/dsm/connections/{id}/nodes/{node_id} - patch"
Export-ModuleMember -Function Remove-CMDSMConnectionNode #/v1/connectionmgmt/services/dsm/connections/{id}/nodes/{node_id} - delete"
