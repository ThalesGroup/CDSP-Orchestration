#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-SCP.psm1                                                         #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

#######
# ENUM
#######
# Authentication Methods
Add-Type -TypeDefinition @"
   public enum scpAuthMethod {
    key,
    password
}
"@


####
# Local Variables
####
$target_uri = "/connectionmgmt/services/scp/connections"
$target_uri_test = "/connectionmgmt/services/scp/connection-test"
$target_scp_key = "/scp/public-key"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections SCP Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections SCP Module"
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


#This project mirrors the "Connection Manager - SCP Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/SCP Connections)

#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections"
#"#/v1/connectionmgmt/services/scp/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager SCP Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/SCP Connections).   
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
        Valid values are "backup/restore" for AWS, GCP, Azure, and Luna Connections, "ddc", "data discovery" for Hadoop connections, and "cte" for SMB connections.
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
        PS> Find-CMSCPConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMSCPConnections {
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
    
    Write-Debug "Getting a List of all SCP Connections in CM"
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
    Write-Debug "List of all CM SCP Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections"
#"#/v1/connectionmgmt/services/scp/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager SCP Connection. 
    .DESCRIPTION
        Creates a new SCP connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER target
        Hostname or FQDN of SCP.
    .PARAMETER port
        Port where SCP service runs on host. If not specified, system will default to port 22.
    .PARAMETER auth_method
        Authentication type for SCP. Accepted values are "key" or "password".
    .PARAMETER username
        Username for accessing SCP.
    .PARAMETER pass
        Password for accessing SCP.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the SCP User and Password when using the password authentication method.. 
    .PARAMETER public_key
        Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.
    .PARAMETER target_path
        A path where the file to be copied via SCP. 
        Note: Use complete paths, not relative to user's home folder. 
        Example "/home/ubuntu/datafolder" or "/opt/cm_backups"
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMSCPConnection -name "My Backup Target" -target 192.168.1.19 -auth_method password -user_credentials $tempcreds -target_path "/opt/ciphertrust_backup" -public_key "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLMaZxKfKeEsEOrONz5gaIac+J9XA+JGTSDMWeA7dDl56EQcyv6nTKsEm2hO5iILGKJH1TBw+fiZOU+qWM8wZu4="
    .EXAMPLE
        PS> New-CMSCPConnection -name "My Backup Target" -target 192.168.1.19 -auth_method password -username backupuser -pass backuppassword -target_path "/opt/ciphertrust_backup" -public_key "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLMaZxKfKeEsEOrONz5gaIac+J9XA+JGTSDMWeA7dDl56EQcyv6nTKsEm2hO5iILGKJH1TBw+fiZOU+qWM8wZu4="
    .EXAMPLE
        PS> New-CMSCPConnection -name "My Backup Target" -target 192.168.1.19 -auth_method key -username backupuser -target_path "/opt/ciphertrust_backup" -public_key "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLMaZxKfKeEsEOrONz5gaIac+J9XA+JGTSDMWeA7dDl56EQcyv6nTKsEm2hO5iILGKJH1TBw+fiZOU+qWM8wZu4="
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMSCPConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $target,
        [Parameter()] [int] $port=22,
        [Parameter(Mandatory)] [scpAuthMethod] $auth_method,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter(Mandatory)] [string] $public_key,
        [Parameter(Mandatory)] [string] $target_path,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an SCP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "host"          = $target
        "port"          = $port
        "auth_method"   = $auth_method.ToString()
        "public_key"    = $public_key
        "path_to"       = $target_path
        "products"      = @("backup/restore")
    }

    if($auth_method -eq "key"){
        $body.add('username',$username)
    }elseif ($auth_method -eq "password") {
        if((!$username -and !$pass) -and !$user_credentials){ 
            return "Missing SCP credentials. Please try again."
        }

        if($user_credentials){
            Write-Debug "What is my credential Username? $($user_credentials.username)" 
            Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
            $body.add('username', $user_credentials.username)
            $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
        }else{
            if($username){ $body.add('username', $username) }
            if($pass){ $body.add('password', $pass) }
        }
    }

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
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
        Write-Debug "Response: $($response)"  
        if($auth_method -eq "key"){
            $endpoint = $CM_Session.REST_URL + $target_scp_key
            Write-Debug "CM SCP Key Endpoint: $($endpoint)"
            $cm_public_key = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
            Write-Host "`nCipherTrust Manager Public Key for Authentication:" -ForegroundColor Red
            Write-Host "$($cm_public_key)`n`nBe sure to copy this key to the target's user's authorized_keys file."
        }
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


#Connection Manager -  SCP Connections
#"#/v1/connectionmgmt/services/scp/connections/{id}"
#"#/v1/connectionmgmt/services/scp/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager SCP Connection
    .DESCRIPTION
        Retriving the full list of SCP Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the SCP connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSCPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMSCPConnection -name "My Backup Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMSCPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMSCPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on SCP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSCPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSCPConnections -name $name).resources[0].id 
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

#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections/{id}"
#"#/v1/connectionmgmt/services/scp/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager SCP Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager SCP connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER target
        Hostname or FQDN of SCP.
    .PARAMETER port
        Port where SCP service runs on host. If not specified, system will default to port 22.
    .PARAMETER auth_method
        Authentication type for SCP. Accepted values are "key" or "password".
    .PARAMETER username
        Username for accessing SCP.
    .PARAMETER pass
        Password for accessing SCP.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the SCP User and Password when using the password authentication method.. 
    .PARAMETER public_key
        Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.
    .PARAMETER target_path
        A path where the file to be copied via SCP. 
        Note: Use complete paths, not relative to user's home folder. 
        Example "/home/ubuntu/datafolder" or "/opt/cm_backups"
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> Update-CMSCPConnection -name "My SAP Connection" -api_endpoint "https://demo-kms-endpoint/kms/v2" -username new_user -user_secret new_secret
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMSCPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $target,
        [Parameter()] [int] $port,
        [Parameter()] [scpAuthMethod] $auth_method,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $public_key,
        [Parameter()] [string] $target_path,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an SCP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSCPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSCPConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
    }

    if($user_credentials){
        Write-Debug "What is my credential Username? $($user_credentials.username)" 
        Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
        $body.add('username', $user_credentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
    }else{
        if($username){ $body.add('username', $username) }
        if($pass){ $body.add('password', $pass) }
    }

    if($target){ $body.add('host', $target)}
    if($port){ $body.add('port', $port)}
    if($auth_method){ $body.add('auth_method', $auth_method.ToString())}
    if($public_key){ $body.add('public_key', $public_key)}
    if($target_path){ $body.add('path_to', $target_path)}

    
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
        $response = Invoke-RestMethod  -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::UnprocessableEntity) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Invalid JSON.`n$($apiError.Message)" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections/{id}"
#"#/v1/connectionmgmt/services/scp/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager SCP  Connection
    .DESCRIPTION
        Delete a CipherTrust Manager SCP  Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the SCP  connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSCPConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMSCPConnection -name "My Backup Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMSCPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMSCPConnection{
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

    Write-Debug "Preparing to remove SCP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSCPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSCPConnections -name $name).resources[0].id 
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
    
#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections/{id}"
#"#/v1/connectionmgmt/services/scp/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the SCP Connection. 
    .PARAMETER name
        Name of the existing CipherTrust Manager SCP connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing SCP connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSCPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing SCP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMSCPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSCPConnections -name $name).resources[0].id 
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


#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER target
        Hostname or FQDN of SCP.
    .PARAMETER port
        Port where SCP service runs on host. If not specified, system will default to port 22.
    .PARAMETER auth_method
        Authentication type for SCP. Accepted values are "key" or "password".
    .PARAMETER username
        Username for accessing SCP.
    .PARAMETER pass
        Password for accessing SCP.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the SCP User and Password when using the password authentication method.. 
    .PARAMETER public_key
        Public key of destination host machine. It will be used to verify the host's identity by verifying key fingerprint. You can find it in /etc/ssh/ at host machine.
    .PARAMETER target_path
        A path where the file to be copied via SCP. 
        Note: Use complete paths, not relative to user's home folder. 
        Example "/home/ubuntu/datafolder" or "/opt/cm_backups"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSCPConnParameters{
    param(
        [Parameter(Mandatory)] [string] $target,
        [Parameter()] [int] $port=22,
        [Parameter(Mandatory)] [scpAuthMethod] $auth_method,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter(Mandatory)] [string] $public_key,
        [Parameter(Mandatory)] [string] $target_path
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing SCP Parameters in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"


    # Mandatory Parameters
    $body = [ordered] @{
        "host"          = $target
        "port"          = $port
        "auth_method"   = $auth_method.ToString()
        "public_key"    = $public_key
        "path_to"       = $target_path
    }

    if($auth_method -eq "key"){
        $body.add('username',$username)
    }elseif ($auth_method -eq "password") {
        if((!$username -and !$pass) -and !$user_credentials){ 
            return "Missing SCP credentials. Please try again."
        }

        if($user_credentials){
            Write-Debug "What is my credential Username? $($user_credentials.username)" 
            Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
            $body.add('username', $user_credentials.username)
            $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
        }else{
            if($username){ $body.add('username', $username) }
            if($pass){ $body.add('password', $pass) }
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

#Connection Manager - SCP Connections
#"#/v1/connectionmgmt/services/scp/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/scp/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
        The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSCPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMSCPConnectionNodes -name "My DSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMSCPConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


####
# Export Module Members
####
#Connection Manager - SCP
#/v1/connectionmgmt/services/scp/connections"

Export-ModuleMember -Function Find-CMSCPConnections #/v1/connectionmgmt/services/scp/connections - get"
Export-ModuleMember -Function New-CMSCPConnection #/v1/connectionmgmt/services/scp/connections - post"

#Connection Manager - SCP
#/v1/connectionmgmt/services/scp/connections/{id}"
Export-ModuleMember -Function Get-CMSCPConnection #/v1/connectionmgmt/services/scp/connections/{id} - get"
Export-ModuleMember -Function Update-CMSCPConnection #/v1/connectionmgmt/services/scp/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMSCPConnection #/v1/connectionmgmt/services/scp/connections/{id} - delete"

#Connection Manager - SCP
#/v1/connectionmgmt/services/scp/connections/{id}/test"
Export-ModuleMember -Function Test-CMSCPConnection #/v1/connectionmgmt/services/scp/connections/{id}/test - post"

#Connection Manager - SCP
#/v1/connectionmgmt/services/scp/connection-test"
Export-ModuleMember -Function Test-CMSCPConnParameters #/v1/connectionmgmt/services/scp/connection-test - post"

