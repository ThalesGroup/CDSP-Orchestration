#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-SAP.psm1                                                         #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/sap-dc/connections"
$target_uri_test = "/connectionmgmt/services/sap-dc/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections SAP Data Custodian Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections SAP Data Custodian Module"
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


#This project mirrors the "Connection Manager - Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/SAP Data Custodian Connections)

#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections"
#"#/v1/connectionmgmt/services/sap-dc/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager SAP Data Custodian Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/SAP Data Custodian Connections).   
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
        PS> Find-CMSAPConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMSAPConnections {
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
    
    Write-Debug "Getting a List of all SAP Data Custodian Connections in CM"
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
    Write-Debug "List of all CM SAP Data Custodian Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections"
#"#/v1/connectionmgmt/services/sap-dc/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager SAP Data Custodian Connection. 
    .DESCRIPTION
        Creates a new SAP Data Custodian connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER api_endpoint
        KMS API endpoint of the SAP Data Custodian. Provide HTTP URL with the API version in it. Only v2 version of KMS API is supported. 
        Example - https://kms-api-demo.datacustodian.cloud.sap/kms/v2.
    .PARAMETER username
        SAP User
    .PARAMETER user_secret
        Secret/Password of the user.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .PARAMETER user_tenant
        Tenant of the user
    .PARAMETER technical_user_api_key
        (Optional) API key of the technical user.
    .PARAMETER technical_user_secret
        (Optional) Secret/Password of the technical user.
    .PARAMETER technical_user_credentials
        (Optional) Pass a PowerShell Credential Object for the Technical User Credentials.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMSAPConnection -name "My SAP Connection" -api_endpoint "https://demo-kms-endpoint/kms/v2" -username user -user_secret mysecret -user_tenant mytenant
    .EXAMPLE
        PS> New-CMSAPConnection -name "My SAP Connection" -api_endpoint "https://demo-kms-endpoint/kms/v2" -user_credentials $SAPUserObject -user_tenant mytenant
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMSAPConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $api_endpoint,
        [Parameter()] [string] $username,
        [Parameter()] [string] $user_secret,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $user_tenant,
        [Parameter()] [string] $technical_user_api_key,
        [Parameter()] [string] $technical_user_secret,
        [Parameter()] [pscredential] $technical_user_credentials,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an SAP Data Custodian Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "products"      = @("cckm")
        "api_endpoint"  = $api_endpoint
        "user_credentials"  = @{}
        "technical_user_credentials"    = @{}
    }

    if((!$username -and !$user_secret) -and !$user_credentials){ 
        return "Missing SAP Data Custodian credentials. Please try again."
    }
    if(!$user_tenant){
        return "Missing SAP Data Custodian tenant. Please try again."
    }
    if($user_credentials){
        Write-Debug "What is my credential Username? $($user_credentials.username)" 
        Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
        $body.user_credentials.add('user', $user_credentials.username)
        $body.user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
        $body.user_credentials.add('tenant', $user_tenant)
    }else{
        if($username){ $body.user_credentials.add('user', $username) }
        if($user_secret){ $body.user_credentials.add('secret', $user_secret) }
        if($user_tenant){ $body.user_credentials.add('tenant', $user_tenant) }
    }

    if($technical_user_credentials){
        Write-Debug "What is my credential Tenant API Key? $($technical_user_credentials.username)" 
        Write-debug "What is my credential Tenant Secret? $($technical_user_credentials.password | ConvertFrom-SecureString)"
        $body.technical_user_credentials.add('api_key', $technical_user_credentials.username)
        $body.technical_user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($technical_user_credentials.password)))
    }else{
        $body.technical_user_credentials.add('api_key', $technical_user_api_key)
        $body.technical_user_credentials.add('secret', $technical_user_secret)
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


#Connection Manager -  SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}"
#"#/v1/connectionmgmt/services/sap-dc/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager SAP Data Custodian Connection
    .DESCRIPTION
        Retriving the full list of SAP Data Custodian Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the SAP Data Custodian connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSAPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMSAPConnection -name "My SAP Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMSAPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMSAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on SAP Data Custodian Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSAPConnections -name $name).resources[0].id 
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

#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}"
#"#/v1/connectionmgmt/services/sap-dc/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager SAP Data Custodian Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager SAP Data Custodian connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER api_endpoint
        KMS API endpoint of the SAP Data Custodian. Provide HTTP URL with the API version in it. Only v2 version of KMS API is supported. 
        Example - https://kms-api-demo.datacustodian.cloud.sap/kms/v2.
    .PARAMETER username
        SAP User
    .PARAMETER user_secret
        Secret/Password of the user.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .PARAMETER user_tenant
        Tenant of the user
    .PARAMETER technical_user_api_key
        (Optional) API key of the technical user.
    .PARAMETER technical_user_secret
        (Optional) Secret/Password of the technical user.
    .PARAMETER technical_user_credentials
        (Optional) Pass a PowerShell Credential Object for the Technical User Credentials.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> Update-CMSAPConnection -name "My SAP Connection" -api_endpoint "https://demo-kms-endpoint/kms/v2" -username new_user -user_secret new_secret
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMSAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $api_endpoint,
        [Parameter()] [string] $username,
        [Parameter()] [string] $user_secret,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $user_tenant,
        [Parameter()] [string] $technical_user_api_key,
        [Parameter()] [string] $technical_user_secret,
        [Parameter()] [pscredential] $technical_user_credentials,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an SAP Data Custodian Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSAPConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    # Optional Parameters
    $body = [ordered] @{
        "user_credentials"  = @{}
        "technical_user_credentials"    = @{}
    }

    if($user_credentials){
        Write-Debug "What is my credential Username? $($user_credentials.username)" 
        Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
        $body.user_credentials.add('user', $user_credentials.username)
        $body.user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
        $body.user_credentials.add('tenant', $user_tenant)
    }else{
        if($username){ $body.user_credentials.add('user', $username) }
        if($user_secret){ $body.user_credentials.add('secret', $user_secret) }
        if($user_tenant){ $body.user_credentials.add('tenant', $user_tenant) }
    }

    if($technical_user_credentials){
        Write-Debug "What is my credential Tenant API Key? $($technical_user_credentials.username)" 
        Write-debug "What is my credential Tenant Secret? $($technical_user_credentials.password | ConvertFrom-SecureString)"
        $body.technical_user_credentials.add('api_key', $technical_user_credentials.username)
        $body.technical_user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($technical_user_credentials.password)))
    }else{
        if($technical_user_api_key){ $body.technical_user_credentials.add('api_key', $technical_user_api_key) }
        if($technical_user_secret){ $body.technical_user_credentials.add('secret', $technical_user_secret) }
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


#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}"
#"#/v1/connectionmgmt/services/sap-dc/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager SAP Data Custodian Connection
    .DESCRIPTION
        Delete a CipherTrust Manager SAP Data Custodian Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the SAP Data Custodian Connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSAPConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMSAPConnection -name "My SAP Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMSAPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMSAPConnection{
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

    Write-Debug "Preparing to remove SAP Data Custodian Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSAPConnections -name $name).resources[0].id 
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
    
#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}"
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the SAP Data Custodian Cloud Connection. 
    .PARAMETER name
        Name of the existing CipherTrust Manager SAP Data Custodian Cloud connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing SAP Data Custodian connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing SAP Data Custodian Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMSAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSAPConnections -name $name).resources[0].id 
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


#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER api_endpoint
        KMS API endpoint of the SAP Data Custodian. Provide HTTP URL with the API version in it. Only v2 version of KMS API is supported. 
        Example - https://kms-api-demo.datacustodian.cloud.sap/kms/v2.
    .PARAMETER username
        SAP User
    .PARAMETER user_secret
        Secret/Password of the user.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .PARAMETER user_tenant
        Tenant of the user
    .PARAMETER technical_user_api_key
        (Optional) API key of the technical user.
    .PARAMETER technical_user_secret
        (Optional) Secret/Password of the technical user.
    .PARAMETER technical_user_credentials
        (Optional) Pass a PowerShell Credential Object for the Technical User Credentials.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSAPConnParameters{
    param(
        [Parameter(Mandatory)] [string] $api_endpoint,
        [Parameter()] [string] $username,
        [Parameter()] [string] $user_secret,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $user_tenant,
        [Parameter()] [string] $technical_user_api_key,
        [Parameter()] [string] $technical_user_secret,
        [Parameter()] [pscredential] $technical_user_credentials
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an SAP Data Custodian Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "products"      = @("cckm")
        "api_endpoint"  = $api_endpoint
        "user_credentials"  = @{}
        "technical_user_credentials"    = @{}
    }

    if((!$username -and !$user_secret) -and !$user_credentials){ 
        return "Missing SAP Data Custodian credentials. Please try again."
    }
    if(!$user_tenant){
        return "Missing SAP Data Custodian tenant. Please try again."
    }
    if($user_credentials){
        Write-Debug "What is my credential Username? $($user_credentials.username)" 
        Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
        $body.user_credentials.add('user', $user_credentials.username)
        $body.user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password)))
        $body.user_credentials.add('tenant', $user_tenant)
    }else{
        if($username){ $body.user_credentials.add('user', $username) }
        if($user_secret){ $body.user_credentials.add('secret', $user_secret) }
        if($user_tenant){ $body.user_credentials.add('tenant', $user_tenant) }
    }

    if($technical_user_credentials){
        Write-Debug "What is my credential Tenant API Key? $($technical_user_credentials.username)" 
        Write-debug "What is my credential Tenant Secret? $($technical_user_credentials.password | ConvertFrom-SecureString)"
        $body.technical_user_credentials.add('api_key', $technical_user_credentials.username)
        $body.technical_user_credentials.add('secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($technical_user_credentials.password)))
    }else{
        $body.technical_user_credentials.add('api_key', $technical_user_api_key)
        $body.technical_user_credentials.add('secret', $technical_user_secret)
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

#Connection Manager - SAP Data Custodian Connections
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/sap-dc/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
        The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSAPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMSAPConnectionNodes -name "My DSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMSAPConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


####
# Export Module Members
####
#Connection Manager - SAP Data Custodian
#/v1/connectionmgmt/services/sap-dc/connections"

Export-ModuleMember -Function Find-CMSAPConnections #/v1/connectionmgmt/services/sap-dc/connections - get"
Export-ModuleMember -Function New-CMSAPConnection #/v1/connectionmgmt/services/sap-dc/connections - post"

#Connection Manager - SAP Data Custodian
#/v1/connectionmgmt/services/sap-dc/connections/{id}"
Export-ModuleMember -Function Get-CMSAPConnection #/v1/connectionmgmt/services/sap-dc/connections/{id} - get"
Export-ModuleMember -Function Update-CMSAPConnection #/v1/connectionmgmt/services/sap-dc/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMSAPConnection #/v1/connectionmgmt/services/sap-dc/connections/{id} - delete"

#Connection Manager - SAP Data Custodian
#/v1/connectionmgmt/services/sap-dc/connections/{id}/test"
Export-ModuleMember -Function Test-CMSAPConnection #/v1/connectionmgmt/services/sap-dc/connections/{id}/test - post"

#Connection Manager - SAP Data Custodian
#/v1/connectionmgmt/services/sap-dc/connection-test"
Export-ModuleMember -Function Test-CMSAPConnParameters #/v1/connectionmgmt/services/sap-dc/connection-test - post"

