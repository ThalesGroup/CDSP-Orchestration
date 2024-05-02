#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Oracle.psm1                                                      #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/oci/connections"
$target_uri_test = "/connectionmgmt/services/oci/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Oracle Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Oracle Module"
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


#This project mirrors the "Connection Manager - oci Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Oracle Connections)

#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections"
#"#/v1/connectionmgmt/services/oci/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager ORACLE Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/ORACLE Connections).   
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
        PS> Find-CMOCIConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMOCIConnections {
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
    
    Write-Debug "Getting a List of all ORACLE Connections in CM"
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
    Write-Debug "List of all CM Oracle Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections"
#"#/v1/connectionmgmt/services/oci/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager Oracle Connection. 
    .DESCRIPTION
        Creates a new Oracle connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER region
        An Oracle Cloud Infrastructure region.
    .PARAMETER tenancy_ocid
        OCID of the tenancy.
    .PARAMETER user_ocid
        OCID of the user.
    .PARAMETER fingerprint
        Fingerprint of the public key added to this user.
        Example: c4:a9:89:47:21:11:11:ac:c4:a9:89:47:21:31:9e
    .PARAMETER private_key
        Private key file for OCI connection (PEM format).
    .PARAMETER key_file
        Specify the filename for the Externally-signed connection certificate.
    .PARAMETER passphrase
        Passphrase of the encrypted private key file.
    .PARAMETER securepass
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMOCIConnection -name "My OCI Connection" -region ap-sydney-1 -user_ocid "ocid1.user.oc1..asdaaaaat2x4wy2jz4iat56kk7kqbzcevwyrasdty2bquujjhwcstmcfvbfq" -tenancy_ocid "ocid1.tenancy.oc1..7777aaaadixb52q2mvlsn634ql577776hb2vg7audpd4d4mcf5zluymff644" -fingerprint "c4:a9:89:47:21:11:11:ac:c4:a9:89:47:21:31:9e" -keyfile C:\Temp\MyOCIPrivateKey.key -pass <KeyFilePassPhrase>

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMOCIConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [ValidateSet(
            'af-johannesburg-1','ap-chuncheon-1','ap-hyderabad-1','ap-melbourne-1','ap-mumbai-1','ap-osaka-1','ap-seoul-1','ap-singapore-1','ap-sydney-1','ap-tokyo-1',
            'ca-montreal-1','ca-toronto-1',
            'eu-amsterdam-1','eu-frankfurt-1','eu-jovanovac-1','eu-madrid-1','eu-marseille-1','eu-milan-1','eu-paris-1','eu-stockholm-1','eu-zurich-1',
            'il-jerusalem-1',
            'me-abudhabi-1','me-dubai-1','me-jeddah-1',
            'mx-monterrey-1','mx-queretaro-1',
            'sa-bogota-1','sa-santiago-1','sa-saopaulo-1','sa-valparaiso-1','sa-vinhedo-1',
            'uk-cardiff-1','uk-london-1',
            'us-ashburn-1','us-chicago-1','us-phoenix-1','us-sanjose-1'
        )] [string] $region,
        [Parameter(Mandatory)] [string] $tenancy_ocid,
        [Parameter(Mandatory)] [string] $user_ocid,
        [Parameter(Mandatory)] [string] $fingerprint,
        [Parameter()] [string] $private_key,
        [Parameter()] [string] $key_file,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $securepass,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Oracle OCI Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "region"        = $region
        "tenancy_ocid"  = $tenancy_ocid
        "user_ocid"     = $user_ocid
        "fingerprint"   = $fingerprint
        "credentials"   = @{}
        "products"      = @("cckm")
    }

    if(!$private_key -and !$key_file){ 
        return "Missing Oracle Private Key. Please try again."
    }
    if($key_file){
        $private_key = Get-Content -Path $key_file -raw -ErrorAction Stop
        $body.credentials.add("key_file",$private_key)
    }elseif($private_key){
        $body.credentials.add("key_file",$private_key)
    }

    $tempKeyFile = Get-Content -Path $key_file
    if($tempKeyFile[1] -like "*ENCRYPTED"){
        if($securepass){
            $body.credentials.add('pass_phrase', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepass.password)))
        }elseif($pass){
            if($pass){ $body.credentials.add('pass_phrase', $pass)}
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


#Connection Manager - Oracle Cloud Connections
#"#/v1/connectionmgmt/services/oci/connections/{id}"
#"#/v1/connectionmgmt/services/oci/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Oracle Connection
    .DESCRIPTION
        Retriving the full list of Oracle Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Oracle connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMOCIConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMOCIConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMOCIConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMOCIConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Oracle Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMOCIConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOCIConnections -name $name).resources[0].id 
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

#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections/{id}"
#"#/v1/connectionmgmt/services/oci/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager Oracle Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager Oracle connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER region
        An Oracle Cloud Infrastructure region.
    .PARAMETER tenancy_ocid
        OCID of the tenancy.
    .PARAMETER user_ocid
        OCID of the user.
    .PARAMETER fingerprint
        Fingerprint of the public key added to this user.
        Example: c4:a9:89:47:21:11:11:ac:c4:a9:89:47:21:31:9e
    .PARAMETER private_key
        Private key file for OCI connection (PEM format).
    .PARAMETER key_file
        Specify the filename for the Externally-signed connection certificate.
    .PARAMETER passphrase
        Passphrase of the encrypted private key file.
    .PARAMETER securepass
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        Existing meta data can be changed but no keys can be deleted.
        e.g. -metadata "red:stop,green:go,blue:ocean"

        For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
        PS> Update-CMOCIConnection -id 72bd06ad-d29f-49ac-b18e-410924f878e4 -user_ocid ocid1.user.oc1..aaaaaaaafyqvwefwrwhlvqwerqersm426viosunxcuqlhgxeih6fa6pyokbua7woa
    .EXAMPLE
        PS> Update-CMOCIConnection -name "My OCI Connection" -tenancy_ocid "ocid1.tenancy.oc1..aaaaaaaaggotgset73cbbtvi5kdhq3igriadqeqweqevldkff3vjpx43hpkncroa"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMOCIConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory)] [ValidateSet(
            'af-johannesburg-1','ap-chuncheon-1','ap-hyderabad-1','ap-melbourne-1','ap-mumbai-1','ap-osaka-1','ap-seoul-1','ap-singapore-1','ap-sydney-1','ap-tokyo-1',
            'ca-montreal-1','ca-toronto-1',
            'eu-amsterdam-1','eu-frankfurt-1','eu-jovanovac-1','eu-madrid-1','eu-marseille-1','eu-milan-1','eu-paris-1','eu-stockholm-1','eu-zurich-1',
            'il-jerusalem-1',
            'me-abudhabi-1','me-dubai-1','me-jeddah-1',
            'mx-monterrey-1','mx-queretaro-1',
            'sa-bogota-1','sa-santiago-1','sa-saopaulo-1','sa-valparaiso-1','sa-vinhedo-1',
            'uk-cardiff-1','uk-london-1',
            'us-ashburn-1','us-chicago-1','us-phoenix-1','us-sanjose-1'
        )] [string] $region,
        [Parameter()] [string] $tenancy_ocid,
        [Parameter()] [string] $user_ocid,
        [Parameter()] [string] $fingerprint,
        [Parameter()] [string] $private_key,
        [Parameter()] [string] $key_file,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $securepass,
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on Oracle Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMOCIConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOCIConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body = [ordered] @{}

    if($region){ $body.add('region',$region) }
    if($tenancy_ocid){ $body.add('tenancy_ocid',$tenancy_ocid) }
    if($user_ocid){ $body.add('user_ocid',$user_ocid) }
    if($fingerprint){ $body.add('fingerprint',$fingerprint) }

    if($key_file){
        $private_key = Get-Content -Path $key_file -raw -ErrorAction Stop
        $body.credentials.add("key_file",$private_key)

        $tempKeyFile = Get-Content -Path $key_file #Retrieving certificate NOT "raw" to be able to test for words instead of characters.
        if($tempKeyFile[1] -like "*ENCRYPTED"){
            if($securepass){
                $body.credentials.add('pass_phrase', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepass.password)))
            }elseif($pass){
                if($pass){ $body.credentials.add('pass_phrase', $pass)}
            }
        }

    }elseif($private_key){
        $body.credentials.add("key_file",$private_key)
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


#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections/{id}"
#"#/v1/connectionmgmt/services/oci/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Oracle Cloud Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Oracle Cloud Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Oracle Cloud connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMOCIConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMOCIConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMOCIConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMOCIConnection{
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

    Write-Debug "Preparing to remove Oracle Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMOCIConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOCIConnections -name $name).resources[0].id 
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
    
#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections/{id}"
#"#/v1/connectionmgmt/services/oci/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the Oracle Cloud Connection. 
    .PARAMETER name
        Name of the existing CipherTrust Manager Oracle Cloud connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Oracle connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMOCIConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Oracle Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMOCIConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMOCIConnections -name $name).resources[0].id 
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


#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER region
        An Oracle Cloud Infrastructure region.
    .PARAMETER tenancy_ocid
        OCID of the tenancy.
    .PARAMETER user_ocid
        OCID of the user.
    .PARAMETER fingerprint
        Fingerprint of the public key added to this user.
        Example: c4:a9:89:47:21:11:11:ac:c4:a9:89:47:21:31:9e
    .PARAMETER private_key
        Private key file for OCI connection (PEM format).
    .PARAMETER key_file
        Specify the filename for the Externally-signed connection certificate.
    .PARAMETER passphrase
        Passphrase of the encrypted private key file.
    .PARAMETER securepass
        Pass a PowerShell Credential Object for the Private Key Passphrase when using an encrypted private key. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMOCIConnParameters{
    param(
        [Parameter(Mandatory)] [ValidateSet(
            'af-johannesburg-1','ap-chuncheon-1','ap-hyderabad-1','ap-melbourne-1','ap-mumbai-1','ap-osaka-1','ap-seoul-1','ap-singapore-1','ap-sydney-1','ap-tokyo-1',
            'ca-montreal-1','ca-toronto-1',
            'eu-amsterdam-1','eu-frankfurt-1','eu-jovanovac-1','eu-madrid-1','eu-marseille-1','eu-milan-1','eu-paris-1','eu-stockholm-1','eu-zurich-1',
            'il-jerusalem-1',
            'me-abudhabi-1','me-dubai-1','me-jeddah-1',
            'mx-monterrey-1','mx-queretaro-1',
            'sa-bogota-1','sa-santiago-1','sa-saopaulo-1','sa-valparaiso-1','sa-vinhedo-1',
            'uk-cardiff-1','uk-london-1',
            'us-ashburn-1','us-chicago-1','us-phoenix-1','us-sanjose-1'
        )] [string] $region,
        [Parameter(Mandatory)] [string] $tenancy_ocid,
        [Parameter(Mandatory)] [string] $user_ocid,
        [Parameter(Mandatory)] [string] $fingerprint,
        [Parameter()] [string] $private_key,
        [Parameter()] [string] $key_file,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $securepass
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Oracle Cloud Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    $body = [ordered] @{
        "region"        = $region
        "tenancy_ocid"  = $tenancy_ocid
        "user_ocid"     = $user_ocid
        "fingerprint"   = $fingerprint
        "credentials"   = @{}
    }

    if(!$private_key -and !$key_file){ 
        return "Missing Oracle Private Key. Please try again."
    }
    if($key_file){
        $private_key = Get-Content -Path $key_file -raw -ErrorAction Stop
        $body.credentials.add("key_file",$private_key)
    }elseif($private_key){
        $body.credentials.add("key_file",$private_key)
    }

    $tempKeyFile = Get-Content -Path $key_file
    if($tempKeyFile[1] -like "*ENCRYPTED"){
        if($securepass){
            $body.credentials.add('pass_phrase', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepass.password)))
        }elseif($pass){
            if($pass){ $body.credentials.add('pass_phrase', $pass)}
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

#Connection Manager - Oracle Connections
#"#/v1/connectionmgmt/services/oci/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/oci/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
        The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMOCIConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMOCIConnectionNodes -name "My DSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMOCIConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


####
# Export Module Members
####
#Connection Manager - Oracle
#/v1/connectionmgmt/services/oci/connections"

Export-ModuleMember -Function Find-CMOCIConnections #/v1/connectionmgmt/services/oci/connections - get"
Export-ModuleMember -Function New-CMOCIConnection #/v1/connectionmgmt/services/oci/connections - post"

#Connection Manager - Oracle
#/v1/connectionmgmt/services/oci/connections/{id}"
Export-ModuleMember -Function Get-CMOCIConnection #/v1/connectionmgmt/services/oci/connections/{id} - get"
Export-ModuleMember -Function Update-CMOCIConnection #/v1/connectionmgmt/services/oci/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMOCIConnection #/v1/connectionmgmt/services/oci/connections/{id} - delete"

#Connection Manager - Oracle
#/v1/connectionmgmt/services/oci/connections/{id}/test"
Export-ModuleMember -Function Test-CMOCIConnection #/v1/connectionmgmt/services/oci/connections/{id}/test - post"

#Connection Manager - Oracle
#/v1/connectionmgmt/services/oci/connection-test"
Export-ModuleMember -Function Test-CMOCIConnParameters #/v1/connectionmgmt/services/oci/connection-test - post"

