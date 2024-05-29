#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Salesforce.psm1                                                  #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/salesforce/connections"
$target_uri_test = "/connectionmgmt/services/salesforce/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Salesforce Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Salesforce Module"
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


#This project mirrors the "Connection Manager - Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Salesforce Connections)

#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections"
#"#/v1/connectionmgmt/services/salesforce/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Salesforce Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Salesforce Connections).   
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
        PS> Find-CMSalesforceConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMSalesforceConnections {
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
    
    Write-Debug "Getting a List of all Salesforce Connections in CM"
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
    Write-Debug "List of all CM Salesforce Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections"
#"#/v1/connectionmgmt/services/salesforce/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager Salesforce Connection. 
    .DESCRIPTION
        Creates a new Salesforce connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER cloud_name
        Name or Type of the Salesforce cloud. Supported cloud options are listed below:
            - Salesforce Sandbox Cloud
            - Salesforce Cloud
    .PARAMETER username
        Username of the Salesforce account. Not required when using domain name.
    .PARAMETER pass
        Password for the Salesforce account. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication or when using domain name. “Allow OAuth Username-Password Flows” must be enabled under Setup -> Settings -> Identity -> OAuth and OpenID Connect Settings in your salesforce account to use password for authentication.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Salesforce username and password. 
    .PARAMETER client_id
        Unique Identifier (client ID/consumer key) for the Salesforce Application.
    .PARAMETER client_secret
        Consumer Secret for the Salesforce application. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication.
    .PARAMETER client_credentials
        Pass a PowerShell Credential Object for the Salesforce Client ID and Secret values. 
    .PARAMETER domain_name
        The domain_name represents My Domain that could be found in your salesforce account. 
        This My Domain acts as a subdomain in framing URL https://MyDomain.my.salesforce.com which is eventually used to establish a connection to salesforce account. 
        The client_credentials grant uses this URL to make a request when usernmame and password are not provided. 
        You can refer to Salesforce documentation in order to learn more about My Domain.
    .PARAMETER is_certificate_used
        User has the option to choose the Certificate Authentication method instead of Client Credentials (password and client_secret) Authentication for Salesforce Cloud connection. In order to use the Certificate, set this field to true. Once the connection is created, in the response user will get a certificate.
    .PARAMETER cert_duration
        Duration in days for which the salesforce server certificate is valid, default (730 i.e. 2 Years).
    .PARAMETER certificate
        User has the option to upload external certificate for Salesforce Cloud connection. This option cannot be used with option is_certificate_used and client_secret. 
        
        User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA.
        The Certificate must have an RSA key strength of 1024, 2048 or 4096. 
        User can also update the new external certificate in the existing connection in Update (PATCH) API call. 
        Any unused certificate will automatically deleted in 24 hours.
    .PARAMETER certificate_file
        Specify the filename for a PEM certificate for the Client Certificate.
    .PARAMETER enable_mutual_tls
        Setting it to true will enforce SSL or TLS mutual authentication for Salesforce API calls. Default is false.
    .PARAMETER tls_cert_w_key
        TLS client certificate along with private key to be used as client side certificate to support Salesforce Mutual Authentication Certificate option. 
        Provide certificate chain as a single PEM-encoded CA-signed certificate representing the concatenated chain of certificates. 
        The uploaded certificate chain must include the intermediate certificates and private key.
        Certificate order should be client certificate and then add its signing certificate, intermediate certificates if any followed by private key of Client certificate.
        If Private key is encrypted then specify password/passphrase used to encrypt Private key in tls_client_private_key_password param.
    .PARAMETER tls_cert_file
        Specify the filename for a PEM certificate for the Mutual TLS Authentication certificate.
    .PARAMETER tls_cert_key_pass
        Password/passphrase for TLS Client Private key. Provide value if private key is encrypted with password/passphrase.
    .PARAMETER tls_cert_key_pscredential
        Pass a PowerShell Credential Object for the TLS Client Private key.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMSalesforceConnection -name "My Salesforce Connection" 
    .EXAMPLE
        PS> New-CMSalesforceConnection -name "My Salesforce Connection" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMSalesforceConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [ValidateSet("Salesforce Cloud","Salesforce Sandbox Cloud")] [string] $cloud_name,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $client_id,
        [Parameter()] [string] $client_secret,
        [Parameter()] [pscredential] $client_credentials,
        [Parameter()] [string] $domain_name,
        [Parameter()] [switch] $is_certificate_used,
        [Parameter()] [int] $cert_duration,
        [Parameter()] [string] $certificate,
        [Parameter()] [string] $cert_file,
        [Parameter()] [switch] $enable_mutual_tls,
        [Parameter()] [string] $tls_cert_w_key,
        [Parameter()] [string] $tls_cert_file,
        [Parameter()] [string] $tls_cert_key_pass,
        [Parameter()] [pscredential] $tls_cert_key_pscredential,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Salesforce Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "products"      = @("cckm")
        "cloud_name"    = $cloud_name
    }

    if($client_credentials){
        if($client_credentials.UserName){ $body.add('client_id',$client_credentials.UserName) }
        if($client_credentials.Password){ $body.add('client_secret',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_credentials.password))) }
    }else{
        if($client_id){ $body.add('client_id',$client_id) }
            else{ return "Missing Client ID, please try again." }
        if($client_secret){ 
            $body.add('client_secret',$client_secret) 
            if($is_certificate_used){ return 'Option "is_certificate_used" cannot be used in conjunction with "client_secret"'}
        }
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

    if($domain_name){ $body.add('domain_name',$domain_name) }
    if($is_certificate_used){ $body.add("is_certificate_used",[bool]$true) }
    if($cert_duration){ $body.add('cert_duration',$cert_duration) }

    if($cert_file){ $certificate = (Get-Content $cert_file -raw) }
        if($certificate){ $body.add('certificate', $certificate) }

    if($enable_mutual_tls){ 
        $body.add("enable_mutual_tls",[bool]$true) 
        if($tls_cert_file){ $tls_cert_w_key = (Get-Content $tls_cert_file -raw) }
            if($tls_cert_w_key){ $body.add('tls_client_certificate_with_private_key', $tls_cert_w_key) }
        if($tls_cert_key_pscredential){ 
            $body.add('tls_client_private_key_password',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tls_cert_key_pscredential.password)))
        }elseif($tls_cert_key_pass){
            $body.add('tls_client_private_key_password',$tls_cert_key_pass)
        }else{
            return "Missing Mutual TLS Certificate Private Key password. Please try again."
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


#Connection Manager -  Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections/{id}"
#"#/v1/connectionmgmt/services/salesforce/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Salesforce Connection
    .DESCRIPTION
        Retriving the full list of Salesforce Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Salesforce connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSalesforceConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMSalesforceConnection -name "My Salesforce Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMSalesforceConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMSalesforceConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Salesforce Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSalesforceConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSalesforceConnections -name $name).resources[0].id 
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

#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections/{id}"
#"#/v1/connectionmgmt/services/salesforce/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager Salesforce Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager Salesforce connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER cloud_name
        Name or Type of the Salesforce cloud. Supported cloud options are listed below:
            - Salesforce Sandbox Cloud
            - Salesforce Cloud
    .PARAMETER username
        Username of the Salesforce account. Not required when using domain name.
    .PARAMETER pass
        Password for the Salesforce account. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication or when using domain name. “Allow OAuth Username-Password Flows” must be enabled under Setup -> Settings -> Identity -> OAuth and OpenID Connect Settings in your salesforce account to use password for authentication.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Salesforce username and password. 
    .PARAMETER client_id
        Unique Identifier (client ID/consumer key) for the Salesforce Application.
    .PARAMETER client_secret
        Consumer Secret for the Salesforce application. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication.
    .PARAMETER client_credentials
        Pass a PowerShell Credential Object for the Salesforce Client ID and Secret values. 
    .PARAMETER domain_name
        The domain_name represents My Domain that could be found in your salesforce account. 
        This My Domain acts as a subdomain in framing URL https://MyDomain.my.salesforce.com which is eventually used to establish a connection to salesforce account. 
        The client_credentials grant uses this URL to make a request when usernmame and password are not provided. 
        You can refer to Salesforce documentation in order to learn more about My Domain.
    .PARAMETER regenerate_certificate
        To update the certificate, set the regenerate_certificate to true. This will update the certificate, corresponding private key and certificate subject.
    .PARAMETER cert_duration
        Duration in days for which the salesforce server certificate is valid, default (730 i.e. 2 Years).
    .PARAMETER certificate
        User has the option to upload external certificate for Salesforce Cloud connection. This option cannot be used with option is_certificate_used and client_secret. 
        
        User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA.
        The Certificate must have an RSA key strength of 1024, 2048 or 4096. 
        User can also update the new external certificate in the existing connection in Update (PATCH) API call. 
        Any unused certificate will automatically deleted in 24 hours.
    .PARAMETER certificate_file
        Specify the filename for a PEM certificate for the Client Certificate.
    .PARAMETER enable_mutual_tls
        Setting it to true will enforce SSL or TLS mutual authentication for Salesforce API calls. Default is false.
    .PARAMETER tls_cert_w_key
        TLS client certificate along with private key to be used as client side certificate to support Salesforce Mutual Authentication Certificate option. 
        Provide certificate chain as a single PEM-encoded CA-signed certificate representing the concatenated chain of certificates. 
        The uploaded certificate chain must include the intermediate certificates and private key.
        Certificate order should be client certificate and then add its signing certificate, intermediate certificates if any followed by private key of Client certificate.
        If Private key is encrypted then specify password/passphrase used to encrypt Private key in tls_client_private_key_password param.
    .PARAMETER tls_cert_file
        Specify the filename for a PEM certificate for the Mutual TLS Authentication certificate.
    .PARAMETER tls_cert_key_pass
        Password/passphrase for TLS Client Private key. Provide value if private key is encrypted with password/passphrase.
    .PARAMETER tls_cert_key_pscredential
        Pass a PowerShell Credential Object for the TLS Client Private key.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> Update-CMSalesforceConnection -name "My Salesforce Connection" -api_endpoint "https://demo-kms-endpoint/kms/v2" -username new_user -user_secret new_secret
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMSalesforceConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [ValidateSet("Salesforce Cloud","Salesforce Sandbox Cloud")] [string] $cloud_name,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $client_id,
        [Parameter()] [string] $client_secret,
        [Parameter()] [pscredential] $client_credentials,
        [Parameter()] [string] $domain_name,
        [Parameter()] [switch] $is_certificate_used,
        [Parameter()] [int] $cert_duration,
        [Parameter()] [string] $certificate,
        [Parameter()] [string] $cert_file,
        [Parameter()] [switch] $enable_mutual_tls,
        [Parameter()] [string] $tls_cert_w_key,
        [Parameter()] [string] $tls_cert_file,
        [Parameter()] [string] $tls_cert_key_pass,
        [Parameter()] [pscredential] $tls_cert_key_pscredential,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating an Salesforce Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSalesforceConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSalesforceConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    # Optional Parameters
    $body = [ordered] @{
    }

    if($cloud_name){ $body.add('cloud_name',$cloud_name) }

    if($client_credentials){
        if($client_credentials.UserName){ $body.add('client_id',$client_credentials.UserName) }
        if($client_credentials.Password){ $body.add('client_secret',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_credentials.password))) }
    }else{
        if($client_id){ $body.add('client_id',$client_id) }
            else{ return "Missing Client ID, please try again." }
        if($client_secret){ $body.add('client_secret',$client_secret) }
    }


    if($user_credentials){
        Write-Debug "What is my credential Username? $($user_credentials.username)" 
        Write-debug "What is my credential User Secret/Password? $($user_credentials.password | ConvertFrom-SecureString)"
        if($user_credentials.username){ $body.add('username', $user_credentials.username) }
        if($user_credentials.password){ $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($user_credentials.password))) }
    }else{
        if($username){ $body.add('username', $username) }
        if($pass){ $body.add('password', $pass) }
    }

    if($domain_name){ $body.add('domain_name',$domain_name) }
    if($is_certificate_used){ $body.add("is_certificate_used",[bool]$true) }
    if($cert_duration){ $body.add('cert_duration',$cert_duration) }

    if($cert_file){ $certificate = (Get-Content $cert_file -raw) }
        if($certificate){ $body.add('certificate', $certificate) }

    if($enable_mutual_tls){ 
        $body.add("enable_mutual_tls",[bool]$true) 
        if($tls_cert_file){ $tls_cert_w_key = (Get-Content $tls_cert_file -raw) }
            if($tls_cert_w_key){ $body.add('tls_client_certificate_with_private_key', $tls_cert_w_key) }
        if($tls_cert_key_pscredential){ 
            $body.add('tls_client_private_key_password',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tls_cert_key_pscredential.password)))
        }elseif($tls_cert_key_pass){
            $body.add('tls_client_private_key_password',$tls_cert_key_pass)
        }else{
            return "Missing Mutual TLS Certificate Private Key password. Please try again."
        }
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


#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections/{id}"
#"#/v1/connectionmgmt/services/salesforce/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Salesforce Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Salesforce Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Salesforce Connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSalesforceConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMSalesforceConnection -name "My Salesforce Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMSalesforceConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMSalesforceConnection{
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

    Write-Debug "Preparing to remove Salesforce Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMSalesforceConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSalesforceConnections -name $name).resources[0].id 
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
    
#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections/{id}"
#"#/v1/connectionmgmt/services/salesforce/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the Salesforce Cloud Connection. 
    .PARAMETER name
        Name of the existing CipherTrust Manager Salesforce Cloud connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Salesforce connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSalesforceConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Salesforce Cloud Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMSalesforceConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMSalesforceConnections -name $name).resources[0].id 
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


#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER cloud_name
        Name or Type of the Salesforce cloud. Supported cloud options are listed below:
            - Salesforce Sandbox Cloud
            - Salesforce Cloud
    .PARAMETER username
        Username of the Salesforce account. Not required when using domain name.
    .PARAMETER pass
        Password for the Salesforce account. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication or when using domain name. “Allow OAuth Username-Password Flows” must be enabled under Setup -> Settings -> Identity -> OAuth and OpenID Connect Settings in your salesforce account to use password for authentication.
    .PARAMETER user_credentials
        Pass a PowerShell Credential Object for the Salesforce username and password. 
    .PARAMETER client_id
        Unique Identifier (client ID/consumer key) for the Salesforce Application.
    .PARAMETER client_secret
        Consumer Secret for the Salesforce application. This a mandatory parameter for a connection with Client Credential Authentication method. This parameter is not needed for Certificate Authentication.
    .PARAMETER client_credentials
        Pass a PowerShell Credential Object for the Salesforce Client ID and Secret values. 
    .PARAMETER domain_name
        The domain_name represents My Domain that could be found in your salesforce account. 
        This My Domain acts as a subdomain in framing URL https://MyDomain.my.salesforce.com which is eventually used to establish a connection to salesforce account. 
        The client_credentials grant uses this URL to make a request when usernmame and password are not provided. 
        You can refer to Salesforce documentation in order to learn more about My Domain.
    .PARAMETER certificate
        User has the option to upload external certificate for Salesforce Cloud connection. This option cannot be used with option is_certificate_used and client_secret. 
        
        User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA.
        The Certificate must have an RSA key strength of 1024, 2048 or 4096. 
        User can also update the new external certificate in the existing connection in Update (PATCH) API call. 
        Any unused certificate will automatically deleted in 24 hours.
    .PARAMETER certificate_file
        Specify the filename for a PEM certificate for the Client Certificate.
    .PARAMETER tls_cert_key_pass
        Password/passphrase for TLS Client Private key. Provide value if private key is encrypted with password/passphrase.
    .PARAMETER tls_cert_key_pscredential
        Pass a PowerShell Credential Object for the TLS Client Private key.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMSalesforceConnParameters{
    param(
        [Parameter(Mandatory)] [ValidateSet("Salesforce Cloud","Salesforce Sandbox Cloud")] [string] $cloud_name,
        [Parameter()] [string] $username,
        [Parameter()] [string] $pass,
        [Parameter()] [pscredential] $user_credentials,
        [Parameter()] [string] $client_id,
        [Parameter()] [string] $client_secret,
        [Parameter()] [pscredential] $client_credentials,
        [Parameter()] [string] $domain_name,
        [Parameter()] [string] $certificate,
        [Parameter()] [string] $cert_file,
        #[Parameter()] [switch] $enable_mutual_tls,
        #[Parameter()] [string] $tls_cert_w_key,
        #[Parameter()] [string] $tls_cert_file,
        [Parameter()] [string] $tls_cert_key_pass,
        [Parameter()] [pscredential] $tls_cert_key_pscredential
    )


<#Future Parameters
PARAMETER enable_mutual_tls
Setting it to true will enforce SSL or TLS mutual authentication for Salesforce API calls. Default is false.
PARAMETER tls_cert_w_key
TLS client certificate along with private key to be used as client side certificate to support Salesforce Mutual Authentication Certificate option. 
Provide certificate chain as a single PEM-encoded CA-signed certificate representing the concatenated chain of certificates. 
The uploaded certificate chain must include the intermediate certificates and private key.
Certificate order should be client certificate and then add its signing certificate, intermediate certificates if any followed by private key of Client certificate.
If Private key is encrypted then specify password/passphrase used to encrypt Private key in tls_client_private_key_password param.
PARAMETER tls_cert_file
Specify the filename for a PEM certificate for the Mutual TLS Authentication certificate.
#>

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Salesforce Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "cloud_name"    = $cloud_name
    }

    if($client_credentials){
        if($client_credentials.UserName){ $body.add('client_id',$client_credentials.UserName) }
        if($client_credentials.Password){ $body.add('client_secret',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_credentials.password))) }
    }else{
        if($client_id){ $body.add('client_id',$client_id) }
            else{ return "Missing Client ID, please try again." }
        if($client_secret){ $body.add('client_secret',$client_secret) }
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

    if($domain_name){ $body.add('domain_name',$domain_name) }

    if($cert_file){ $certificate = (Get-Content $cert_file -raw) }
        if($certificate){ $body.add('certificate', $certificate) }

#    if($enable_mutual_tls){ $body.add("enable_mutual_tls",[bool]$true) }
#    if($tls_cert_file){ $tls_cert_w_key = (Get-Content $tls_cert_file -raw) }
#        if($tls_cert_w_key){ $body.add('tls_client_certificate_with_private_key', $tls_cert_w_key) }
#    if($tls_cert_key_pscredential){ 
#        $body.add('tls_client_private_key_password',[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tls_cert_key_pscredential.password)))
#    }elseif($tls_cert_key_pass){
#        $body.add('tls_client_private_key_password',$tls_cert_key_pass)
#    }else{
#        return "Missing Mutual TLS Certificate Private Key password. Please try again."
#    }

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

#Connection Manager - Salesforce Connections
#"#/v1/connectionmgmt/services/salesforce/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/salesforce/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
        The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMSalesforceConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMSalesforceConnectionNodes -name "My DSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMSalesforceConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


####
# Export Module Members
####
#Connection Manager - Salesforce 
#/v1/connectionmgmt/services/salesforce/connections"

Export-ModuleMember -Function Find-CMSalesforceConnections #/v1/connectionmgmt/services/salesforce/connections - get"
Export-ModuleMember -Function New-CMSalesforceConnection #/v1/connectionmgmt/services/salesforce/connections - post"

#Connection Manager - Salesforce 
#/v1/connectionmgmt/services/salesforce/connections/{id}"
Export-ModuleMember -Function Get-CMSalesforceConnection #/v1/connectionmgmt/services/salesforce/connections/{id} - get"
Export-ModuleMember -Function Update-CMSalesforceConnection #/v1/connectionmgmt/services/salesforce/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMSalesforceConnection #/v1/connectionmgmt/services/salesforce/connections/{id} - delete"

#Connection Manager - Salesforce 
#/v1/connectionmgmt/services/salesforce/connections/{id}/test"
Export-ModuleMember -Function Test-CMSalesforceConnection #/v1/connectionmgmt/services/salesforce/connections/{id}/test - post"

#Connection Manager - Salesforce 
#/v1/connectionmgmt/services/salesforce/connection-test"
Export-ModuleMember -Function Test-CMSalesforceConnParameters #/v1/connectionmgmt/services/salesforce/connection-test - post"

