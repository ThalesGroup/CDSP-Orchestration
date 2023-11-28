#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Azure.psm1                                                       #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/azure/connections"
$target_uri_test = "/connectionmgmt/services/azure/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Azure Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Azure Module"
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


#This project mirrors the "Connection Manager - Azure Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Azure Connections)

#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections"
#"#/v1/connectionmgmt/services/azure/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Azure Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Azure Connections#/v1/connectionmgmt/services/azure/connections-get).   
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
    .PARAMETER cloud_name
        Filter the result based on the cloud name. 
            - AzureCloud
            - AzureChinaCloud
            - AzureUSGovernment
            - AzureStock
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
        PS> Find-CMAzureConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMAzureConnections {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $sort,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $meta_contains, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $cloud_name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $createdBefore, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $createdAfter, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $last_connection_ok, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $last_connection_before, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $last_connection_after, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $external_connection_used
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Azure Connections in CM"
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
    if ($cloud_name) {
        if ($firstset) {
            $endpoint += "&cloud_name="
        }
        else {
            $endpoint += "?cloud_name="
            $firstset = $true
        }
        $endpoint += $cloud_name
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User set already exists"
            throw "Error $([int]$StatusCode) $($StatusCode): User set already exists"
            return
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of all CM Connections to Azure with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections"
#"#/v1/connectionmgmt/services/azure/connections - post"

<#
    .SYNOPSIS
    Create a new CipherTrust Manager Azure Connection 
    .DESCRIPTION
    Creates a new Azure connection. The connection can be created with Client Secret or Certificate authentication. Currently Azure Stack connection supports only Client Secret.
    .PARAMETER name
    Unique connection name.
    .PARAMETER client_id
    Unique Identifier (client ID) for the Azure application.
    .PARAMETER tenant_id
    Tenant ID of the Azure application.
    .PARAMETER active_directory_endpoint
    (Optional) Azure stack active directory authority URL
    .PARAMETER azure_stack_connection_type
    (Optional) Azure stack connection type
        Options:
        AAD
        ADFS
    .PARAMETER azure_stack_server_cert
    (Optional) Azure stack server certificate. Use the PEM-formatted certificate text.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER azure_stack_server_cert_file
    (Optional) Specify the filename for a PEM certificate for Azure stack server certificate. 
    .PARAMETER cert_duration
    (Optional) Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years).
    .PARAMETER certificate
    (Optional) Externally-signed connection certificate. Use the PEM-formatted certificate text.
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER extcertfile
    (Optional) Specify the filename for the Externally-signed connection certificate. 
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation     
    .PARAMETER client_secret
    (Required in Azure Stack connection) Secret key for the Azure application. 
    .PARAMETER cloud_name
        - AzureCloud
        - AzureChinaCloud
        - AzureUSGovernment
        - AzureStock
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER external_certificate_used
    (Optional) true if the certificate associated with the connection is generated externally, false otherwise.
    .PARAMETER is_certificate_used
    (Optional) User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true in Update (PATCH) API call.
    .PARAMETER key_vault_dns_suffix
    (Optional) Azure stack key vault dns suffix
    .PARAMETER management_url
    (Optional) Azure stack management URL
    .PARAMETER resource_manager_url
    (Optional) Azure stack resource manager URL.
    .PARAMETER vault_resource_url
    (Optional) Azure stack vault service resource URL
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
function New-CMAzureConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $tenant_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $description, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $active_directory_endpoint, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_connection_type, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_cert, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_certfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [int] $cert_duration, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $certificate, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $extcertfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_secret, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $cloud_name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [switch] $external_certificate_used, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [switch] $is_certificate_used, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $key_vault_dns_suffix, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $management_url, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $resource_manager_url, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $vault_resource_url,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Azure Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if (!$client_id -or !$tenant_id) { return "Missing Client or Tenant ID. Please try again."}

    if(($is_certificate_used -eq $false) -and ((!$certificate -and !$extcertfile) -and !$client_secret)){
        return "Please provide certificate or client_secret or set is_certificate_used to true."
    }

    # Mandatory Parameters
    $body=@{
        "name" = $name
        "client_id" = $client_id
        "tenant_id" = $tenant_id
        "products" = @("cckm")
    }

    # Optional Parameters
    if($active_directory_endpoint){ $body.add('access_key_id', $access_key_id)}
    if($azure_stack_connection_type){ $body.add('secret_access_key', $secret_access_key)}
    if($azure_stack_server_certfile){ $azure_stack_server_cert = (Get-Content $azure_stack_server_certfile -raw)}
        if($azure_stack_server_cert){ $body.add('azure_stack_server_cert', $azure_stack_server_cert)}
    if($cert_duration){ $body.add('cert_duration', $cert_duration)}
    if($extcertfile){ $certificate = (Get-Content $extcertfile -raw)}
        if($certificate){ $body.add('certificate', $certificate)}
    if($client_secret){ $body.add('client_secret', $client_secret)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($description){ $body.add('description', $description)}
    if($external_certificate_used){ $body.add('external_certificate_used', [bool]$true)}
    if($is_certificate_used){ $body.add('is_certificate_used', [bool]$true)}
    if($key_vault_dns_suffix){ $body.add('key_vault_dns_suffix', $key_vault_dns_suffix)}
    if($management_url){ $body.add('management_url', $management_url)}
    if($resource_manager_url){ $body.add('resource_manager_url', $resource_manager_url)}
    if($vault_resource_url){ $body.add('vault_resource_url', $vault_resource_url)}
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


#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections/{id}"
#"#/v1/connectionmgmt/services/azure/connections/{id} - get"

<#
    .SYNOPSIS
    Get full details on a CipherTrust Manager Azure Connection
    .DESCRIPTION
    Retriving the full list of Azure Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
    The complete name of the Azure connection. Do not use wildcards.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMAzureConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Get-CMAzureConnection -name "My Azure Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Get-CMAzureConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Use the complete name of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Get-CMAzureConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Azure Connection"
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
    Write-Debug "Connection details retrieved"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections/{id}"
#"#/v1/connectionmgmt/services/azure/connections/{id} - patch"


<#
    .SYNOPSIS
    Update an existing a new CipherTrust Manager Azure Connection 
    .DESCRIPTION
    Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
    Name of the existing CipherTrust Manager Azure connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Azure connection.
    .PARAMETER client_id
    Unique Identifier (client ID) for the Azure application.
    .PARAMETER tenant_id
    Tenant ID of the Azure application.
    .PARAMETER active_directory_endpoint
    (Optional) Azure stack active directory authority URL
    .PARAMETER azure_stack_connection_type
    (Optional) Azure stack connection type
        Options:
        AAD
        ADFS
    .PARAMETER azure_stack_server_cert
    (Optional) Azure stack server certificate. Use the PEM-formatted certificate text.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER azure_stack_server_cert_file
    (Optional) Specify the filename for a PEM certificate for Azure stack server certificate. 
    .PARAMETER cert_duration
    (Optional) Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years).
    .PARAMETER certificate
    (Optional) Externally-signed connection certificate. Use the PEM-formatted certificate text.
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER extcertfile
    (Optional) Specify the filename for the Externally-signed connection certificate. 
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation     
    .PARAMETER client_secret
    (Required in Azure Stack connection) Secret key for the Azure application. 
    .PARAMETER cloud_name
        - AzureCloud
        - AzureChinaCloud
        - AzureUSGovernment
        - AzureStock
    .PARAMETER description
    (Optional) Description of the connection.
    .PARAMETER external_certificate_used
    (Optional) true if the certificate associated with the connection is generated externally, false otherwise.
    .PARAMETER is_certificate_used
    (Optional) User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true in Update (PATCH) API call.
    .PARAMETER key_vault_dns_suffix
    (Optional) Azure stack key vault dns suffix
    .PARAMETER management_url
    (Optional) Azure stack management URL
    .PARAMETER resource_manager_url
    (Optional) Azure stack resource manager URL.
    .PARAMETER vault_resource_url
    (Optional) Azure stack vault service resource URL
    .PARAMETER metadata
    (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
    Existing meta data can be changed but no keys can be deleted.
    e.g. -metadata "red:stop,green:go,blue:ocean"

    For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
    PS> Update-CMAzureConnections -name MyAzureConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMAzureConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $tenant_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $description, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $active_directory_endpoint, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_connection_type, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_cert, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_certfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [int] $cert_duration, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $certificate, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $extcertfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_secret, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $cloud_name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [switch] $external_certificate_used, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [switch] $is_certificate_used, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $key_vault_dns_suffix, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $management_url, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $resource_manager_url, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $vault_resource_url,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on Azure Connection"
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
    
    # Parameters
    $body=@{}

    # Optional Parameters
    if($active_directory_endpoint){ $body.add('access_key_id', $access_key_id)}
    if($azure_stack_connection_type){ $body.add('secret_access_key', $secret_access_key)}
    if($azure_stack_server_certfile){ $azure_stack_server_cert = (Get-Content $azure_stack_server_certfile -raw)}
        if($azure_stack_server_cert){ $body.add('azure_stack_server_cert', $azure_stack_server_cert)}
    if($cert_duration){ $body.add('cert_duration', $cert_duration)}
    if($extcertfile){ $certificate = (Get-Content $extcertfile -raw)}
        if($certificate){ $body.add('certificate', $certificate)}
    if($client_id){ $body.add('client_id', $client_id)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($client_secret){ $body.add('client_secret', $client_secret)}
    if($description){ $body.add('description', $description)}
    if($external_certificate_used){ $body.add('external_certificate_used', [bool]$true)}
    if($is_certificate_used){ $body.add('is_certificate_used', [bool]$true)}
    if($key_vault_dns_suffix){ $body.add('key_vault_dns_suffix', $key_vault_dns_suffix)}
    if($management_url){ $body.add('management_url', $management_url)}
    if($resource_manager_url){ $body.add('resource_manager_url', $resource_manager_url)}
    if($tenant_id){ $body.add('tenant_id', $tenant_id)}
    if($vault_resource_url){ $body.add('vault_resource_url', $vault_resource_url)}
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
    Write-Debug "Connection updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections/{id}"
#"#/v1/connectionmgmt/services/azure/connections/{id} - delete"

<#
    .SYNOPSIS
    Delete a CipherTrust Manager Azure Connection
    .DESCRIPTION
    Delete a CipherTrust Manager Azure Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
    The complete name of the Azure connection. This parameter is case-sensitive.
    .PARAMETER id
    The CipherTrust manager "id" value for the connection.
    Use the Find-CMAzureConnections cmdlet to find the appropriate id value.
    .EXAMPLE
    PS> Remove-CMAzureConnection -name "My Azure Connection"
    Use the complete name of the connection. 
    .EXAMPLE
    PS> Remove-CMAzureConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    Using the id of the connection. 
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Remove-CMAzureConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to remove Azure Connection"
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

    Write-Debug "Endpoint w Target: $($endpoint)"

    $confirmop=""
    while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
        $confirmop = $(Write-Host -ForegroundColor red  "THIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
        if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
            Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
            return "Operation Cancelled"
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
    Write-Debug "Connection deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return "Connection Deleted."
}    
    
#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connections/{id}"
#"#/v1/connectionmgmt/services/azure/connections/{id}/test - post"

<#
    .SYNOPSIS
    Test existing connection.
    .DESCRIPTION
    Tests that an existing connection with the given name, ID, or URI reaches the Azure cloud. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
    Name of the existing CipherTrust Manager Azure connection.
    .PARAMETER id
    CipherTrust Manager "id" value of the existing Azure connection.
    .PARAMETER client_id
    Unique Identifier (client ID) for the Azure application.
    .PARAMETER tenant_id
    Tenant ID of the Azure application.
    .PARAMETER active_directory_endpoint
    (Optional) Azure stack active directory authority URL
    .PARAMETER azure_stack_connection_type
    (Optional) Azure stack connection type
        Options:
        AAD
        ADFS
    .PARAMETER azure_stack_server_cert
    (Optional) Azure stack server certificate. Use the PEM-formatted certificate text.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER azure_stack_server_cert_file
    (Optional) Specify the filename for a PEM certificate for Azure stack server certificate. 
    .PARAMETER certificate
    (Optional) Externally-signed connection certificate. Use the PEM-formatted certificate text.
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER extcertfile
    (Optional) Specify the filename for the Externally-signed connection certificate. 
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation     
    .PARAMETER client_secret
    (Required in Azure Stack connection) Secret key for the Azure application. 
    .PARAMETER cloud_name
        - AzureCloud
        - AzureChinaCloud
        - AzureUSGovernment
        - AzureStock
    .PARAMETER management_url
    (Optional) Azure stack management URL
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMAzureConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $tenant_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $active_directory_endpoint, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_connection_type, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_cert, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_certfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $certificate, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $extcertfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_secret, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $cloud_name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $management_url
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

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

    # Parameters
    $body=@{}

    if($active_directory_endpoint){ $body.add('access_key_id', $access_key_id)}
    if($azure_stack_connection_type){ $body.add('secret_access_key', $secret_access_key)}
    if($azure_stack_server_certfile){ $azure_stack_server_cert = (Get-Content $azure_stack_server_certfile -raw)}
        if($azure_stack_server_cert){ $body.add('azure_stack_server_cert', $azure_stack_server_cert)}
    if($extcertfile){ $certificate = (Get-Content $extcertfile -raw)}
        if($certificate){ $body.add('certificate', $certificate)}
    if($client_id){ $body.add('client_id', $client_id)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($client_secret){ $body.add('client_secret', $client_secret)}
    if($management_url){ $body.add('management_url', $management_url)}
    if($tenant_id){ $body.add('tenant_id', $tenant_id)}
            
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
    Write-Debug "Connection tested"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Azure Connections
#"#/v1/connectionmgmt/services/azure/connection-test - post"

<#
    .SYNOPSIS
    Test connection parameters for a non-existent connection. 
    .DESCRIPTION
    Tests that the connection parameters can be used to reach the Azure account. This does not create a persistent connection.
    .PARAMETER client_id
    Unique Identifier (client ID) for the Azure application.
    .PARAMETER tenant_id
    Tenant ID of the Azure application.
    .PARAMETER active_directory_endpoint
    (Optional) Azure stack active directory authority URL
    .PARAMETER azure_stack_connection_type
    (Optional) Azure stack connection type
        Options:
        AAD
        ADFS
    .PARAMETER azure_stack_server_cert
    (Optional) Azure stack server certificate. Use the PEM-formatted certificate text.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER azure_stack_server_cert_file
    (Optional) Specify the filename for a PEM certificate for Azure stack server certificate. 
    .PARAMETER certificate
    (Optional) Externally-signed connection certificate. Use the PEM-formatted certificate text.
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER extcertfile
    (Optional) Specify the filename for the Externally-signed connection certificate. 
    This option cannot be used with option is_certificate_used and client_secret. User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. 
    The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. 
    User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.
    While it can be used from the command-line, the switch is best used when running automation     
    .PARAMETER client_secret
    (Required in Azure Stack connection) Secret key for the Azure application. 
    .PARAMETER cloud_name
        - AzureCloud
        - AzureChinaCloud
        - AzureUSGovernment
        - AzureStock
    .PARAMETER management_url
    (Optional) Azure stack management URL
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMAzureConnParameters{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $tenant_id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $active_directory_endpoint, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_connection_type, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_cert, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $azure_stack_server_certfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $certificate, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $extcertfile, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_secret, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $cloud_name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $management_url
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Azure Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    if (!$client_id -or !$tenant_id -or !$client_secret) { return "Missing Client ID / Tenant ID / Client Secret. Please try again."}

    # Parameters
    $body=@{
        "client_id" = $client_id
        "tenant_id" = $tenant_id
        "client_secret" = $client_secret
    }

    if($active_directory_endpoint){ $body.add('access_key_id', $access_key_id)}
    if($azure_stack_connection_type){ $body.add('secret_access_key', $secret_access_key)}
    if($azure_stack_server_certfile){ $azure_stack_server_cert = (Get-Content $azure_stack_server_certfile -raw)}
        if($azure_stack_server_cert){ $body.add('azure_stack_server_cert', $azure_stack_server_cert)}
    if($extcertfile){ $certificate = (Get-Content $extcertfile -raw)}
        if($certificate){ $body.add('certificate', $certificate)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($management_url){ $body.add('management_url', $management_url)}
                
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
    Write-Debug "Connection tested"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}  

####
# Export Module Members
####
#Connection Manager - Azure
#/v1/connectionmgmt/services/azure/connections"

Export-ModuleMember -Function Find-CMAzureConnections #/v1/connectionmgmt/services/azure/connections - get"
Export-ModuleMember -Function New-CMAzureConnection #/v1/connectionmgmt/services/azure/connections - post"

#Connection Manager - Azure
#/v1/connectionmgmt/services/azure/connections/{id}"
Export-ModuleMember -Function Get-CMAzureConnection #/v1/connectionmgmt/services/azure/connections/{id} - get"
Export-ModuleMember -Function Update-CMAzureConnection #/v1/connectionmgmt/services/azure/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMAzureConnection #/v1/connectionmgmt/services/azure/connections/{id} - delete"

#Connection Manager - Azure
#/v1/connectionmgmt/services/azure/connections/{id}/test"
Export-ModuleMember -Function Test-CMAzureConnection #/v1/connectionmgmt/services/azure/connections/{id}/test - post"

#Connection Manager - Azure
#/v1/connectionmgmt/services/azure/connection-testt"
Export-ModuleMember -Function Test-CMAzureConnParameters #/v1/connectionmgmt/services/azure/connection-test - post"
