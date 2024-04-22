#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-AWS.psm1                                                         #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################


####
# Local Variables
####
$target_uri = "/connectionmgmt/services/aws/connections"
$target_uri_test = "/connectionmgmt/services/aws/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections AWS Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections AWS Module"
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


#This project mirrors the "Connection Manager - AWS Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/AWS Connections)

#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections"
#"#/v1/connectionmgmt/services/aws/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager AWS Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/AWS Connections#/v1/connectionmgmt/services/aws/connections-get).   
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
    .PARAMETER is_role_anywhere
        Filters IAM Roles Anywhere Connections 
    .EXAMPLE
        PS> Find-CMAWSConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMAWSConnections {
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
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $meta_contains, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [ValidateSet('aws','aws-us-goc','aws-cn')]
        [string] $cloud_name,
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [switch] $is_role_anywhere

    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all AWS Connections in CM"
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
    Write-Debug "List of all CM Connections to AWS with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections"
#"#/v1/connectionmgmt/services/aws/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager AWS Connection 
    .DESCRIPTION
        Creates a new AWS connection. You can either create a connection using the Secret Access Key and ID or use the Certificate-based authentication to create an IAM Roles Anywhere connection.
    .PARAMETER name
        Unique connection name.
    .PARAMETER access_key_id
        (Optional) Client ID of the AWS User
    .PARAMETER secret_access_key
        (Optional) Client secret associated with the access key ID of the AWS user.
    .PARAMETER assume_role_arn
        (Optional) AWS IAM Role ARN
    .PARAMETER assume_role_external_id
        (Optional)Specify AWS Role external ID.
    .PARAMETER aws_region
        (Optional)AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given. Default values are:

            for aws, default region will be "us-east-1"
            for aws-us-gov, default region will be "us-gov-east-1"
            for aws-cn, default region will be "cn-north-1"
    .PARAMETER aws_sts_regional_endpoints
        (Optional)By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are:

            legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com
            regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region.

            To know more about AWS STS please go through the following link https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
    .PARAMETER cloud_name
        (Optional)Name of the cloud. Options: aws (default), aws-us-goc, or aws-cn
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER is_role_anywhere
        (Optional) Use this switch to create connections of type AWS IAM Anywhere with temporary credentials.
    .PARAMETER anywhere_role_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Role ARN.
    .PARAMETER anywhere_role_cert
        (Required if using IAM Role Anywhere) Upload the PEM-formatted certificate text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER anywhere_role_certfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM certificate for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_role_privkey
        (Required if using IAM Role Anywhere) Upload the PEM-formatted private key text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted private key then pass the variable to the command.
    .PARAMETER anywhere_role_keyfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM private key for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_profile_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Profile ARN.
    .PARAMETER anywhere_trust_anchor_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Trust Anchor ARN.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMAWSConnection -name MyTestAWSConnection2 -description "This is my Test AWS Connection" -access_key_id abc123abc123 -secret_access_key xyz987xyz987 -assume_role_arn "arn:aws:iam::123456789012:user/johndoe" -assume_role_external_id EXT_ROLE_ID -aws_region us-west-1 -aws_sts_regional_endpoints regional -cloud_name aws-us-gov -metadata "red:stop,:green:go,blue:ocean" 
    .EXAMPLE
        PS> New-CMAWSConnection -name MyTestAWSConnection3 -description "This is my Test AWS Connection" -assume_role_arn "arn:aws:iam::123456789012:user/johndoe" -assume_role_external_id EXT_ROLE_ID -aws_region us-west-1 -aws_sts_regional_endpoints regional -cloud_name aws-us-gov -is_role_anywhere -anywhere_role_arn "arn:aws:iam::123456789012:user/johndoe" -anywhere_role_certfile mongocert.pem -anywhere_role_keyfile mongokey.pem -anywhere_profile_arn "arn:aws:iam::123456789012:user" -anywhere_trust_anchor_arn "arn:aws:iam::123456789012:user/johndoe" -metadata "red:stop,green:go,blue:ocean"
        
        This example uses certificate files for the IAM Role Anywhere certificate. It will import the files and convert to proper JSON format.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMAWSConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $access_key_id, 
        [Parameter()] [string] $secret_access_key, 
        [Parameter()] [string] $assume_role_arn, 
        [Parameter()] [string] $assume_role_external_id, 
        [Parameter()] [ValidateSet(
            'us-east-2','us-east-1','us-west-1','us-west-2',
            'af-south-1',
            'ap-east-1','ap-south-2','ap-southeast-3','ap-southeast-4','ap-south-1','ap-northeast-3','ap-northeast-2','ap-southeast-1','ap-southeast-2','ap-northeast-1',
            'ca-central-1',
            'eu-central-1','eu-west-1','eu-west-2','eu-south-1','eu-west-3','eu-south-2','eu-north-1','eu-central-2',
            'il-central-1',
            'me-south-1','me-central-1',
            'sa-east-1',
            'us-gov-east-1','us-gov-west-1'
        )] [string] $aws_region, 
        [Parameter()] [string] $aws_sts_regional_endpoints, 
        [Parameter()] [ValidateSet('aws','aws-us-goc','aws-cn')] [string] $cloud_name, 
        [Parameter()] [switch] $is_role_anywhere, 
        [Parameter()] [string] $anywhere_role_arn, 
        [Parameter()] [string] $anywhere_role_cert, 
        [Parameter()] [string] $anywhere_role_certfile, 
        [Parameter()] [string] $anywhere_role_privkey, 
        [Parameter()] [string] $anywhere_role_keyfile, 
        [Parameter()] [string] $anywhere_profile_arn, 
        [Parameter()] [string] $anywhere_trust_anchor_arn,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an AWS Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"


    # Mandatory Parameters
    $body = [ordered] @{
        "name" = $name
        "products" = @("cckm")
    }

    # Optional Parameters
    if($access_key_id){ $body.add('access_key_id', $access_key_id)}
    if($secret_access_key){ $body.add('secret_access_key', $secret_access_key)}
    if($assume_role_arn){ $body.add('assume_role_arn', $assume_role_arn)}
    if($assume_role_external_id){ $body.add('assume_role_external_id', $assume_role_external_id)}
    if($aws_region){ $body.add('aws_region', $aws_region)}
    if($aws_sts_regional_endpoints){ $body.add('aws_sts_regional_endpoints', $aws_sts_regional_endpoints)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($description){ $body.add('description', $description)}
    if($is_role_anywhere){
        if(!$anywhere_role_arn -or !$anywhere_profile_arn -or !$anywhere_trust_anchor_arn){
            return "Missing IAM Anywhere Parameters. Please try again."
        }elseif(!$anywhere_role_cert -and !$anywhere_role_certfile){
            return "Missing IAM Anywhere Certificate. Please try again."
        }elseif(!$anywhere_role_privkey -and !$anywhere_role_keyfile){
            return "Missing IAM Anywhere Private Key. Please try again."
        }
        if($anywhere_role_certfile){ $anywhere_role_cert = (Get-Content $anywhere_role_certfile -raw) }
        if($anywhere_role_keyfile){ $anywhere_role_privkey = (Get-Content $anywhere_role_keyfile -raw) }

        $body.add('is_role_anywhere',[bool]$true)
        $body.add('iam_role_anywhere',@{})
        $body.iam_role_anywhere.add('anywhere_role_arn',$anywhere_role_arn)
        $body.iam_role_anywhere.add('certificate',$anywhere_role_cert)
        $body.iam_role_anywhere.add('private_key',$anywhere_role_privkey)
        $body.iam_role_anywhere.add('profile_arn',$anywhere_profile_arn)
        $body.iam_role_anywhere.add('trust_anchor_arn',$anywhere_trust_anchor_arn)
    }
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


#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections/{id}"
#"#/v1/connectionmgmt/services/aws/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager AWS Connection
    .DESCRIPTION
        Retriving the full list of AWS Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the AWS connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMAWSConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMAWSConnection -name "My AWS Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMAWSConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMAWSConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on AWS Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMAWSConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMAWSConnections -name $name).resources[0].id 
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

#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections/{id}"
#"#/v1/connectionmgmt/services/aws/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager AWS Connection 
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager AWS connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing AWS connection.
    .PARAMETER access_key_id
        (Optional) Client ID of the AWS User
    .PARAMETER secret_access_key
        (Optional) Client secret associated with the access key ID of the AWS user.
    .PARAMETER assume_role_arn
        (Optional) AWS IAM Role ARN
    .PARAMETER assume_role_external_id
        (Optional)Specify AWS Role external ID.
    .PARAMETER aws_region
        (Optional)AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given. Default values are:

            for aws, default region will be "us-east-1"
            for aws-us-gov, default region will be "us-gov-east-1"
            for aws-cn, default region will be "cn-north-1"
    .PARAMETER aws_sts_regional_endpoints
        (Optional)By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are:

            legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com
            regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region.

            To know more about AWS STS please go through the following link https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
    .PARAMETER cloud_name
        (Optional)Name of the cloud. Options: aws (default), aws-us-goc, or aws-cn
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER anywhere_role_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Role ARN.
    .PARAMETER anywhere_role_cert
        (Required if using IAM Role Anywhere) Upload the PEM-formatted certificate text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER anywhere_role_certfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM certificate for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_role_privkey
        (Required if using IAM Role Anywhere) Upload the PEM-formatted private key text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted private key then pass the variable to the command.
    .PARAMETER anywhere_role_keyfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM private key for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_profile_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Profile ARN.
    .PARAMETER anywhere_trust_anchor_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Trust Anchor ARN.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        Existing meta data can be changed but no keys can be deleted.
        e.g. -metadata "red:stop,green:go,blue:ocean" {

        For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
        PS> Update-CMAWSConnections -name MyAWSConnection -access_key_id <NewAccessKey> -secret_access_key <NewSecret>
        Updates the connection name "MyAWSConnection" with a new access/secret keypair.
    .EXAMPLE
        PS> Update-CMAWSConnections -name MyAWSConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMAWSConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $access_key_id, 
        [Parameter()] [string] $secret_access_key, 
        [Parameter()] [string] $assume_role_arn, 
        [Parameter()] [string] $assume_role_external_id, 
        [Parameter()] [ValidateSet(
            'us-east-2','us-east-1','us-west-1','us-west-2',
            'af-south-1',
            'ap-east-1','ap-south-2','ap-southeast-3','ap-southeast-4','ap-south-1','ap-northeast-3','ap-northeast-2','ap-southeast-1','ap-southeast-2','ap-northeast-1',
            'ca-central-1',
            'eu-central-1','eu-west-1','eu-west-2','eu-south-1','eu-west-3','eu-south-2','eu-north-1','eu-central-2',
            'il-central-1',
            'me-south-1','me-central-1',
            'sa-east-1',
            'us-gov-east-1','us-gov-west-1'
        )] [string] $aws_region, 
        [Parameter()] [string] $aws_sts_regional_endpoints, 
        [Parameter()] [ValidateSet('aws','aws-us-goc','aws-cn')] [string] $cloud_name, 
        [Parameter()] [string] $anywhere_role_arn, 
        [Parameter()] [string] $anywhere_role_cert, 
        [Parameter()] [string] $anywhere_role_certfile, 
        [Parameter()] [string] $anywhere_role_privkey, 
        [Parameter()] [string] $anywhere_role_keyfile, 
        [Parameter()] [string] $anywhere_profile_arn, 
        [Parameter()] [string] $anywhere_trust_anchor_arn,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on AWS Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMAWSConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMAWSConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Parameters
    $body = [ordered] @{}

    if($access_key_id){ $body.add('access_key_id', $access_key_id)}
    if($secret_access_key){ $body.add('secret_access_key', $secret_access_key)}
    if($assume_role_arn){ $body.add('assume_role_arn', $assume_role_arn)}
    if($assume_role_external_id){ $body.add('assume_role_external_id', $assume_role_external_id)}
    if($aws_region){ $body.add('aws_region', $aws_region)}
    if($aws_sts_regional_endpoints){ $body.add('aws_sts_regional_endpoints', $aws_sts_regional_endpoints)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($description){ $body.add('description', $description)}
    if((Find-CMAWSConnections -name $name).resources[0].is_role_anywhere -eq $false){
        if($anywhere_role_arn -or $anywhere_profile_arn -or $anywhere_trust_anchor_arn){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }elseif($anywhere_role_cert -or $anywhere_role_certfile){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }elseif($anywhere_role_privkey -or $anywhere_role_keyfile){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }
    }else{
        if($anywhere_role_certfile){ $anywhere_role_cert = (Get-Content $anywhere_role_certfile -raw) }
        if($anywhere_role_keyfile){ $anywhere_role_privkey = (Get-Content $anywhere_role_keyfile -raw) }
        
        if($anywhere_role_arn -or $anywhere_profile_arn -or $anywhere_trust_anchor_arn -or $anywhere_role_cert -or $anywhere_role_privkey){
            $body.add('iam_role_anywhere',@{})
            if($anywhere_role_arn){ $body.iam_role_anywhere.add('anywhere_role_arn',$anywhere_role_arn) }
            if($anywhere_role_cert){ $body.iam_role_anywhere.add('certificate',$anywhere_role_cert) }
            if($anywhere_role_privkey){ $body.iam_role_anywhere.add('private_key',$anywhere_role_privkey) }
            if($anywhere_profile_arn){ $body.iam_role_anywhere.add('profile_arn',$anywhere_profile_arn) }
            if($anywhere_trust_anchor_arn){ $body.iam_role_anywhere.add('trust_anchor_arn',$anywhere_trust_anchor_arn) }
        }
    }
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


#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections/{id}"
#"#/v1/connectionmgmt/services/aws/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager AWS Connection
    .DESCRIPTION
        Delete a CipherTrust Manager AWS Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the AWS connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMAWSConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMAWSConnection -name "My AWS Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMAWSConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMAWSConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter()] [switch] $force
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on AWS Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMAWSConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMAWSConnections -name $name).resources[0].id 
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
    
#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connections/{id}"
#"#/v1/connectionmgmt/services/aws/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the AWS cloud. If no connection parameters are provided in request, the existing parameters will be used. This does not create a persistent connection.
    .PARAMETER name
        Name of the existing CipherTrust Manager AWS connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing AWS connection.
    .PARAMETER access_key_id
        (Optional) Client ID of the AWS User
    .PARAMETER secret_access_key
        (Optional) Client secret associated with the access key ID of the AWS user.
    .PARAMETER assume_role_arn
        (Optional) AWS IAM Role ARN
    .PARAMETER assume_role_external_id
        (Optional)Specify AWS Role external ID.
    .PARAMETER aws_region
        (Optional)AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given. Default values are:

            for aws, default region will be "us-east-1"
            for aws-us-gov, default region will be "us-gov-east-1"
            for aws-cn, default region will be "cn-north-1"
    .PARAMETER aws_sts_regional_endpoints
        (Optional)By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are:

            legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com
            regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region.

            To know more about AWS STS please go through the following link https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
    .PARAMETER cloud_name
        (Optional)Name of the cloud. Options: aws (default), aws-us-goc, or aws-cn
    .PARAMETER is_role_anywhere
        (Optional) Use this switch to create connections of type AWS IAM Anywhere with temporary credentials.
    .PARAMETER anywhere_role_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Role ARN.
    .PARAMETER anywhere_role_cert
        (Required if using IAM Role Anywhere) Upload the PEM-formatted certificate text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER anywhere_role_certfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM certificate for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_role_privkey
        (Required if using IAM Role Anywhere) Upload the PEM-formatted private key text for AWS IAM Anywhere Cloud connections.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted private key then pass the variable to the command.
    .PARAMETER anywhere_role_keyfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM private key for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_profile_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Profile ARN.
    .PARAMETER anywhere_trust_anchor_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Trust Anchor ARN.
    .LINK
    https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
    #>
function Test-CMAWSConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter()] [string] $access_key_id, 
        [Parameter()] [string] $secret_access_key, 
        [Parameter()] [string] $assume_role_arn, 
        [Parameter()] [string] $assume_role_external_id, 
        [Parameter()] [ValidateSet(
            'us-east-2','us-east-1','us-west-1','us-west-2',
            'af-south-1',
            'ap-east-1','ap-south-2','ap-southeast-3','ap-southeast-4','ap-south-1','ap-northeast-3','ap-northeast-2','ap-southeast-1','ap-southeast-2','ap-northeast-1',
            'ca-central-1',
            'eu-central-1','eu-west-1','eu-west-2','eu-south-1','eu-west-3','eu-south-2','eu-north-1','eu-central-2',
            'il-central-1',
            'me-south-1','me-central-1',
            'sa-east-1',
            'us-gov-east-1','us-gov-west-1'
        )] [string] $aws_region, 
        [Parameter()] [string] $aws_sts_regional_endpoints, 
        [Parameter()] [ValidateSet('aws','aws-us-goc','aws-cn')] [string] $cloud_name, 
        [Parameter()] [switch] $is_role_anywhere, 
        [Parameter()] [string] $anywhere_role_arn, 
        [Parameter()] [string] $anywhere_role_cert, 
        [Parameter()] [string] $anywhere_role_certfile, 
        [Parameter()] [string] $anywhere_role_privkey, 
        [Parameter()] [string] $anywhere_role_keyfile, 
        [Parameter()] [string] $anywhere_profile_arn, 
        [Parameter()] [string] $anywhere_trust_anchor_arn
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on AWS Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMAWSConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMAWSConnections -name $name).resources[0].id 
        $endpoint += "/" + $id + "/test"
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    # Parameters
    $body = [ordered] @{}

    if($access_key_id){ $body.add('access_key_id', $access_key_id)}
    if($secret_access_key){ $body.add('secret_access_key', $secret_access_key)}
    if($assume_role_arn){ $body.add('assume_role_arn', $assume_role_arn)}
    if($assume_role_external_id){ $body.add('assume_role_external_id', $assume_role_external_id)}
    if($aws_region){ $body.add('aws_region', $aws_region)}
    if($aws_sts_regional_endpoints){ $body.add('aws_sts_regional_endpoints', $aws_sts_regional_endpoints)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if((Find-CMAWSConnections -name $name).resources[0].is_role_anywhere -eq $false){
        if($anywhere_role_arn -or $anywhere_profile_arn -or $anywhere_trust_anchor_arn){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }elseif($anywhere_role_cert -or $anywhere_role_certfile){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }elseif($anywhere_role_privkey -or $anywhere_role_keyfile){
            return "Connection not using IAM Role Anywhere. A new connection is required. Please try again."
        }
    }else{
        if($anywhere_role_certfile){ $anywhere_role_cert = (Get-Content $anywhere_role_certfile -raw) }
        if($anywhere_role_keyfile){ $anywhere_role_privkey = (Get-Content $anywhere_role_keyfile -raw) }
        
        if($anywhere_role_arn -or $anywhere_profile_arn -or $anywhere_trust_anchor_arn -or $anywhere_role_cert -or $anywhere_role_privkey){
            $body.add('iam_role_anywhere',@{})
            if($anywhere_role_arn){ $body.iam_role_anywhere.add('anywhere_role_arn',$anywhere_role_arn) }
            if($anywhere_role_cert){ $body.iam_role_anywhere.add('certificate',$anywhere_role_cert) }
            if($anywhere_role_privkey){ $body.iam_role_anywhere.add('private_key',$anywhere_role_privkey) }
            if($anywhere_profile_arn){ $body.iam_role_anywhere.add('profile_arn',$anywhere_profile_arn) }
            if($anywhere_trust_anchor_arn){ $body.iam_role_anywhere.add('trust_anchor_arn',$anywhere_trust_anchor_arn) }
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


#Connection Manager - AWS Connections
#"#/v1/connectionmgmt/services/aws/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the AWS account. This does not create a persistent connection.
    .PARAMETER access_key_id
        (Optional) Client ID of the AWS User
    .PARAMETER secret_access_key
        (Optional) Client secret associated with the access key ID of the AWS user.
    .PARAMETER assume_role_arn
        (Optional) AWS IAM Role ARN
    .PARAMETER assume_role_external_id
        (Optional)Specify AWS Role external ID.
    .PARAMETER aws_region
        (Optional)AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given. Default values are:

            for aws, default region will be "us-east-1"
            for aws-us-gov, default region will be "us-gov-east-1"
            for aws-cn, default region will be "cn-north-1"
    .PARAMETER aws_sts_regional_endpoints
        (Optional)By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are:

            legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com
            regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region.

            To know more about AWS STS please go through the following link https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
    .PARAMETER cloud_name
        (Optional)Name of the cloud. Options: aws (default), aws-us-goc, or aws-cn
    .PARAMETER is_role_anywhere
        (Optional) Use this switch to create connections of type AWS IAM Anywhere with temporary credentials.
    .PARAMETER anywhere_role_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Role ARN.
    .PARAMETER anywhere_role_cert
        (Required if using IAM Role Anywhere) Upload the PEM-formatted certificate text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER anywhere_role_certfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM certificate for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_role_privkey
        (Required if using IAM Role Anywhere) Upload the PEM-formatted private key text for AWS IAM Anywhere Cloud connections. 
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted private key then pass the variable to the command.
    .PARAMETER anywhere_role_keyfile
        (Required if using IAM Role Anywhere) Specify the filename for a PEM private key for AWS IAM Anywhere Cloud connections.
    .PARAMETER anywhere_profile_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Profile ARN.
    .PARAMETER anywhere_trust_anchor_arn
        (Required if using IAM Role Anywhere) Specify AWS IAM Anywhere Trust Anchor ARN.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMAWSConnParameters{
    param(
        [Parameter()] [string] $access_key_id, 
        [Parameter()] [string] $secret_access_key, 
        [Parameter()] [string] $assume_role_arn, 
        [Parameter()] [string] $assume_role_external_id, 
        [Parameter()][ValidateSet(
            'us-east-2','us-east-1','us-west-1','us-west-2',
            'af-south-1',
            'ap-east-1','ap-south-2','ap-southeast-3','ap-southeast-4','ap-south-1','ap-northeast-3','ap-northeast-2','ap-southeast-1','ap-southeast-2','ap-northeast-1',
            'ca-central-1',
            'eu-central-1','eu-west-1','eu-west-2','eu-south-1','eu-west-3','eu-south-2','eu-north-1','eu-central-2',
            'il-central-1',
            'me-south-1','me-central-1',
            'sa-east-1',
            'us-gov-east-1','us-gov-west-1'
        )] [string] $aws_region, 
        [Parameter()] [string] $aws_sts_regional_endpoints, 
        [Parameter()] [ValidateSet('aws','aws-us-goc','aws-cn')] [string] $cloud_name, 
        [Parameter()] [switch] $is_role_anywhere, 
        [Parameter()] [string] $anywhere_role_arn, 
        [Parameter()] [string] $anywhere_role_cert, 
        [Parameter()] [string] $anywhere_role_certfile, 
        [Parameter()] [string] $anywhere_role_privkey, 
        [Parameter()] [string] $anywhere_role_keyfile, 
        [Parameter()] [string] $anywhere_profile_arn, 
        [Parameter()] [string] $anywhere_trust_anchor_arn    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing AWS Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Parameters
    $body = [ordered] @{}

    if($access_key_id){ $body.add('access_key_id', $access_key_id)}
    if($secret_access_key){ $body.add('secret_access_key', $secret_access_key)}
    if($assume_role_arn){ $body.add('assume_role_arn', $assume_role_arn)}
    if($assume_role_external_id){ $body.add('assume_role_external_id', $assume_role_external_id)}
    if($aws_region){ $body.add('aws_region', $aws_region)}
    if($aws_sts_regional_endpoints){ $body.add('aws_sts_regional_endpoints', $aws_sts_regional_endpoints)}
    if($cloud_name){ $body.add('cloud_name', $cloud_name)}
    if($is_role_anywhere){
        if(!$anywhere_role_arn -or !$anywhere_profile_arn -or !$anywhere_trust_anchor_arn){
            return "Missing IAM Anywhere Parameters. Please try again."
        }elseif(!$anywhere_role_cert -and !$anywhere_role_certfile){
            return "Missing IAM Anywhere Certificate. Please try again."
        }elseif(!$anywhere_role_privkey -and !$anywhere_role_keyfile){
            return "Missing IAM Anywhere Private Key. Please try again."
        }
        if($anywhere_role_certfile){ $anywhere_role_cert = (Get-Content $anywhere_role_certfile -raw) }
        if($anywhere_role_keyfile){ $anywhere_role_privkey = (Get-Content $anywhere_role_keyfile -raw) }

        $body.add('iam_role_anywhere',@{})
        $body.iam_role_anywhere.add('anywhere_role_arn',$anywhere_role_arn)
        $body.iam_role_anywhere.add('certificate',$anywhere_role_cert)
        $body.iam_role_anywhere.add('private_key',$anywhere_role_privkey)
        $body.iam_role_anywhere.add('profile_arn',$anywhere_profile_arn)
        $body.iam_role_anywhere.add('trust_anchor_arn',$anywhere_trust_anchor_arn)
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

####
# Export Module Members
####
#Connection Manager - AWS
#/v1/connectionmgmt/services/aws/connections"

Export-ModuleMember -Function Find-CMAWSConnections #/v1/connectionmgmt/services/aws/connections - get"
Export-ModuleMember -Function New-CMAWSConnection #/v1/connectionmgmt/services/aws/connections - post"

#Connection Manager - AWS
#/v1/connectionmgmt/services/aws/connections/{id}"
Export-ModuleMember -Function Get-CMAWSConnection #/v1/connectionmgmt/services/aws/connections/{id} - get"
Export-ModuleMember -Function Update-CMAWSConnection #/v1/connectionmgmt/services/aws/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMAWSConnection #/v1/connectionmgmt/services/aws/connections/{id} - delete"

#Connection Manager - AWS
#/v1/connectionmgmt/services/aws/connections/{id}/test"
Export-ModuleMember -Function Test-CMAWSConnection #/v1/connectionmgmt/services/aws/connections/{id}/test - post"

#Connection Manager - AWS
#/v1/connectionmgmt/services/aws/connection-testt"
Export-ModuleMember -Function Test-CMAWSConnParameters #/v1/connectionmgmt/services/aws/connection-test - post"
