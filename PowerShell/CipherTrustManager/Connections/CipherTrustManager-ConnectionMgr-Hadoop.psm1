#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Hadoop.psm1                                                      #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/hadoop/connections"
$target_uri_test = "/connectionmgmt/services/hadoop/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Hadoop Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Hadoop Module"
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


#This project mirrors the "Connection Manager - Hadoop Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Hadoop Connections)

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections"
#"#/v1/connectionmgmt/services/hadoop/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Hadoop Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Hadoop Connections).   
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
        PS> Find-CMHadoopConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMHadoopConnections {
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
    
    Write-Debug "Getting a List of all Hadoop Connections in CM"
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
    Write-Debug "List of all CM Connections to Hadoop Cluster with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections"
#"#/v1/connectionmgmt/services/hadoop/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager Hadoop Connection. 
    .DESCRIPTION
        Creates a new Hadoop connection. 
    .PARAMETER name
        Unique connection name.
    .PARAMETER nodename
        Hostname of the FIRST Hadoop server in the Hadoop Cluster being conencted to. Use Add-CMHadoopConnectionNode for EACH additional node.
    .PARAMETER port
        (Optional) Port for Hadoop Server. Possible values 1-65535..
    .PARAMETER protocol
        (Optional) http or https protocol to be used for communication with the Hadoop node (https required for hadoop-knox)
    .PARAMETER path
        (Optional) path for Hadoop Server
    .PARAMETER hadoopcertificate
        Enter the PEM-formatted certificate text for the Hadoop Server being connected to.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER hadoopcertfile
        Specify a filename for the certificate.
    .PARAMETER knoxuser
        The Hadoop Knox username. 
    .PARAMETER knoxpass
        The Hadoop Knox passsword.
    .PARAMETER knoxsecurecredentials
        Supply a PSCredential object with the Knox username and password
    .PARAMETER topology
        (Optional) Topology deployment of the Knox gateway.
    .PARAMETER products
        (Optional) Array of the CipherTrust products associated with the connection. Valid values are:
            "ddc" for:
                GCP
                Hadoop connections
            "cte" for:
                Hadoop connections
                SMB
                OIDC
                LDAP connections
            "data discovery" for Hadoop connections. - This is the default selection.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMHadoopConnection -name "MyHadoopCluster" -description "This is an Powershell created Hadoop Connection" -nodename "node1" -hadoopcertificate "<PEM-formatted-certificate>" -knoxuser knox -knoxpass Thales123! -metadata "red:stop,green:go"
    .EXAMPLE
        PS> New-CMHadoopConnection -name "MyHadoopCluster" -description "This is an Powershell created Hadoop Connection" -nodename "node1" -hadoopcertfile .\hadoopnode1cert.pem -knoxuser knox -knoxpass Thales123! -metadata "red:stop,green:go"
    .EXAMPLE
        PS> New-CMHadoopConnection -name "MyHadoopCluster" -nodename "node1" -hadoopcertfile .\knoxnode1cert.pem -knoxsecurecredentials [PSCredential]$knoxcreds
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMHadoopConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $nodename, 
        [Parameter()] [int] $port, 
        [Parameter()] [ValidateSet("https","http")] [string] $protocol = "https", 
        [Parameter()] [string] $path, 
        [Parameter()] [string] $hadoopcertificate, 
        [Parameter()] [string] $hadoopcertfile, 
        [Parameter()] [string] $knoxuser, 
        [Parameter()] [string] $knoxpass,
        [Parameter()] [ValidateSet("ddc","cte","data discovery")] [string[]] $products="data discovery",
        [Parameter()] [pscredential] $knoxsecurecredentials, 
        [Parameter()] [string] $topology = "default", 
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Hadoop Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if (($protocol -eq "https") -and (!$hadoopcertificate -and !$hadoopcertfile)) { return "Missing Hadoop Node Certificate. Please try again."}
    if ((!$knoxuser -or !$knoxpass) -and !$knoxsecurecredentials) { return "Missing Hadoop Credentials. Please try again."}

    # Mandatory Parameters
    $body = [ordered] @{
        "name"      = $name
        "products"  = @( $products )
        "service"   = "hadoop-knox"
        "nodes"     = @()
    }
    
    if($knoxsecurecredentials){
        Write-Debug "What is my credential user? $($knoxsecurecredentials.username)" 
        Write-debug "What is my credential password? $($knoxsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $knoxsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($knoxsecurecredentials.password)))
    }else{
        if($knoxpass){ $body.add('password', $knoxpass)}
        if($knoxuser){ $body.add('username', $knoxuser)}
    }

    #Build Node dictionary object
    $node = [ordered] @{}
        $node.hostname = $nodename
        $node.port = $port
        $node.protocol = $protocol
        if($hadoopcertfile){ $hadoopcertificate = (Get-Content $hadoopcertfile -raw) }
            if($hadoopcertificate){ $node.server_certificate = $hadoopcertificate }
        if($path){ $node.path = $path }
        $body.nodes += $node

    #Optional Parameters        
    if($topology) { $body.add('topology', $topology)}
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


#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}"
#"#/v1/connectionmgmt/services/hadoop/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Retriving the full list of Hadoop Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Hadoop connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMHadoopConnection -name "My Hadoop Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMHadoopConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMHadoopConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Hadoop Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMHadoopConnections -name $name).resources[0].id 
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

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}"
#"#/v1/connectionmgmt/services/hadoop/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager Hadoop Connection. This is ONLY used to update the Hadoop Credentials. Use "Update-CMHadoopConnectionNode -id {id} -nodeid {node_id}" to update node information.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager Hadoop connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Hadoop connection.
    .PARAMETER knoxuser
        The Hadoop Knox username. 
    .PARAMETER knoxpass
        The Hadoop Knox passsword.
    .PARAMETER knoxsecurecredentials
        Supply a PSCredential object with the Knox username and password
    .PARAMETER topology
        (Optional) Topology deployment of the Knox gateway.
    .PARAMETER products
        (Optional) Array of the CipherTrust products associated with the connection. Valid values are:
            "ddc" for:
                GCP
                Hadoop connections
            "cte" for:
                Hadoop connections
                SMB
                OIDC
                LDAP connections
            "data discovery" for Hadoop connections. - This is the default selection.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> Update-CMHadoopConnection -name MyHadoopConnection -knoxuser <newuser> -knoxpass <newpass>
    .EXAMPLE
        PS> Update-CMHadoopConnection -name MyHadoopConnection -knoxsecurecredentials $mycreds
    .EXAMPLE
        PS> Update-CMHadoopConnections -name MyHadoopConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMHadoopConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $knoxuser, 
        [Parameter()] [string] $knoxpass,
        [Parameter()] [ValidateSet("ddc","cte","data discovery")] [string[]] $products,
        [Parameter()] [pscredential] $knoxsecurecredentials, 
        [Parameter()] [string] $topology = "default", 
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on Hadoop Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMHadoopConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Optional Parameters
    $body = [ordered] @{}
    
    if($knoxsecurecredentials){
        Write-Debug "What is my credential user? $($knoxsecurecredentials.username)" 
        Write-debug "What is my credential password? $($knoxsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $knoxsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($knoxsecurecredentials.password)))
    }else{
        if($knoxpass){ $body.add('password', $knoxpass)}
        if($knoxuser){ $body.add('username', $knoxuser)}
    }

    if($topology) { $body.add('topology', $topology)}
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


#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}"
#"#/v1/connectionmgmt/services/hadoop/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Hadoop Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Hadoop connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMHadoopConnection -name "My Hadoop Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMHadoopConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMHadoopConnection{
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

    Write-Debug "Preparing to remove Hadoop Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $id = (Find-CMHadoopConnections -name $name).resources[0].id 
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
    
#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the Hadoop Cluster. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
        Name of the existing CipherTrust Manager Hadoop connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Hadoop connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMHadoopConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Hadoop Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        $id = (Find-CMHadoopConnections -name $name).resources[0].id 
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


#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the Hadoop Cluster. This does not create a persistent connection.
    .PARAMETER nodename
        Hostname of the Hadoop Node in the cluster being tested.
    .PARAMETER hadoopcertificate
        Enter the PEM-formatted certificate text for the Hadoop being connected to.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER hadoopcertfile
        Specify a filename for the Hadoop certificate.
    .PARAMETER knoxuser
        Username for accessing Knox server. 
    .PARAMETER knoxpass
        Password of Knox server
    .PARAMETER knoxsecurecredentials
        Supply a PSCredential object with the Knox username and password
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMHadoopConnParameters{
    param(
        [Parameter()] [string] $nodename, 
        [Parameter()] [string] $hadoopcertificate, 
        [Parameter()] [string] $hadoopcertfile, 
        [Parameter()] [string] $knoxuser, 
        [Parameter()] [string] $knoxpass, 
        [Parameter()] [pscredential] $knoxsecurecredentials
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Hadoop Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    if (($protocol -eq "https") -and (!$hadoopcertificate -and !$hadoopcertfile)) { return "Missing Hadoop Node Certificate. Please try again."}
    if ((!$knoxuser -or !$knoxpass) -and !$knoxsecurecredentials) { return "Missing Hadoop Credentials. Please try again."}

    # Mandatory Parameters
    $body = [ordered] @{
        "nodes"     = @()
        "service"   = "hadoop-knox"
    }
    
    if($knoxsecurecredentials){
        Write-Debug "What is my credential user? $($knoxsecurecredentials.username)" 
        Write-debug "What is my credential password? $($knoxsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('username', $knoxsecurecredentials.username)
        $body.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($knoxsecurecredentials.password)))
    }else{
        if($knoxpass){ $body.add('password', $knoxpass)}
        if($knoxuser){ $body.add('username', $knoxuser)}
    }

    #Build Node dictionary object
    $node = [ordered] @{}
        $node.hostname = $nodename
        $node.port = $port
        $node.protocol = $protocol
        if($hadoopcertfile){ $hadoopcertificate = (Get-Content $hadoopcertfile -raw) }
            if($hadoopcertificate){ $node.server_certificate = $hadoopcertificate }
        if($path){ $node.path = $path }
        $body.nodes += $node

    #Optional Parameters        
    if($topology) { $body.add('topology', $topology)}
        
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

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager Hadoop Connection
    .PARAMETER name
        The complete name of the Hadoop connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMHadoopConnectionNodes -name "My Hadoop Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMHadoopConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
    function Find-CMHadoopConnectionNodes{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Getting details on Hadoop Connection Nodes"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes"
        }elseif($name){ 
            $id = (Find-CMHadoopConnections -name $name).resources[0].id 
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

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - post"

<#
    .SYNOPSIS
        Add a nodes to a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Add a nodes to a CipherTrust Manager Hadoop Connection
    .PARAMETER name
        The complete name of the Hadoop connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .PARAMETER nodename
        Hostname of the Hadoop node in the cluster being added.
    .PARAMETER hadoopcertificate
        Enter the PEM-formatted certificate text for the Hadoop being connected to.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER hadoopcertfile
        Specify a filename for the Hadoop certificate.
    .PARAMETER port
        (Optional) Port for Hadoop Server. Possible values 1-65535..
    .PARAMETER protocol
        (Optional) http or https protocol to be used for communication with the Hadoop node (https required for hadoop-knox)
    .PARAMETER path
        (Optional) path for Hadoop Server
    .EXAMPLE
        PS> Add-CMHadoopConnectionNode -name "My Hadoop Connection" -nodename "node2" -hadoopcertificate <PEM-formatted-certificate-text>
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Add-CMHadoopConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodename "node2" -hadoopcertfile .\hadoop2_cert.pem
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
    function Add-CMHadoopConnectionNode{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter()] [string] $nodename, 
            [Parameter()] [int] $port, 
            [Parameter()] [ValidateSet("https","http")] [string] $protocol = "https", 
            [Parameter()] [string] $path, 
            [Parameter()] [string] $hadoopcertificate, 
            [Parameter()] [string] $hadoopcertfile
        
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Adding new Hadoop Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes"
        }elseif($name){ 
            $id = (Find-CMHadoopConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes"
        }else{
            return "Missing Connection Identifier."
        }

        Write-Debug "Endpoint w Target: $($endpoint)"
        
        if(($protocol -eq "https") -and (!$hadoopcertificate -and !$hadoopcertfile)){ return "Missing Node Certificate."}
        if(!$nodename -or !$protocol -or !$port){ return "Missing Node Parameters."}

        # Mandatory Parameters
        $body = [ordered] @{}

        # Add Node Details to body
        if($nodename){ $body.add("hostname",$nodename) }
        if($port){ $body.add("port", $port) }
        if($protocol){ $body.add("protocol", $protocol) }
        if($path){ $node.path = $path }
        if($hadoopcertfile){ $hadoopcertificate = (Get-Content $hadoopcertfile -raw) }
            if($hadoopcertificate){ $body.add("server_certificate", $hadoopcertificate) }
            
        $jsonBody = $body | ConvertTo-JSON 

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

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get detail on an individual node of a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Get detail on an individual node of a CipherTrust Manager Hadoop Connection
    .PARAMETER name
        The complete name of the Hadoop connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
        The Node "id" value for the connection.
        Use the Find-CMHadoopConnectionNodes cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMHadoopConnectionNode -name "My Hadoop Connection" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMHadoopConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
    function Get-CMHadoopConnectionNodes{
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
    
        Write-Debug "Getting details on Hadoop Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }elseif($name){ 
            $id = (Find-CMHadoopConnections -name $name).resources[0].id 
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


#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes/{nodeid}"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes/{nodeid} - delete"

<#
    .SYNOPSIS
        Delete a node from a CipherTrust Manager Hadoop Connection.
    .DESCRIPTION
        Delete a node from a CipherTrust Manager Hadoop Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Hadoop connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
        Node ID of the node in the Hadoop Cluster being removed.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMHadoopConnection -name "My Hadoop Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMHadoopConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
    function Remove-CMHadoopConnectionNode{
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
    
        Write-Debug "Preparing to remove Hadoop Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid      
        }elseif($name){ 
            $id = (Find-CMHadoopConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }else{
            return "Missing Node Identifier."
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
        Write-Debug "Node deleted"
        Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    
        return "Node Deleted."
    }    

#Connection Manager - Hadoop Connections
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - post"

<#
    .SYNOPSIS
        Update an existing node of a CipherTrust Manager Hadoop Connection
    .DESCRIPTION
        Update an existing node of a CipherTrust Manager Hadoop Connection
    .PARAMETER name
        The complete name of the Hadoop connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMHadoopConnections cmdlet to find the appropriate id value.
    .PARAMETER nodeid
        Node ID of the node in the Hadoop Cluster being updated.
    .PARAMETER nodename
        Hostname of the Hadoop node in the cluster being added.
    .PARAMETER hadoopcertificate
        Enter the PEM-formatted certificate text for the Hadoop being connected to.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER hadoopcertfile
        Specify a filename for the Hadoop certificate.
    .PARAMETER port
        (Optional) Port for Hadoop Server. Possible values 1-65535..
    .PARAMETER protocol
        (Optional) http or https protocol to be used for communication with the Hadoop node (https required for hadoop-knox)
    .PARAMETER path
        (Optional) path for Hadoop Server
    .EXAMPLE
        PS> Update-CMHadoopConnectionNode -name "My Hadoop Connection" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" -hadoopcertificate <PEM-formatted-certificate-text>
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Update-CMHadoopConnectionNode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -nodeid "7c585e46-cc4b-4b6b-b456-e74aeb5d5aab" -hadoopcertfile .\node2_cert.pem
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
    function Update-CMHadoopConnectionNode{
        param(
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $name, 
            [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
            [string] $id,
            [Parameter()] [string] $nodeid, 
            [Parameter()] [string] $nodename, 
            [Parameter()] [int] $port, 
            [Parameter()] [ValidateSet("https","http")] [string] $protocol = "https", 
            [Parameter()] [string] $path, 
            [Parameter()] [string] $hadoopcertificate, 
            [Parameter()] [string] $hadoopcertfile
        )
    
        Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
        Write-Debug "Updating a Hadoop Connection Node"
        $endpoint = $CM_Session.REST_URL + $target_uri
        Write-Debug "Endpoint: $($endpoint)"
    
        if($id){
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }elseif($name){ 
            $id = (Find-CMHadoopConnections -name $name).resources[0].id 
            $endpoint += "/" + $id + "/nodes/" + $nodeid
        }else{
            return "Missing Connection Identifier."
        }

        Write-Debug "Endpoint w Target: $($endpoint)"

        # Optional Parameters
        $body = [ordered] @{}
        
        #Node details
        if($nodename){ $body.add("hostname",$nodename) }
        if($port){ $body.add("port", $port) }
        if($protocol){ $body.add("protocol", $protocol) }
        if($path){ $node.path = $path }
        if($hadoopcertfile){ $hadoopcertificate = (Get-Content $hadoopcertfile -raw) }
            if($hadoopcertificate){ $body.add("server_certificate", $hadoopcertificate) }
            
        $jsonBody = $body | ConvertTo-JSON 

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
#Connection Manager - Hadoop
#/v1/connectionmgmt/services/hadoop/connections"

Export-ModuleMember -Function Find-CMHadoopConnections #/v1/connectionmgmt/services/hadoop/connections - get"
Export-ModuleMember -Function New-CMHadoopConnection #/v1/connectionmgmt/services/hadoop/connections - post"

#Connection Manager - Hadoop
#/v1/connectionmgmt/services/hadoop/connections/{id}"
Export-ModuleMember -Function Get-CMHadoopConnection #/v1/connectionmgmt/services/hadoop/connections/{id} - get"
Export-ModuleMember -Function Update-CMHadoopConnection #/v1/connectionmgmt/services/hadoop/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMHadoopConnection #/v1/connectionmgmt/services/hadoop/connections/{id} - delete"

#Connection Manager - Hadoop
#/v1/connectionmgmt/services/hadoop/connections/{id}/test"
Export-ModuleMember -Function Test-CMHadoopConnection #/v1/connectionmgmt/services/hadoop/connections/{id}/test - post"

#Connection Manager - Hadoop
#/v1/connectionmgmt/services/hadoop/connection-test"
Export-ModuleMember -Function Test-CMHadoopConnParameters #/v1/connectionmgmt/services/hadoop/connection-test - post"

#Connection Manager - Hadoop
#/v1/connectionmgmt/services/hadoop/connections/{id}/nodes"
Export-ModuleMember -Function Find-CMHadoopConnectionNodes #/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - get"
Export-ModuleMember -Function Add-CMHadoopConnectionNode #/v1/connectionmgmt/services/hadoop/connections/{id}/nodes - post"
Export-ModuleMember -Function Get-CMHadoopConnectionNode #/v1/connectionmgmt/services/hadoop/connections/{id}/nodes/{node_id} - get"
Export-ModuleMember -Function Update-CMHadoopConnectionNode #/v1/connectionmgmt/services/hadoop/connections/{id}/nodes/{node_id} - patch"
Export-ModuleMember -Function Remove-CMHadoopConnectionNode #/v1/connectionmgmt/services/hadoop/connections/{id}/nodes/{node_id} - delete"
