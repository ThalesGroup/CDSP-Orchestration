#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-LunaHSMConnection.psm1                                           #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2024 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

###
# ENUM
###
#Supported Algorithms
Add-Type -TypeDefinition @"
   public enum transportType {
    tcp,
    tls
}
"@

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/luna-network/connections"
$target_uri_test = "/connectionmgmt/services/luna-network/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Luna HSM Connections Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Luna HSM Connections Module"
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


#This project mirrors the "Connection Manager - Luna HSM Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Luna HSM Connections)

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections"
#"#/v1/connectionmgmt/services/luna-network/connections - get"

<#
    .SYNOPSIS
        Returns a list of Luna Network HSM connections.
    .DESCRIPTION
        Returns a list of Luna Network HSM connections to partitions. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Luna HSM Connections
        #/v1/connectionmgmt/services/luna-network/connections-get).   
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
            - cckm
            - hsm_anchored_domain
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
    .PARAMETER operation_status
        Filter the result based on operational sttaus result..
    .EXAMPLE
        PS> Find-CMLunaHSMConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMLunaHSMConnections {
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
        [Parameter()] [ValidateSet('cckm','hsm_anchored_domain')] 
            [string[]] $products,
        [Parameter()] [string] $meta_contains, 
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after,
        [Parameter()] [string] $operation_status
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Luna Network HSM Connections in CM"
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
    if ($operation_status) {
        if ($firstset) {
            $endpoint += "&operation_status=true"
        }
        else {
            $endpoint += "?operation_status=true"
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
    Write-Debug "List of all CM Connections to Luna Network HSMs with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections"
#"#/v1/connectionmgmt/services/luna-network/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager Luna Network HSM Connection to be used in conjustion with a Luna HSM Server. 
    .DESCRIPTION
        Creates a new Luna HSM connection. 
    .PARAMETER name
        Unique connection name.
    .PARAMETER hostname
        IP for Hostname/FQDN of the PRE-EXISTING Luna Network HSM server. 
        To use an HA group enter each HSM Server IP in a comma-separated list. If the partitions in the HA group are in the same HSM server, enter the same IP twice.
    .PARAMETER serial
        Serial Number for the target partition.
        To use an HA group enter each partition serial number in a comma-separated list.
    .PARAMETER label
        Label for the target partition.
        To use an HA group enter each partition label in a comma separated list.
    .PARAMETER copass
        Crypto Officer password for the target partition.
        To use an HA group both partitions must have the same Crypto Officer password.
    .PARAMETER description
        (Optional) Connection description.
    .PARAMETER ha_enabled
        This flag signifies if it is HighAvailability(HA) Group or not. The default is false.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMLunaHSMConnection -name "My Luna HSM Partition 1" -description "CCKM Partition" -hostname 192.168.100.70 -serial "123456" -label "part1" -copass "MyPassword" -metadata "red:stop,green:go"
        Explanation:
        This command will create a new connection called "My Luna HSM Partition 1" with a description of "CCKM Partition". That traget will be a PRE-EXISTING Luna HSM Server at 192.168.100.70.
        The connection will be to a partition with LABEL (not named) "part1" with Serial Number "123456." and a Crypto Officer password of "MyPassword". 
    .EXAMPLE
        PS> New-CMLunaHSMConnection -name "My Luna HSM Connection 1" -description "CCKM HA Group" -hostname 192.168.100.70,192.168.100.71 -serial 12345,98765 -label part1,part2 -copass "MyPassword" -ha_enabled -metadata "red:stop,green:go"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMLunaHSMConnection{
    param(
        [Parameter(Mandatory,HelpMessage="Enter name for Luna HSM Partition Connection.")]
            [string] $name, 
        [Parameter(Mandatory, HelpMessage="Enter Luna HSM Server IP or FQDN as previously defined.")]
            [string[]] $hostname, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Serial Number.")]
            [string[]] $serial, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Label.")]
            [string[]] $label, 
        [Parameter(Mandatory, HelpMessage="Enter Crypto Officer password.")]
            [string] $copass, 
        [Parameter()] [switch] $ha_enabled, 
        [Parameter()] [ValidateSet('cckm','hsm_anchored_domain')] 
            [string[]] $products,
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Luna HSM Partition Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    
    # Mandatory Parameters
    $body= [ordered] @{
        "name" = $name
        "products" = $products
        "password" = $copass
    }

    
    #Partition Parameter Block Creation
    $partitions = @()
    $partition_counter=0
    while($partition_counter -lt $serial.Count){
        $part_params = [ordered] @{}
        $part_params.add('hostname',$hostname[$partition_counter]) 
        $part_params.add('partition_label',$label[$partition_counter]) 
        $part_params.add('serial_number',$serial[$partition_counter])
        $partitions += $part_params
        $partition_counter++
    }

    $body.add('partitions',$partitions)

    # Optional Parameters
    if(!$ha_enabled -and ($serial.count -gt 1)){
        return "Non HA Group can only have one partition in an HSM Connection."
    }elseif($ha_enabled){
        $body.add('is_ha_enabled',[bool]$true)
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


#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}" - get

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Luna HSM Connection
    .DESCRIPTION
        Retriving the full list of Luna HSM Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Luna HSM Connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMLunaHSMConnections -name "My Luna HSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMLunaHSMConnections -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLunaHSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
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

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}" - patch

<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager Luna HSM Connection 
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager Luna HSM Connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Luna HSM Connection.
    .PARAMETER copass
        Update the Crypto Officer Password for the connection.
    .PARAMETER ha_enabled
        Activate/Deactive HA Group Mode on the Connection.
    .PARAMETER products
            - cckm
            - hsm_anchored_domain
    .PARAMETER description
        (Optional) Description about the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        Existing meta data can be changed but no keys can be deleted.
        e.g. -metadata "red:stop,green:go,blue:ocean"

        For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
        PS> Update-CMLunaHSMConnections -name MyLuna HSMConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMLunaHSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory)] [string] $copass, 
        [Parameter(Mandatory)] [switch] $ha_enabled, 
        [Parameter()] [ValidateSet('cckm','hsm_anchored_domain')] 
            [string[]] $products,
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body= [ordered] @{}

    # Optional Parameters
    if($copass){ $body.add('password',$copass)}
    if($ha_enabled){ $body.add('is_ha_enabled',[bool]$true)}
    if($products){ $body.add('products',$products)}
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


#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}" - delete

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Luna HSM Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Luna HSM Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Luna HSM connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMLunaHSMConnection -name "My Luna HSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLunaHSMConnections -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLunaHSMConnection{
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

    Write-Debug "Preparing to remove Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($hostname){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -hostname $hostname).resources[0].id 
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

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}/partitions - post"

<#
    .SYNOPSIS
        Adds a partitiom into a luna network connection with the ID 
    .DESCRIPTION
        Adds a partitiom into a luna network connection with the ID 
    .PARAMETER name
        The complete name of the Luna HSM connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMConnections cmdlet to find the appropriate id value.
    .PARAMETER hostname
        IP for Hostname/FQDN of the PRE-EXISTING Luna Network HSM server. 
        To use an HA group enter each HSM Server IP in a comma-separated list. If the partitions in the HA group are in the same HSM server, enter the same IP twice.
    .PARAMETER serial
        Serial Number for the target partition.
        To use an HA group enter each partition serial number in a comma-separated list.
    .PARAMETER label
        Label for the target partition.
        To use an HA group enter each partition label in a comma separated list.
    .EXAMPLE
        PS> Add-CMLunaHSMConnectionPartition -name "My Luna HSM Connection" -hostname 192.168.100.70 -serial "987654" -label "part2" 
        Explanation:
        This command will add an additional partition attached to "My Luna HSM Connection" with appropriate partition details.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Add-CMLunaHSMConnectionPartition{
    param(
        [Parameter(Mandatory=$false)]
            [string] $name, 
        [Parameter(Mandatory=$false)]
            [string[]] $id, 
        [Parameter(Mandatory, HelpMessage="Enter Luna HSM Server IP or FQDN as previously defined.")]
            [string] $hostname, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Serial Number.")]
            [string] $serial, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Label.")]
            [string] $label
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Adding a partition to an existing Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/partitions"
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
        $endpoint += "/" + $id + "/partitions"
    }else{
        return "Missing Connection Identifier."
    }

    # Mandatory Parameters
    $body= [ordered] @{
        "hostname" = $hostname
        "serial_number" = $serial
        "partition_label" = $label
    }

    $jsonBody = $body | ConvertTo-JSON 
    
    Write-Debug "Endpoint: $($endpoint)"
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Partition already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Partition removed."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}/partitions/{partition_id} - delete"

<#
    .SYNOPSIS
        Deletes a partition of luna network connection with the given ID
    .DESCRIPTION
        Deletes a partition of luna network connection with the given ID
    .PARAMETER name
        The complete name of the Luna HSM connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMConnections cmdlet to find the appropriate id value.
    .PARAMETER partition_id
        CipherTrust Manager UUID of the partition to be deleted. 
        This value can be retried by using the Get-CMLunaHSMConnection -name "<your_connection_name>" command and reviewing the partitions value.
        This needs to be an exact value.
    .EXAMPLE
        PS> Remove-CMLunaHSMConnectionPartition -name "My Luna HSM Connection" -partition_id d0d7d73d-38c1-4c3d-a6b8-72a82eb22377
        Explanation:
        This command will add an additional partition attached to "My Luna HSM Connection" with appropriate partition details.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLunaHSMConnectionPartition{
    param(
        [Parameter(Mandatory=$false)]
            [string] $name, 
        [Parameter(Mandatory=$false)]
            [string[]] $id, 
        [Parameter(Mandatory=$false, HelpMessage="Enter Partition ID.")]
            [string[]] $partition_id
    )

    if(!$partition_id){ return "Missing Partition ID. Unable to proceed. Please try again."}

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Removes a partition from an existing Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/partitions/" + $partition_id
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        [string]$id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
        $endpoint += "/" + $id + "/partitions/" + $partition_id
    }else{
        return "Missing Connection Identifier."
    }

    if((Get-CMLunaHSMConnection -id $id).partitions.count -eq 1){
        return "Unable to delete the partition. To delete a partition, available number of partitions must be greater than 1."
    }

    Write-Debug "Endpoint: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        #Write-Debug "Insert REST API call Here."
        $response = Invoke-RestMethod  -Method 'DELETE' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::NotFound) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Partition does not exist." -ErrorAction Stop
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Partition deleted."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return "Partition Deleted."
}    

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}"
#"#/v1/connectionmgmt/services/luna-network/connections/{id}/test" - post

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI target. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
        Name of the existing CipherTrust Manager Luna HSM connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Luna HSM connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMLunaHSMConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Luna HSM Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
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


#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the Luna HSM Partition. This does not create a persistent connection.
    .PARAMETER hostname
        IP for Hostname/FQDN of the PRE-EXISTING Luna Network HSM server. 
        To use an HA group enter each HSM Server IP in a comma-separated list. If the partitions in the HA group are in the same HSM server, enter the same IP twice.
    .PARAMETER serial
        Serial Number for the target partition.
        To use an HA group enter each partition serial number in a comma-separated list.
    .PARAMETER label
        Label for the target partition.
        To use an HA group enter each partition label in a comma separated list.
    .PARAMETER copass
        Crypto Officer password for the target partition.
        To use an HA group both partitions must have the same Crypto Officer password.
    .PARAMETER ha_enabled
        This flag signifies if it is HighAvailability(HA) Group or not. The default is false.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMLunaHSMConnParameters{
    param(
        [Parameter(Mandatory, HelpMessage="Enter Luna HSM Server IP or FQDN as previously defined.")]
            [string[]] $hostname, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Serial Number.")]
            [string[]] $serial, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Label.")]
            [string[]] $label, 
        [Parameter(Mandatory, HelpMessage="Enter Crypto Officer password.")]
            [string] $copass, 
        [Parameter()] [switch] $ha_enabled
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing Luna HSM Connection Parameter details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body= [ordered] @{
        "password" = $copass
    }

    #Partition Parameter Block Creation
    $partitions = @()
    $partition_counter=0
    while($partition_counter -lt $serial.Count){
        $part_params = [ordered] @{}
        $part_params.add('hostname',$hostname[$partition_counter]) 
        $part_params.add('partition_label',$label[$partition_counter]) 
        $part_params.add('serial_number',$serial[$partition_counter])
        $partitions += $part_params
        $partition_counter++
    }

    $body.add('partitions',$partitions)

    # Optional Parameters
    if(!$ha_enabled -and ($serial.count -gt 1)){
        return "Non HA Group can only have one partition in an HSM Connection."
    }elseif($ha_enabled){
        $body.add('is_ha_enabled',[bool]$true)
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
    Write-Debug "Connection parameters tested."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}  

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections-test/"
#"#/v1/connectionmgmt/services/luna-network/connections-test/{id}/test" - get

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI target. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
        Name of the existing CipherTrust Manager Luna HSM connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing Luna HSM connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLunaHSMConnectionStatus{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting Luna HSM Connection Status"
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id    
    }elseif($name){ 
        if((Find-CMLunaHSMConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMConnections -name $name).resources[0].id 
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
    Write-Debug "Connection status retrieved."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


####
# Export Module Members
####
#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections"
#"#/v1/connectionmgmt/services/luna-network/connections - get"

Export-ModuleMember -Function Find-CMLunaHSMConnections #/v1/connectionmgmt/services/luna-network/connections - get"
Export-ModuleMember -Function New-CMLunaHSMConnection #/v1/connectionmgmt/services/luna-network/connections - post"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}"
Export-ModuleMember -Function Get-CMLunaHSMConnection #/v1/connectionmgmt/services/luna-network/connections/{id} - get"
Export-ModuleMember -Function Update-CMLunaHSMConnection #/v1/connectionmgmt/services/luna-network/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMLunaHSMConnection #/v1/connectionmgmt/services/luna-network/connections/{id} - delete"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id}/partitions"
Export-ModuleMember -Function Add-CMLunaHSMConnectionPartition #/v1/connectionmgmt/services/luna-network/connections/{id}/partition - post"
Export-ModuleMember -Function Remove-CMLunaHSMConnectionPartition #/v1/connectionmgmt/services/luna-network/connections/{id}/partitions/{partition_id} - delete"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connections/{id} - post"
Export-ModuleMember -Function Test-CMLunaHSMConnection #/v1/connectionmgmt/services/luna-network/connections/{id}/test - post"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connection-test/{id}"
Export-ModuleMember -Function Get-CMLunaHSMConnectionStatus #/v1/connectionmgmt/services/luna-network/connection-test/{id} - get"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/connection-test - post"
Export-ModuleMember -Function Test-CMLunaHSMConnectionParameters #/connectionmgmt/services/luna-network/connection-test - post"


