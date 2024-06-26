#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-Main.psm1                                                        #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################
###
###
# ENUM
###
# Supported Algorithms
Add-Type -TypeDefinition @"
   public enum certAlgorithms {
    rsa,
    ecdsa
}
"@

# Key Sizes
[flags()] Enum KeySizeTable {
    KeySize1024 = 1024 
    KeySize2048 = 2048 
    KeySize4096 = 4096
}

####
# Local Variables
####
$target_uri = "/connectionmgmt/connections"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Main Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Main Module"
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


#This project mirrors the "Connection Manager (Main)" section of the API Playground of CM (/playground_v2/api/Connection Manager)

#Connection Manager
#"#/v1/cnnectionmgmt/connections-get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager).   
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
    .PARAMETER service
        Filter the result based on the external services associated with the connections. (e.g. aws,azure,gcp,hadoop-knox,luna network)
    .PARAMETER category
        Filter the result based on category.
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
        PS> Find-CMConnection -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMConnections {
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
        [Parameter()] [string] $fields, 
        [Parameter()] [string] $products, 
        [Parameter()] [string] $meta_contains, 
        [Parameter()] [string] $service, 
        [Parameter()] [string] $category, 
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Connections in CM"
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
    if ($service) {
        if ($firstset) {
            $endpoint += "&service="
        }
        else {
            $endpoint += "?service="
            $firstset = $true
        }
        $endpoint += $service
    }
    if ($category) {
        if ($firstset) {
            $endpoint += "&category="
        }
        else {
            $endpoint += "?category="
            $firstset = $true
        }
        $endpoint += $category
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
    Write-Debug "List of all CM Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    if($response.GetType() -eq [String]){
        return $response | ConvertFrom-JSON -AsHashTable
    }else{
        return $response
    }
}    


#Connection Manager
#"/v1/cnnectionmgmt/connections"
#"/v1/cnnectionmgmt/connections/{id} - delete"
#"/v1/cnnectionmgmt/connections/{id}/delete - post"


<#
    .SYNOPSIS
        Delete a CipherTrust Manager Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Connection. This operation cannot be undone. This will remove all associated certificates, usernames, passwords, etc.
    .PARAMETER name
        Identify a connection by its name.
    .PARAMETER id
        Identify a connection by its ID.
    .PARAMETER force
        Use the -force switch to delete an in-use connection.
    .EXAMPLE
        PS> Remove-CMConnection -name "scpbackup"
        Removes a connection named "scpbackup" 
    .EXAMPLE
        PS> Remove-CMConnection -id <UUID>
        Removes a connection by its UUID. 
    .EXAMPLE
        PS> Remove-CMConnection -name "scpbackup" -force
        Removes a connection named "scpbackup" even if marked as "in use."
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMConnection {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter()] [switch] $force
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting a List of all Connections in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri

    if(!$force){
        if(!$id -and $name){
            if((Find-CMConnections -name $name).resources[0].total -eq 0){
                return "`nConection name not found. Please try again."
            }else{
                $connectionid = (Find-CMConnections -name $name).resources[0].id
                $endpoint += "/" + $connectionid
            }
        }elseif($id){
            $endpoint += "/" + $id
        }else{
            return "No connection ID or name provided. Please try again."
        }
        Write-Debug "Endpoint w ID: $($endpoint)"
        Write-Debug "Method: DELETE"
        
        Try {
            Test-CMJWT #Make sure we have an up-to-date jwt
            $headers = @{
                Authorization = "Bearer $($CM_Session.AuthToken)"
            }
            Write-Debug "Headers: "
            Write-HashtableArray $($headers)
            $response = Invoke-RestMethod  -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    }else{
        if(!$id -and $name){
            if((Find-CMConnections -name $name).resources[0].total -eq 0){
                return "`nConection name not found. Please try again."
            }else{
                $connectionid = (Find-CMConnections -name $name).resources[0].id
                $endpoint += "/" + $connectionid + "/delete"
            }
        }elseif($id){
            $endpoint += "/" + $id + "/delete"
        }else{
            return "No connection ID or name provided. Please try again."
        }
        Write-Debug "Endpoint w ID: $($endpoint)"
        $jsonBody = '{
            "force": true
        }'
        Write-Debug "Method: POST"
        Write-Debug "JSON Body for POST: `n$($jsonBody)"

        Try {
            Test-CMJWT #Make sure we have an up-to-date jwt
            $headers = @{
                Authorization = "Bearer $($CM_Session.AuthToken)"
            }
            Write-Debug "Headers: "
            Write-HashtableArray $($headers)
            $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Headers $headers -Body $jsonBody -ContentType 'application/json'
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
    }

    Write-Host "Connection Deleted."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager
#"/v1/cnnectionmgmt/connections"
#"/v1/cnnectionmgmt/connections/csr - post"

<#
    .SYNOPSIS
        This API creates a Certificate Signing Request (CSR) that can be used in a connection (eg: Azure, Salesforce) in CipherTrust Manager. Connection CSR will ONLY use RSA.
    .DESCRIPTION
        The corresponding private key is stored securely on the CipherTrust Manager. The user can get the CSR signed using the external PKI.
        If the private key remains unused by a connection after 24 hours of creation, it gets deleted automatically.
    .PARAMETER name
        A unique name of CSR.
    .PARAMETER cn
        Common Name for the certificate. If not specified, the common name will be the same as the name.
    .PARAMETER size
        Certificate algorithm size. Defaults to 2048 if not specified.
        Option:
            -1024
            -2048
            -4096
    .PARAMETER dnsNames
        Subject Alternative Names: DNS Names (Commma Separated)
    .PARAMETER ipAdresses
        Subject Alternative Names: IP Addresses (Commma Separated)
    .PARAMETER emaiAddresses
        Subject Alternative Names: Email Addresses (Commma Separated)
    .PARAMETER o
        Certificate Subject: Organization
        Parameter Aliases: -org or -organization
    .PARAMETER ou
        Certificate Subject: Organizational Unit
    .PARAMETER l
        Certificate Subject: Location
        Parameter Aliases: -locality or -location
    .PARAMETER st
        Certificate Subject: State
        Parameter Aliases: -state
    .PARAMETER c
        Certificate Subject: Country
        Parameter Aliases: -country
    .EXAMPLE
        PS> New-CMConnectionCSR -name "MyConnectionCert" -cn "mydevice.ciphertrustmanager.local" 
    .EXAMPLE
        PS> New-CMConnectionCSR -name "MyConnectionCert" -cn "mydevice.ciphertrustmanager.local" -size 2048 -dnsNames "mydevice.contoso.com,mydevice.contoso.local" -ipAddresses "10.0.0.1" -emailAddresses "support@contoso.com" -ou "Security" -o "Thales DIS" -l "Plantation" -st "Florida" -c "USA"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMConnectionCSR {
param (
    [Parameter(Mandatory=$true)] [string] $name,
    [Parameter()] [string] $cn=$name,
    [Parameter()] [certAlgorithms] $algorithm="RSA",
    [Parameter()] [KeySizeTable] $size,
    [Parameter()] [string[]] $dnsNames,
    [Parameter()] [string[]] $ipAddresses,
    [Parameter()] [string[]] $emailAddresses,
    [Parameter()] [Alias('organization','org')] [string] $o="",
    [Parameter()] [Alias('oganizationalunit')] [string] $ou="",
    [Parameter()] [Alias('location','locality')] [string] $l="",
    [Parameter()] [Alias('state')] [string] $st="",
    [Parameter()] [Alias('country')] [string] $c=""
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting a List of all Connections in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/csr"

    Write-Debug "Endpoint: $($endpoint)"


    # Mandatory Parameters
    $body= [ordered] @{
        
        "name"          = $name
        "cn"            = $cn
        "algorithm"     = $algorithm.ToString()
        "size"          = [int]$size
    }

    #Optional Parameters
    if($dnsNames){
        $dnsNames = $dnsNames.Split(",")
        $body.Add('dnsNames',$dnsNames)
    }
    if($ipAddresses){
        $ipAddresses = $ipAddresses.Split(",")
        $body.Add('ipAddresses',$ipAddresses)
    }
    if($emailAddresses){
        $emailAddresses = $emailAddresses.Split(",")
        $body.Add('emailAddresses',$emailAddresses)
    }
    if($ou -or $o -or $l -or $st -or $c){
        $body.add("names", @())
        $subject = [ordered] @{}
        if($ou){ $subject.ou = $ou }
        if($o){ $subject.o = $o }
        if($l){ $subject.l = $l }
        if($st){ $subject.st = $st }   
        if($c){ $subject.c = $c }
               
        $body.names = @( $subject )
    }

    $jsonBody = $body | ConvertTo-Json
    
    
    
    Write-Debug "JSON Body:`n$($jsonBody)"

    #Optional Parameters Complete

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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    $csr = $response.csr.ToString()

    return "CSR:`n$($csr)"
}    

####
# Export Module Members
####
#Connection Manager
#/v1/connectionmgmt/connections

Export-ModuleMember -Function Find-CMConnections    #/v1/connectionmgmt/connections - get
Export-ModuleMember -Function Remove-CMConnection   #/v1/connectionmgmt/connections/{id} - delete
                                                    #/v1/connectionmgmt/connections/{id}/delete - post to force delete with body
#Connection Manager
#/v1/connectionmgmt/connections/csr
Export-ModuleMember -Function New-CMConnectionCSR   #/v1/connectionmgmt/connections/csr - post