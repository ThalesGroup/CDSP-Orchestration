#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-LunaHSMServer.psm1                                               #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2024 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

###
# ENUM
###
# Communication Type to be associated with Luna.
Add-Type -TypeDefinition @"
   public enum hsmProductType {
    cckm,
    hsm_anchored_domain
}
"@

# Communication Type to be associated with Luna.
Add-Type -TypeDefinition @"
   public enum hsmChannel {
    NTLS,
    STC
}
"@

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/luna-network/servers"
$target_uri_client = "/connectionmgmt/services/luna-network/client"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Luna HSM Server Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Luna HSM Server Module"
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


#This project mirrors the "Connection Manager - Luna HSM Servers" section of the API Playground of CM (/playground_v2/api/Connection Manager/Luna Network HSM Servers)

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers  - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager Luna HSM Servers
    .DESCRIPTION
        Returns a list of all Luna HSMs. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Luna HSM Servers)
    .PARAMETER id
        Filter the results based on the connection's ID.
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .PARAMETER sort
        The field, or fields, to order the results by. This should be a comma-delimited list of properties.
        For example, "name,-createdAt" .. will sort the results first by 'name', ascending, then by 'createdAt', descending.
    .PARAMETER hostname
        Filter results based on the IP or hostname of the Luna HSM.
    .PARAMETER channel
        Filter the results based on the channel of communication. 
        Options: (CASE-SENSITIVE)
        -NTLS
        -STC
    .PARAMETER createdBefore
        Filters results to those created at or before the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .PARAMETER createdAfter
        Filters results to those created at or after the specified timestamp. 
        Timestamp should be in RFC3339Nano format, e.g. 2023-12-01T23:59:59.52Z, or a relative timestamp where valid units are 'Y','M','D' representing years, months, days respectively. Negative values are also permitted. e.g. "-1Y-2M-5D".
    .EXAMPLE
        PS> Find-CMLunaHSMServer -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMLunaHSMServer {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter()] [int] $skip,
        [Parameter()] [int] $limit,
        [Parameter()] [string] $sort,
        [Parameter()] [string] $hostname, 
        [Parameter()] [string] $channel,
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter 
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Luna HSM Servers in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
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
    if ($hostname) {
        if ($firstset) {
            $endpoint += "&host="
        }
        else {
            $endpoint += "?host="
            $firstset = $true
        }
        $endpoint += $hostname
    }
    if ($channel) {
        if ($firstset) {
            $endpoint += "&channel="
        }
        else {
            $endpoint += "?channel="
            $firstset = $true
        }
        $endpoint += $channel.ToUpper()
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
    Write-Debug "List of all CM Connections to Luna HSM Servers."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers  - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager Luna HSM Server Connection 
    .DESCRIPTION
        Creates a new Luna HSM Server connection. 
    .PARAMETER target
        IP for Hostname/FQDN of the Luna HSM Server.
    .PARAMETER description
        (Optional) Description about the connection.
    .PARAMETER hsm_cert
        (Optional) CA certificate in PEM format.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER hsm_certfile
        (Optional) Specify the filename for a PEM certificate for the Luna HSM Server certificate. 
    .PARAMETER products
            - cckm
            - hsm_anchored_domain
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMLunaHSMServer -target 192.168.100.70 -hsm_certfile "C:\temp\192.168.100.70.pem" -products hsm_anchored_domain,cckm -metadata "red:stop,green:go"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMLunaHSMServer{
    param(
        [Parameter(Mandatory)] [string] $target, 
        [Parameter()] [string] $description, 
        [Parameter()] [string] $hsm_cert, 
        [Parameter()] [string] $hsm_certfile, 
        [Parameter()] [hsmProductType[]] $products,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an Luna HSM Server Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body= [ordered] @{
        "hostname" = $target
    }

    # Optional Parameters
    if($description){ $body.add('description', $description)}
    if(!$hsm_cert -and !$hsm_certfile){
        return "Missing HSM Certificate. Please try again."
    }else{
        if($hsm_certfile){ $hsm_cert = (Get-Content $hsm_certfile -raw)}
            if($hsm_cert){ $body.add('hsm_certificate', $hsm_cert)}
    }
    if(!$products){
        Write-Host "Which product will this be used for?`n`t1. CCKM`n`t2. HSM Anchored Domain`n`t3. Both"
        $whichProduct = Read-Host "Selection"
        switch($whichProduct){
            
            "1" { $products = "cckm"}
            "2" { $products = "hsm_anchored_domain"}
            "3" { 
                    $products = @()
                    $products += "cckm"
                    $products += "hsm_anchored_domain"
                }
        }
    }

    foreach($item in $products){
        [string[]]$productJSON += $item.ToString()
    }
    if($productJSON){ $body.add('products', $productJSON) }
    
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


#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id}  - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Luna HSM Connection
    .DESCRIPTION
        Retriving the full list of Luna HSM Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Luna HSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMServer cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMLunaHSMServer -name "My Luna HSM Server"
        Use the complete IP or hostname of the server. 
    .EXAMPLE
        PS> Get-CMLunaHSMServer -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLunaHSMServer{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hostname, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Luna HSM Server"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($hostname){ 
        $id = (Find-CMLunaHSMServer -hostname $name).resources[0].id 
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

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id} - delete"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id}/delete - post"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Luna HSM Server
    .DESCRIPTION
        Delete a CipherTrust Manager Luna HSM Server. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Luna HSM Server. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMServer cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMLunaHSMServer -hostname 192.168.100.70
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLunaHSMServer -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLunaHSMServer{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hostname, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false)]
        [switch] $force
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to remove Luna HSM Server"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($hostname){ 
        $id = (Find-CMLunaHSMServer -hostname $hostname).resources[0].id 
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
        Invoke-RestMethod -Method 'DELETE' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' | Out-Null
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

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id}/delete - post"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Luna HSM Server
    .DESCRIPTION
        Delete a CipherTrust Manager Luna HSM Server. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Luna HSM Server. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMServer cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMLunaHSMServerInUse -hostname 192.168.100.70
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLunaHSMServerInUse -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLunaHSMServerInUse{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hostname, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false)]
        [switch] $force
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to remove Luna HSM Server"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/delete"        
    }elseif($hostname){ 
        $id = (Find-CMLunaHSMServer -hostname $hostname).resources[0].id 
        $endpoint += "/" + $id + "/delete"
    }else{
        return "Missing Connection Identifier."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    if(!$force){
        $confirmop=""
        while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
            $confirmop = $(Write-Host -ForegroundColor red  "THIS IS REMOVING AN IN-USE LUNA HSM SERVER.`nTHIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
            if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
                Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
                return "Operation Cancelled"
            }
        }
    }
    

    $body= @{
        "force" = [bool]$true
    }

    $jsonBody = $body | ConvertTo-Json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        Write-Debug $($jsonBody)
        Invoke-RestMethod -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' | Out-Null
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


#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/servers"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id}/enable-stc - post"
#"#/v1/connectionmgmt/services/luna-network/Servers/{id}/disable-stc - post"

<#
    .SYNOPSIS
        Enable/Disable STC Mode on a Luna HSM Server Connection
    .DESCRIPTION
        Enable/Disable STC Mode on a Luna HSM Server Connection
    .PARAMETER name
        The complete name of the Luna HSM Server. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMServer cmdlet to find the appropriate id value.
    .PARAMETER enable
        Enables the STC mode for the given HSM server.
    .PARAMETER disable
        Disables the STC mode for the given HSM server.
    .EXAMPLE
        PS> Set-CMLunaHSMServerSTCMode -hostname 192.168.100.70 -enable
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Set-CMLunaHSMServerSTCMode -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -disable
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMLunaHSMServerSTCMode{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hostname, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false)]
        [switch] $enable,
        [Parameter(Mandatory = $false)]
        [switch] $disable
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to enable or disable STC Mode on Luna HSM Server"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id
    }elseif($hostname){ 
        $id = (Find-CMLunaHSMServer -hostname $hostname).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    if($enable){ 
        $endpoint += "/enable-stc" 
    }elseif($disable){
        $endpoint += "/disable-stc" 
    }elseif(!$enable -and !$disable){
        return "Missing command. Plese try again."
    }

    Write-Debug "Endpoint w Target: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        if($jsonBody){Write-Debug $($jsonBody)}
        $response = Invoke-RestMethod -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"
        $response  
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
    Write-Debug "HSM Communcation Channel Changed."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return
}    

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/client"

<#
    .SYNOPSIS
        Returns the information about Luna Client (certificate, hostname, stc client identity, etc.) for a Luna HSM Server.
    .DESCRIPTION
        Returns the information about Luna Client (certificate, hostname, stc client identity, etc.) for a Luna HSM Server.
    .PARAMETER exportcert
        Switch to autoexport the CM Client Certificate for HSM.
    .PARAMETER outputPath
        Path to export the client certificate. Use the full path including trailing slash.
        e.g. C:\OutputDirectory\
    .EXAMPLE
        PS> $clientinfo = Get-CMLunaClientInfo 
        Output the client information to a PowerShell object called $clientinfo
    .EXAMPLE
        PS> Get-CMLunaClientInfo -exportcert -client_cert_path "C:\temp"
        Retrieve the client information and export the client certificate to a file. The file NAMwill be autogenerated to match the system hostname for CCKM.
        e.g. cckm-client-440bb628-9d51-406a-9906-865ef484f527.pem
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLunaClientInfo{
    param(
        [Parameter(Mandatory = $false)]
        [switch] $exportcert, 
        [Parameter(Mandatory = $false)]
        [string] $outputPath
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to retrieve the Luna Client information for the CipherTrust Manager."
    $endpoint = $CM_Session.REST_URL + $target_uri_client
    Write-Debug "Endpoint: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        if($jsonBody){Write-Debug $($jsonBody)}
        $response = Invoke-RestMethod -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"
        $response  
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

    if($exportcert){
        if(!$outputPath){
            $outputPath = Read-Host "Enter full path to output the CM client certificate. Use the full path including trailing slash.`nPress enter for the current directory. [$($PWD)] "
        }
        if($outputPath -eq ""){
            $outputPath = $PWD 
            $outputPath += "\"
        }
        $outputFileName = "$($response.hostname).pem"
        $fullOutputPath = $outputPath + $outputFileName
        
        $response.certificate | Out-File -FilePath $fullOutputPath
    }

    Write-Debug "CipherTrust Luna Client information retrieved."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return "Client information retrieved."
}    

####
# Export Module Members
####
#Connection Manager - Luna HSM Servers
#/v1/connectionmgmt/services/luna-network/servers/"

Export-ModuleMember -Function Find-CMLunaHSMServer #/v1/connectionmgmt/services/luna-network/servers  - get"
Export-ModuleMember -Function New-CMLunaHSMServer #/v1/connectionmgmt/services/luna-network/servers - post"

#Connection Manager - Luna HSM Servers
#/v1/connectionmgmt/services/luna-network/servers/{id}"
Export-ModuleMember -Function Get-CMLunaHSMServer #/v1/connectionmgmt/services/luna-network/servers/{id} - get"
Export-ModuleMember -Function Remove-CMLunaHSMServer #/v1/connectionmgmt/services/luna-network/servers/{id} - delete"
Export-ModuleMember -Function Remove-CMLunaHSMServerInUse #/v1/connectionmgmt/services/luna-network/servers/{id} - post"

#Connection Manager - Luna HSM Servers
#/v1/connectionmgmt/services/luna-network/servers/{id}/enable-stc"
#/v1/connectionmgmt/services/luna-network/servers/{id}/disable-stc"
Export-ModuleMember -Function Set-CMLunaHSMServerSTCMode    #/v1/connectionmgmt/services/luna-network/servers/{id}/enable-stc - post"
                                                            #/v1/connectionmgmt/services/luna-network/servers/{id}/disable-stc - post"

#Connection Manager - Luna HSM Servers
#"#/v1/connectionmgmt/services/luna-network/client"
Export-ModuleMember -Function Get-CMLunaClientInfo #/v1/connectionmgmt/services/luna-network/client - get"
