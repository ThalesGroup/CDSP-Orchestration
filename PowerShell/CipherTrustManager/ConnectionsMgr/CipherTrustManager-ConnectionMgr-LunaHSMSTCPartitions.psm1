#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-LunaHSMPartitions.psm1                                           #
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
$target_uri = "/connectionmgmt/services/luna-network/stc-partitions"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections Luna Network HSM STC Partition Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections Luna HSM STC Partition Module"
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


#This project mirrors the "Connection Manager - Luna Network HSM STC Partition" section of the API Playground of CM (/playground_v2/api/Connection Manager/Luna Network HSM STC Partition)

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/stc-partitions"
#"#/v1/connectionmgmt/services/luna-network/stc-partitions - get"

<#
    .SYNOPSIS
        Returns a list of Luna Network HSM STC Partitions.
    .DESCRIPTION
        Returns a list of Luna Network HSM STC Partitions. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Luna Network HSM STC Partition
        #/v1/connectionmgmt/services/luna-network/stc-partitions - get).   
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .PARAMETER name
        Filter by the conection name
    .PARAMETER label
        Filter results by partition label.
    .PARAMETER serial_number
        Filter results by partition serial number.
    .EXAMPLE
        PS> Find-CMLunaHSMSTCPartitions -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMLunaHSMSTCPartitions {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [int] $skip,
        [Parameter()] [int] $limit,
        [Parameter()] [string] $label, 
        [Parameter()] [string] $serial_number
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all Luna Network HSM STC Partitions in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name
    }
    if ($label) {
        if ($firstset) {
            $endpoint += "&label="
        }
        else {
            $endpoint += "?label="
            $firstset = $true
        }
        $endpoint += $label
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
    if ($serial_number) {
        if ($firstset) {
            $endpoint += "&serial_number="
        }
        else {
            $endpoint += "?serial_number="
            $firstset = $true
        }
        $endpoint += $serial_number
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
    Write-Debug "List of all CM Connections to Luna Network HSM STC Partitions with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/stc-partitions"
#"#/v1/connectionmgmt/services/luna-network/stc-partitions - post"

<#
    .SYNOPSIS
        EXPERIMENTAL: Create a new CipherTrust Manager Luna Network HSM STC Partition to be used in conjuction with a Luna HSM Server. 
    .DESCRIPTION
        EXPERIMENTAL: Creates a new Luna HSM STC Partition connection. 
    .PARAMETER name
        Name of the Luna Network HSM STC Partition.
    .PARAMETER label
        Label of the Luna Network HSM STC Partition.
    .PARAMETER partition_identity
        Contents of Luna Network HSM STC Partition Identity(pid) file in base64 form.
    .PARAMETER serial_number
        Serial Number of Luna Network HSM STC Partition.
    .PARAMETER description
        (Optional) Connection description.
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
function Register-CMLunaHSMSTCPartition{
    param(
        [Parameter(Mandatory,HelpMessage="Enter name for Luna HSM STC Partition.")]
            [string] $name, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Serial Number.")]
            [string[]] $serial_number, 
        [Parameter(Mandatory, HelpMessage="Enter Partition Label.")]
            [string[]] $label, 
        [Parameter(Mandatory, HelpMessage="Contents of Luna Network HSM STC Partition Identity(pid) file in base64 form.")]
            [string] $partition_identity, 
        [Parameter()] [ValidateSet('cckm','hsm_anchored_domain')] 
            [string[]] $products,
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Luna HSM STC Partition Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    
    # Mandatory Parameters
    $body= [ordered] @{
        "name" = $name
        "label" = $label
        "serial_number" = $serial_number
        "partition_identity" = $partition_identity
    }

    
    # Optional Parameters
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
#"#/v1/connectionmgmt/services/luna-network/stc-partitions/{id}"
#"#/v1/connectionmgmt/services/luna-network/stc-partitions/{id}" - get

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Luna HSM STC Partition Connection
    .DESCRIPTION
        Retriving the full list of Luna HSM STC Partition Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Luna HSM STC Partition Connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMLunaHSMSTCPartition -name "My Luna HSM STC Partition"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMLunaHSMSTCPartition -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLunaHSMSTCPartition{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on Luna HSM STC Partition"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMLunaHSMSTCPartitions -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMSTCPartitions -name $name).resources[0].id 
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
#"#/v1/connectionmgmt/services/luna-network/stc-partitions/{id}"
#"#/v1/connectionmgmt/services/luna-network/stc-partitions/{id}" - delete

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Luna HSM STC Partition Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Luna HSM STC Partition Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Luna HSM STC Partition connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLunaHSMSTCPartitions cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMLunaHSMSTCPartition -name "My Luna HSM STC Partition"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLunaHSMSTCPartition -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLunaHSMSTCPartition{
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

    Write-Debug "Preparing to remove Luna HSM STC Partition Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($hostname){ 
        if((Find-CMLunaHSMSTCPartitions -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLunaHSMSTCPartitions -name $name).resources[0].id 
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



####
# Export Module Members
####
#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/stc-partitions"
#"#/v1/connectionmgmt/services/luna-network/stc-partitions - get"

Export-ModuleMember -Function Find-CMLunaHSMSTCPartitions #/v1/connectionmgmt/services/luna-network/stc-partitions - get"
Export-ModuleMember -Function Register-CMLunaHSMSTCPartition #/v1/connectionmgmt/services/luna-network/stc-partitions - post"

#Connection Manager - Luna HSM Connections
#"#/v1/connectionmgmt/services/luna-network/stc-partitions/{id}"
Export-ModuleMember -Function Get-CMLunaHSMSTCPartition #/v1/connectionmgmt/services/luna-network/stc-partitions/{id} - get"
Export-ModuleMember -Function Remove-CMLunaHSMSTCPartition #/v1/connectionmgmt/services/luna-network/stc-partitions/{id} - delete"


