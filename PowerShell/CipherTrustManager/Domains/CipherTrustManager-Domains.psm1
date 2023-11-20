#######################################################################################################################
# File:             CipherTrustManager-Users.psm1                                                                     #
# Author:           Rick Leon, Professional Servcies                                                                  #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_curdom_uri = "/domain"
$target_uri = "/domains"
$target_syslogredir_uri = "/domain-syslog-redirection"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    $PSDefaultParameterValues = @{"Invoke-RestMethod:SkipCertificateCheck"=$True}
    $PSDefaultParameterValues = @{"ConvertTo-JSON:Depth"=5} 
}else{
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

#This project mirrors the "Domains" section of the API Playground of CM (/playground_v2/api/Domains)

#Domain
#"#/v1/domain/-get"

<#
    .SYNOPSIS
        Get Current Active Domain
    .DESCRIPTION
        Returns the domain where the user is currently authenticated.
    .EXAMPLE
        PS> Get-CMDomainCurrent
        
        Result: MyDomain
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMDomainCurrent {

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a Current Domain in CM"
    $endpoint = $CM_Session.REST_URL + $target_curdom_uri
    Write-Debug "Endpoint: $($endpoint)"
    
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
    Write-Debug "Current domain."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    


#Domains
#"#/v1/domains/"
#"#/v1/domains/-get"

<#
    .SYNOPSIS
        List Domains
    .DESCRIPTION
        Returns a list of all domains. The results can be filtered, using the query parameters. Wildcard are supported.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters.    
    .PARAMETER name
        Filter by the Domain name
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Find-CMDomains -name tar*
        Returns a list of all Domains whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMDomains {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of Domains in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name
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
    Write-Debug "List of domains."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Domains
#"#/v1/domains/"
#"#/v1/domains/-post"

<#
    .SYNOPSIS
        Create a Domain
    .DESCRIPTION
        Creates a domain with optional parameters
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters.    
    .PARAMETER name
        The desired name of the domain.
    .PARAMETER admins
        The initial administrator for the domain. This field uses the User_ID value for the administrator.
        If the administrator's user_id is unknown. Use the Find-CMUser cmdlet to retrieve.
        e.g Find-CMUser -name admin
        e.g. user_id: local|7fd1b8c9-dda6-46ea-a016-094e2f518356
    .PARAMETER parent_ca_id
        (Optional) The CipherTrust ID for the desired parent Certificate Authority. If no CA is specified the oldest CA in the environment will be automatically selected.
    .PARAMETER allow_user_management
        (Optional) Enable to allow local domain users to be created instead of root users being assigned to the domain.
    .PARAMETER hsm_conn_id
        (Optional) If an HSM-anchored domain is desired, the CipherTrust Connection ID is required.
    .PARAMETER hsm_kek_label
        (Optional) Optional name field for the domain KEK for an HSM-anchored domain. If not provided, a random UUID is assigned for KEK label.
    .EXAMPLE
        PS> New-CMDomain -name MyDomain -admins "local|7fd1b8c9-dda6-46ea-a016-094e2f518356"
        Creates a domain with the name MyDomain with a single administrator.
    .EXAMPLE    
        PS> New-CMDomain -name MyDomain -admins "local|7fd1b8c9-dda6-46ea-a016-094e2f518356","contoso.com|myAdmin"
        Creates a domain with the name MyDomain with a two administrators in a comma-separated list. One administrator being local and the second from an LDAP Connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function New-CMDomain {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string[]] $admins,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $parent_ca,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $allow_user_management,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $hsm_conn_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $hsm_kek_label
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Domain in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'name' = $name
        'admins' = @($admins.split(","))
    }

    # Optional Parameters
    if ($parent_ca_id) { $body.add('parent_ca_id', $parent_ca_id) }
    if ($hsm_conn_id) { $body.add('hsm_connection_id', $hsm_conn_id) }
    if ($hsm_kek_label) { $body.add('hsm_kek_label', $hsm_kek_label) }
    if ($allow_user_management -eq $True) { $body.add('allow_user_management', [bool]$true) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Domain already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Domain created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Domains
#"#/v1/domains/"
#"#/v1/domains/{id}-delete"

<#
    .SYNOPSIS
        Delete a Domain
    .DESCRIPTION
        Permanently deleted a domain and all contents. USE EXTREME CAUTION.
    .PARAMETER name
        The name of the domain to be deleted. This parameter is CASE-SENSITIVE. 
    .EXAMPLE
        PS> Remove-CMDomain -name MyDomain 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Remove-CMDomain {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )
    
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Domain in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if((Find-CMDomains -name $name).resources[0].total -eq 0){
        return "`nDomain not found. Please try again."
    }else{
        $domainid = (Find-CMDomains -name $name).resources[0].id
        $endpoint += "/" + $domainid
    }

    Write-Debug "Endpoint: $($endpoint)"

    $confirmop=""
    $confirmname=""
    while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
        $confirmop = $(Write-Host -ForegroundColor red  "THIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
        if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
            Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
            return "Operation Cancelled"
        }
    }
    
    $confirmname = $(Write-Host -ForegroundColor red  "`nConfirm the name of the domain to be deleted: " -NoNewline; Read-Host)
    if($confirmname -cne $name){
        return "Domain name does not match. Cancelling Operation."
    }
    
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Domain already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Domain deleted."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    Write-Host "`nDomain Deleted" -ForegroundColor Red
    return $response
}    
   
#Domains
#'#/v1/domain-syslog-redirection/status"

<#
    .SYNOPSIS
        Show status of Domain Syslog Redirection in current domain. 
    .DESCRIPTION
        Domain Syslog Redirection will send Domain-level syslog to the Parent Domain, typically root, configured SYSLOG server.
    .EXAMPLE
        PS> Get-CMDomainSyslogRedirection

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Get-CMDomainSyslogRedirection {
    
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if($(Get-CMDomainCurrent).name -eq "root"){
        Write-Host "Session is currently Authenticated in ROOT Domain.`nRun Disconnect-CipherTrustManager first and reconnect to desired Domain using -domain switch."
        return 
    }

    Write-Debug "Checking a Domain Redirection Status"
    $endpoint = $CM_Session.REST_URL + $target_syslogredir_uri + "/status"
    Write-Debug "Endpoint: $($endpoint)"

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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Domain already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Status Found."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return "Syslog Redirection Status for Domain: $($(Get-CMDomainCurrent).name) is $($response.enable_syslog_redirection)."
}    

#Domains
#'#/v1/domain-syslog-redirection/enable"
#'#/v1/domain-syslog-redirection/disable"

<#
    .SYNOPSIS
        Update status of Domain Syslog Redirection in current domain. 
    .DESCRIPTION
        Domain Syslog Redirection will send Domain-level syslog to the Parent Domain, typically root, configured SYSLOG server.
    .PARAMETER status
        Turn SYSLOG Redirection on or off. Allowed Values: on/off.
    .EXAMPLE
        PS> Update-CMDomainSyslogRedirection -status on
    .EXAMPLE
        PS> Update-CMDomainSyslogRedirection -status off

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Update-CMDomainSyslogRedirection {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $status
    )
    
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if($(Get-CMDomainCurrent).name -eq "root"){
        Write-Host "Session is currently Authenticated in ROOT Domain.`nRun Disconnect-CipherTrustManager first and reconnect to desired Domain using -domain switch."
        return 
    }

    Write-Debug "Updating a Domain Redirection Status"
    $endpoint = $CM_Session.REST_URL + $target_syslogredir_uri
    Write-Debug "Endpoint: $($endpoint)"


    
    if($status -eq "on"){
        $endpoint += "/enable"
    }elseif($status -eq "off"){
        $endpoint += "/disable"
    }else{
        Get-CMDomainSyslogRedirection
        return "No Operation Provided. Showing Current Status."
    }

    Write-Debug "Endpoint: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Domain already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Status Updated."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return "Syslog Redirection Status for Domain: $($(Get-CMDomainCurrent).name) is $($response.enable_syslog_redirection)."
}    

#Domains
#`#/v1/domains/{id}
#`#/v1/domains/{id} - update

<#
    .SYNOPSIS
        Update the HSM-anchored status of a Domain after it is has been created.
    .DESCRIPTION
        Updating a domain will have one of two functions. It will either convert a standrd domain into an HSM-Anchored Domain, or it will generate a new Domain Key Encrypting Key (KEK) on a Connected Luna HSM partition. This operation is irreversible.
    .PARAMETER name
        The name of the domain to update.
    .PARAMETER hsm_connection_id
        The ID of the HSM connection. The existing connection ID is used if this parameter is not specified.
    .PARAMETER hsm_kek_label
        Label of the target domain KEK. This is a required parameter. A key with this label must exist on the HSM.
    .EXAMPLE
        PS> Update-CMDomainHSM -name "DEV" -hsm_connection_id <UUID> -hsm_kek_label MyNewKEK
    .EXAMPLE
        PS> Update-CMDomainHSM -name "DEV" -hsm_kek_label MyNewKEK

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Update-CMDomainHSM {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hsm_connection_id,
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hsm_kek_label
    )
    
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating a Domain HSM-Anchored Status"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if((Find-CMDomains -name $name).resources[0].total -eq 0){
        return "`nDomain not found. Please try again."
    }else{
        $domainid = (Find-CMDomains -name $name).resources[0].id
        $endpoint += "/" + $domainid
    }

    Write-Debug "Endpoint: $($endpoint)"

    $confirmop=""
    $confirmname=""
    while($confirmop -ne "yes" -or $confirmop -ne "YES" ){
        $confirmop = $(Write-Host -ForegroundColor red  "THIS OPERATION CANNOT BE UNDONE.`nARE YOU SURE YOU WISH TO CONTINUE? (yes/no) " -NoNewline; Read-Host)
        if($confirmop -eq "NO" -or $confirmop -eq "no" ){ 
            Write-Host "CANCELLING OPERATION. NO CHANGES HAVE BEEN MADE."
            return "Operation Cancelled"
        }
    }
    
    $confirmname = $(Write-Host -ForegroundColor red  "`nConfirm the name of the domain to convert: " -NoNewline; Read-Host)
    if($confirmname -cne $name){
        return "Domain name does not match. Cancelling Operation."
    }

    $Body = @{
     
        "hsm_connection_id" = $hsm_connection_id
        "hsm_kek_label"     = $hsm_kek_label

    }


    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug $($jsonBody)

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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Domain already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Status Updated."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return "Process Completed."
}    

#Domains
#`#/v1/domains/{id}
#`/v1/domains/{id}/keks - Get (get)

<#
    .SYNOPSIS
        Returns the list of domain KEKs for specified domain along with the status of ongoing and previous KEK rotations. Applicable to hsm anchored domains.
    .DESCRIPTION
        Returns the list of domain KEKs for specified domain along with the status of ongoing and previous KEK rotations. Applicable to hsm anchored domains.
    .PARAMETER name
        The name of the domain to check.
    .EXAMPLE
        PS> Find-CMDomainKEKS -name "DEV"

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Find-CMDomainKEKS {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of Keks in Domain in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if((Find-CMDomains -name $name).resources[0].total -eq 0){
        return "`nDomain not found. Please try again."
    }else{
        $domainid = (Find-CMDomains -name $name).resources[0].id
        $endpoint += "/" + $domainid + "/keks"
    }
    
    Write-Debug "Endpoint: $($endpoint)"

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
    Write-Debug "List of domains keks."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

#Domains
#`#/v1/domains/{id}
#`/v1/domains/{id}/keks/{kekID} - Get (get)

<#
    .SYNOPSIS
        Returns the domain KEK of specified account along with the status of ongoing and previous KEK rotations. Applicable to hsm anchored domains.
    .DESCRIPTION
        Returns the domain KEK of specified account along with the status of ongoing and previous KEK rotations. Applicable to hsm anchored domains.
    .PARAMETER domain
        The name of the HSM-Anchored CipherTrust Domain.
    .PARAMETER kekid
        The CipherTrust Manager ID of the Domain KEK to retrieve detail on. Use Find-CMDomainKEKS cmdlet to find KEK ID.
    .EXAMPLE
        PS> Get-CMDomainKEK -domainname <DomainName> -kekid <UUID>

        PS> Get-CMDomainKEK -domainname "MyDomain" -kekid "d0930205-bd38-4230-a46b-03075d85d400"

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Get-CMDomainKEK {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $domain,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $kekid
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting KEK Detail"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if((Find-CMDomains -name $domain).resources[0].total -eq 0){
        return "`nDomain not found. Please try again."
    }else{
        $domainid = (Find-CMDomains -name $name).resources[0].id
        $endpoint += "/" + $domainid + "/keks/" + $kekid
    }
    
    Write-Debug "Endpoint: $($endpoint)"

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
    Write-Debug "List of domains keks."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}  

#Domains
#`#/v1/domains/{id}
#`/v1/domains/{id}/rotate-kek (post)
#`/v1/domains/{id}/retry-kek-rotation (post)

<#
    .SYNOPSIS
        Rotates the KEK that protects domain resources such as keys. Applicable only to hsm anchored domains. 
    .DESCRIPTION
        Rotates the KEK that protects domain resources such as keys. Applicable only to hsm anchored domains. This creates a new HSM-based KEK, or reuses an existing HSM-based KEK. All domain keys that are re-wrapped by this KEK.
    .PARAMETER domain
        The name of the HSM-Anchored CipherTrust Domain.
    .PARAMETER hsm_connection_id
        The ID of the HSM connection. The existing connection ID is used if this parameter is not specified.
    .PARAMETER hsm_kek_label
        Label of the domain KEK on the HSM. A newly created UUID is used as the label when this parameter is not specified. If a key with this label exists on the HSM, it is reused, and a new HSM key is created otherwise.
    .PARAMETER retry
        Retries a domain KEK rotation thats has been stopped. Applicable only to hsm anchored domains. Reuses an existing HSM-based KEK. All domain keys that are re-wrapped by this KEK.
    .EXAMPLE
        PS> Update-CMDomainRotateKEK -domainname <DomainName>
    .EXAMPLE
        PS> Update-CMDomainRotateKEK -domainname <DomainName> -hsm_connection_id <UUID>
    .EXAMPLE
        PS> Update-CMDomainRotateKEK -domainname <DomainName> -hsm_connection_id <UUID> -hsm_kek_label "MyNewKEK_v2"
    .EXAMPLE
        PS> Update-CMDomainRotateKEK -domainname <DomainName> -retry

    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function Update-CMDomainRotateKEK {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $domain,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $hsm_connection_id,
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $hsm_kek_label,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [switch] $retry


    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Rotating Domain KEK"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($retry -eq $True){
        if((Find-CMDomains -name $domain).resources[0].total -eq 0){
            return "`nDomain not found. Please try again."
        }else{
            $domainid = (Find-CMDomains -name $name).resources[0].id
            $endpoint += "/" + $domainid + "/retry-kek-rotation"
        }

        Write-Debug "Endpoint: $($endpoint)"
    }else{
        if((Find-CMDomains -name $domain).resources[0].total -eq 0){
            return "`nDomain not found. Please try again."
        }else{
            $domainid = (Find-CMDomains -name $name).resources[0].id
            $endpoint += "/" + $domainid + "/rotate-kek"
        }

        $body = @{}

        # Optional Parameters
        if ($hsm_connection_id) { $body.add('hsm_connection_id', $hsm_connection_id) }
        if ($hsm_kek_label) { $body.add('hsm_kek_label', $hsm_kek_label) }
    
        Write-Debug "Endpoint: $($endpoint)"
        $jsonBody = $body | ConvertTo-Json -Depth 5
        Write-Debug $($jsonBody)
    }

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        if($retry -eq $False){ $response = Invoke-RestMethod -Method 'POST' -Uri $endpoint -Headers $headers -Body $jsonBody -ContentType 'application/json' 
        }else{ $response = Invoke-RestMethod -Method 'POST' -Uri $endpoint -Headers $headers -ContentType 'application/json'
        }
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
    Write-Debug "Rotating Domain KEK."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}  


####
# Export Module Members
####
#Domains
#/v1/domain
Export-ModuleMember -Function Get-CMDomainCurrent #/v1/domain - Get (get)

#/v1/domains
Export-ModuleMember -Function Find-CMDomains #/v1/domains - List (get)
Export-ModuleMember -Function New-CMDomain ##/v1/domains - Create (post)

#`#/v1/domains/{id}
#Export-ModuleMember -Function Update-CMDomainHSM #/v1/domains/{id} - Update (patch)
Export-ModuleMember -Function Remove-CMDomain #/v1/domains/{id} - Delete (delete) 

#`#/v1/domains/{id}/keks + 
#`#/v1/domains/{id}/keks/{kekID} 
#`#/v1/domains/{id}/rotate-kek 
#`#/v1/domains/{id}/retry-rotate-kek
Export-ModuleMember -Function Find-CMDomainKEKS #/v1/domains/{id}/keks - Get (get)
Export-ModuleMember -Function Get-CMDomainKEK #/v1/domains/{id}/keks/{kekID} - Get (get)
Export-ModuleMember -Function Update-CMDomainRotateKEK #/v1/domains/{id}/rotate-kek - Get (get)
                             #Update-CMDomainKEK -retry #/v1/domains/{id}/retry-kek-rotation - Get (get)

#`#/v1/domains/domain-syslog-redirection/enable + /disable + /status
Export-ModuleMember -Function Get-CMDomainSyslogRedirection #/v1/domains/domain-syslog-redirection/status - Get (get)
Export-ModuleMember -Function Update-CMDomainSyslogRedirection #/v1/domains/domain-syslog-redirection/enable or disable - Enable/Diable (post)
