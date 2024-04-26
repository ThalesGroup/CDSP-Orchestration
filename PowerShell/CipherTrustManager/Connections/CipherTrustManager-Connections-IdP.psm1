#######################################################################################################################
# File:             CipherTrustManager-Connections-IdP.psm1                                                           #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/usermgmt/connections"
$target_uri_test = "/usermgmt/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections IdP Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections IdP Module"
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


#This project mirrors the "Connections: Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/Connections) for the creation of Identity Providers for CM Authentication

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/"
#"#/v1/usermgmt/connections/ - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager IdP Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/Connections).   
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .PARAMETER sort
        The field, or fields, to order the results by. This should be a comma-delimited list of properties.
        For example, "name,-createdAt" .. will sort the results first by 'name', ascending, then by 'createdAt', descending.
    .PARAMETER strategy
        Search for connection Identity Provider type:
            -ldap
            -oidc
    .EXAMPLE
        PS> Find-CMIdPConnections -strategy ldap
        Returns a list of all LDAP Identity Providers
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMIdPConnections {
    param
    (
        [Parameter()] [int] $skip,
        [Parameter()] [int] $limit,
        [Parameter()] [string] $sort,
        [Parameter()] [ValidateSet("ldap","oidc")] [string] $strategy
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all LDAP Connections in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
    if ($strategy) {
        $endpoint += "?strategy="
        $firstset = $true
        $endpoint += $strategy
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
    Write-Debug "List of all CM Identity Provider Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/"
#"#/v1/usermgmt/connections/ - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager LDAP Connection. 
    .DESCRIPTION
        Creates a new LDAP connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER disable_auto_create
        Enable flag to disable automatic creation of a user when the user logs in via LDAP or OIDC. By default, a CM user is created when a user logs in using LDAP or OIDC credentials. Setting this flag will not allow an unknown user to login, the user will need to be created manually before being allowed to login.

        Default: false
    .PARAMETER root_dn
        Starting point to use when searching for users.
    .PARAMETER server_url
        LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER uid_field
        Attribute inside the user object which contains the user id.
        Default: sAMAccountName
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users. This value can be left empty to disable group support for this connection.
    .PARAMETER bind_pass
        Password for the Bind DN object. This value can be left empty to disable group support for this connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection
    .PARAMETER group_filter
        REQUIRED FOR GROUP MAPPING: Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains the group identifier (name). This value can be left empty to disable group support for this connection.
        
        For example:
        In a standard Windows AD Schema, if "cn" is used for this parameter it will return the groups short/friendly/display name. Or if "distinguishedName" (not dn) is used, it will return the group's full Distinguished Name. 
    .PARAMETER group_member_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains group membership information, basically which users are members of the group. This value can be left empty to disable group support for this connection.
    .PARAMETER guid_field
        Attribute inside the group object which contains the globally unique identifier of the group. On bind, if guid_field is not provided, it will default to whatever is in uid_field. However, on uid_field update, guid_field will not update automatically.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER root_cas
        (Optional) CA certificate in PEM format.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER root_ca_file
        (Optional) Specify the filename for a PEM certificate for LDAPS CA certificate. 
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_field
        Attribute inside the user object which contains the user distingushed name. If user_dn_field is not provided, an attempt is made to determine default value based on uid_field. If uid_field is provided as sAMAccountName, Active Directory configuration is assumed and 'distingushedName' is used as default for user_dn_field. Otherwise, it will default to 'dn'.

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_field" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_field" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .EXAMPLE
        PS> New-CMIdPConnectionLDAP -name contoso.com -root_dn "DC=contoso,DC=com" -server_url "ldap://mydc.contoso.com" -uid_field "sAMAccountName" -bind_dn "CN=ldap_bind,OU=MyUsers,DC=contoso,DC=com" -bind_pass "Thales123!" -group_base_dn "DC=contoso,DC=com" -group_filter "(objectClass=Group)" -group_id_field "cn" -group_member_field "member"
    .EXAMPLE
        PS> New-CMIdPConnectionLDAP -name contoso.com -root_dn "DC=contoso,DC=com" -server_url "ldaps://mydc.contoso.com" -uid_field "sAMAccountName" -root_ca_file 'C:\temp\mydc-root.cer' -bindsecurecredentials $bindcreds -group_base_dn "DC=contoso,DC=com" -group_filter "(objectClass=Group)" -group_id_field "cn" -group_member_field "member"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMIdPConnectionLDAP{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $root_dn,
        [Parameter(Mandatory)] [string] $server_url,
        [Parameter()] [string] $uid_field="sAMAccountName",
        [Parameter()] [switch] $disable_auto_create,
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_field,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $guid_field,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_field,
        [Parameter()] [string[]] $root_cas,
        [Parameter()] [string] $root_ca_file,
        [Parameter()] [switch] $insecure_skip_verify
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an LDAP IdP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"          = $name
        "strategy"      = "ldap"
        "ldap_options"  = @{}
    }

    $body.ldap_options.add("root_dn",$root_dn)
    $body.ldap_options.add("server_url",$server_url)
    $body.ldap_options.add("uid_field",$uid_field)

    if ($server_url.Substring(4,1) -eq "s"){
        if(!$root_cas -and !$root_ca_file){ 
            return "Missing LDAPS Certificate. Please try again."
        }
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $body.ldap_options.add("root_cas",$root_cas)
        }elseif($root_cas){
            $body.ldap_options.add("root_cas",$root_cas)
        }
    }

    # Optional Parameters

    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $body.ldap_options.add('bind_dn', $bindsecurecredentials.username)
        $body.ldap_options.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $body.ldap_options.add('bind_dn', $bind_dn)}
        if($bind_pass){ $body.ldap_options.add('bind_password', $bind_pass)}
    }
    
    if($group_base_dn){ $body.ldap_options.add("group_base_dn",$group_base_dn) }
    if($group_filter){ $body.ldap_options.add("group_filter",$group_filter) }
    if($group_id_field){ $body.ldap_options.add("group_id_field",$group_id_field) }
    if($group_member_field){ $body.ldap_options.add("group_member_field",$group_member_field) }
    if($guid_field){ $body.ldap_options.add("guid_field",$guid_field) }
    if($search_filter){ $body.ldap_options.add("search_filter",$search_filter) }
    if($user_dn_field){ $body.ldap_options.add("user_dn_field",$user_dn_field) }
    if($insecure_skip_verify){ $body.ldap_options.add("insecure_skip_verify",[bool]$true) }

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

#Connection Manager - OIDC Connections
#"#/v1/connectionmgmt/services/oidc/connections"
#"#/v1/connectionmgmt/services/oidc/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager OIDC Connection. 
    .DESCRIPTION
        Creates a new OIDC connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER client_id
        OIDC Client ID of the Connection
    .PARAMETER client_secret
        Secret value for the OIDC Connection
    .PARAMETER clientsecureinfo
        PS Credential object containing the Client ID and secret values for the OIDC Connection 
    .PARAMETER redirect_uris
        Set of allowed URIs to redirect to after finished authentication to the external identity provider (authorization server).

        These URIs should match the Redirection URIs values for the client pre-registered at the OpenID Provider. The Redirection URI MUST NOT use the http scheme.

        Typically https://ciphertrust-manager-host/api/v1/auth/oidc-callback where 'ciphertrust-manager-host' should be updated to the hostname of your server.
        
        An entry is required for EACH node in a CIpherTrust Manager cluster.

    .PARAMETER discovery_uri
        URI to the well-known configuration endpoint of the external identity provider. External ID Provider settings such as authorization URI and public signing keys will be auto-downloaded from this URI.
    .PARAMETER flow_type
        Can be an one of "implicit" or "authorization_code".
        Default value is "implicit".
    .PARAMETER groups_claim
        The claim field name to extract group membership from in the OIDC ID Token. Works in conjunction with Group Maps. If unspecified it default to 'groups'.
    .EXAMPLE
        PS> New-CMIdPConnectionOIDC -name ThalesSTA -client_id cfae912f-5b09-4cc1-85b1-e754f434f985 -client_secret 1babc971-154b-4b1b-8f74-008747fea882 -discovery_uri "https://idp.us.safenetid.com/auth/realms/0F512MZXMS-STA/.well-known/openid-configuration" -redirect_uris "https://{cm-node-1}/api/v1/auth/oidc-callback","https://{cm-node-2}/api/v1/auth/oidc-callback"
    .EXAMPLE
        PS> New-CMIdPConnectionOIDC -name ThalesSTA -clientsecureinfo $clientinfo -discovery_uri "https://{oauth-provider-hostname}/.well-known/openid-configuration" -redirect_uris "https://cm-node1/api/v1/auth/oidc-callback","https://cm-node2/api/v1/auth/oidc-callback"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMIdPConnectionOIDC{
    param(
        [Parameter(Mandatory,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $discovery_uri,
        [Parameter()] [string[]] $redirect_uris,
        [Parameter()] [string] $client_id,
        [Parameter()] [string] $client_secret,
        [Parameter()] [pscredential] $clientsecureinfo,
        [Parameter()] [ValidateSet("implicit","authorization_flow")] [string] $flow_type,
        [Parameter()] [string] $groups_claim
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an OIDC IdP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"      = $name
        "strategy"  = "oidc"
        "oidc_options" = @{}
    }

    if($clientsecureinfo){
        Write-Debug "What is my credential client_id? $($clientsecureinfo.username)" 
        Write-debug "What is my credential client_secret? $($clientsecureinfo.password | ConvertFrom-SecureString)"
        $body.oidc_options.add('client_id', $clientsecureinfo.username)
        $body.oidc_options.add('client_secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientsecureinfo.password)))
    }else{
        if($client_id){ $body.oidc_options.add('client_id', $client_id) }
        if($client_secret){ $body.oidc_options.add('client_secret', $client_secret) }
    }
    
    if($redirect_uris){ 
        $body.oidc_options.add("redirect_uris",$redirect_uris)
    }else{ 
        return "Missing Callback URLs. Please try again." }
    if($discovery_uri) { $body.oidc_options.add('discovery_uri', $discovery_uri) }
    if($flow_type){ $body.oidc_options.add("flow_type",$flow_type) }
    if($groups_claim){ $body.oidc_options.add("groups_claim",$groups_claim) }

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




#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}"
#"#/v1/usermgmt/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager Identity Provider (IdP) Connection
    .DESCRIPTION
        Retriving the full list of Identity Provider (IdP) Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the Identity Provider (IdP) connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMIdPConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMIdPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMIdPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to retrive IdP Connection Details"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
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

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}"
#"#/v1/usermgmt/connections/{id} - patch"

<#
    .SYNOPSIS
        Update an existing CipherTrust Manager LDAP Connection. 
    .DESCRIPTION
        Update an existing LDAP connection. 
    .PARAMETER name
        The complete name of the Identity Provider (IdP) connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .PARAMETER disable_auto_create
        Enable flag to disable automatic creation of a user when the user logs in via LDAP or OIDC. By default, a CM user is created when a user logs in using LDAP or OIDC credentials. Setting this flag will not allow an unknown user to login, the user will need to be created manually before being allowed to login.

        Default: false
    .PARAMETER root_dn
        REQUIRED: Starting point to use when searching for users.
    .PARAMETER server_url
        REQUIRED: LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER uid_field
        Attribute inside the user object which contains the user id.
        Default: sAMAccountName
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users. This value can be left empty to disable group support for this connection.
    .PARAMETER bind_pass
        Password for the Bind DN object. This value can be left empty to disable group support for this connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection
    .PARAMETER group_filter
        REQUIRED FOR GROUP MAPPING: Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains the group identifier (name). This value can be left empty to disable group support for this connection.
        
        For example:
        In a standard Windows AD Schema, if "cn" is used for this parameter it will return the groups short/friendly/display name. Or if "distinguishedName" (not dn) is used, it will return the group's full Distinguished Name. 
    .PARAMETER group_member_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains group membership information, basically which users are members of the group. This value can be left empty to disable group support for this connection.
    .PARAMETER guid_field
        Attribute inside the group object which contains the globally unique identifier of the group. On bind, if guid_field is not provided, it will default to whatever is in uid_field. However, on uid_field update, guid_field will not update automatically.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER root_cas
        (Optional) CA certificate in PEM format.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER root_ca_file
        (Optional) Specify the filename for a PEM certificate for LDAPS CA certificate. 
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_field
        Attribute inside the user object which contains the user distingushed name. If user_dn_field is not provided, an attempt is made to determine default value based on uid_field. If uid_field is provided as sAMAccountName, Active Directory configuration is assumed and 'distingushedName' is used as default for user_dn_field. Otherwise, it will default to 'dn'.

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_field" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_field" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .EXAMPLE
        PS> New-CMIdPConnectionLDAP -name contoso.com -root_dn "DC=contoso,DC=com" -server_url "ldap://mydc.contoso.com" -uid_field "sAMAccountName" -bind_dn "CN=ldap_bind,OU=MyUsers,DC=contoso,DC=com" -bind_pass "Thales123!" -group_base_dn "DC=contoso,DC=com" -group_filter "(objectClass=Group)" -group_id_field "cn" -group_member_field "member"
    .EXAMPLE
        PS> New-CMIdPConnectionLDAP -name contoso.com -root_dn "DC=contoso,DC=com" -server_url "ldaps://mydc.contoso.com" -uid_field "sAMAccountName" -root_ca_file 'C:\temp\mydc-root.cer' -bindsecurecredentials $bindcreds -group_base_dn "DC=contoso,DC=com" -group_filter "(objectClass=Group)" -group_id_field "cn" -group_member_field "member"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMIdPConnectionLDAP{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory)] [string] $root_dn,
        [Parameter(Mandatory)] [string] $server_url,
        [Parameter()] [string] $uid_field="sAMAccountName",
        [Parameter()] [switch] $disable_auto_create,
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_field,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $guid_field,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_field,
        [Parameter()] [string[]] $root_cas,
        [Parameter()] [string] $root_ca_file,
        [Parameter()] [switch] $insecure_skip_verify
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating an LDAP IdP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    # Mandatory Parameters
    $body = [ordered] @{
        "strategy"      = "ldap"
        "ldap_options"  = @{}
    }

    $body.ldap_options.add("root_dn",$root_dn)
    $body.ldap_options.add("server_url",$server_url)
    $body.ldap_options.add("uid_field",$uid_field)

    if ($server_url.Substring(4,1) -eq "s"){
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $body.ldap_options.add("root_cas",$root_cas)
        }elseif($root_cas){
            $body.ldap_options.add("root_cas",$root_cas)
        }
    }

    # Optional Parameters

    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $body.ldap_options.add('bind_dn', $bindsecurecredentials.username)
        $body.ldap_options.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $body.ldap_options.add('bind_dn', $bind_dn)}
        if($bind_pass){ $body.ldap_options.add('bind_password', $bind_pass)}
    }
    
    if($group_base_dn){ $body.ldap_options.add("group_base_dn",$group_base_dn) }
    if($group_filter){ $body.ldap_options.add("group_filter",$group_filter) }
    if($group_id_field){ $body.ldap_options.add("group_id_field",$group_id_field) }
    if($group_member_field){ $body.ldap_options.add("group_member_field",$group_member_field) }
    if($guid_field){ $body.ldap_options.add("guid_field",$guid_field) }
    if($search_filter){ $body.ldap_options.add("search_filter",$search_filter) }
    if($user_dn_field){ $body.ldap_options.add("user_dn_field",$user_dn_field) }
    if($insecure_skip_verify){ $body.ldap_options.add("insecure_skip_verify",[bool]$true) }

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
    Write-Debug "Connection created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}"
#"#/v1/usermgmt/connections/{id}" - patch"

<#
    .SYNOPSIS
        Update an existing CipherTrust Manager OIDC Connection. 
    .DESCRIPTION
        Update an existing OIDC connection. 
    .PARAMETER name
        The complete name of the Identity Provider (IdP) connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .PARAMETER client_id
        REQUIRED: OIDC Client ID of the Connection
    .PARAMETER client_secret
        Secret value for the OIDC Connection
    .PARAMETER clientsecureinfo
        PS Credential object containing the Client ID and secret values for the OIDC Connection 
    .PARAMETER redirect_uris
        REQUIRED: Set of allowed URIs to redirect to after finished authentication to the external identity provider (authorization server).

        These URIs should match the Redirection URIs values for the client pre-registered at the OpenID Provider. The Redirection URI MUST NOT use the http scheme.

        Typically https://ciphertrust-manager-host/api/v1/auth/oidc-callback where 'ciphertrust-manager-host' should be updated to the hostname of your server.
        
        An entry is required for EACH node in a CIpherTrust Manager cluster.

    .PARAMETER discovery_uri
        URI to the well-known configuration endpoint of the external identity provider. External ID Provider settings such as authorization URI and public signing keys will be auto-downloaded from this URI.
    .PARAMETER flow_type
        Can be an one of "implicit" or "authorization_code".
        Default value is "implicit".
    .PARAMETER groups_claim
        The claim field name to extract group membership from in the OIDC ID Token. Works in conjunction with Group Maps. If unspecified it default to 'groups'.
    .PARAMETER refresh
        Update authorization_uri and jwks from issuer's well-known configuration
    .EXAMPLE
        PS> Update-CMIdPConnectionOIDC -name ThalesSTA -client_id cfab123f-5b09-4cc1-85b1-e754f123f985 -redirect_uris "https://10.0.0.1/api/v1/auth/oidc-callback","https://10.0.0.2/api/v1/auth/oidc-callback"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Update-CMIdPConnectionOIDC{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter()] [string] $discovery_uri,
        [Parameter()] [string[]] $redirect_uris,
        [Parameter()] [string] $client_id,
        [Parameter()] [string] $client_secret,
        [Parameter()] [pscredential] $clientsecureinfo,
        [Parameter()] [ValidateSet("implicit","authorization_flow")] [string] $flow_type,
        [Parameter()] [string] $groups_claim,
        [Parameter()] [switch] $refresh
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating an OIDC IdP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }

    if($refresh){
        $endpoint += "/refresh"
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
            if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
                Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
            }
            elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::UnprocessableEntity) {
                Write-Error "Error $([int]$StatusCode) $($StatusCode): $($apiError.Message)" -ErrorAction Stop
            }
                else {
                Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
            }
        }

        return $response
    
    }
    # Mandatory Parameters
    $body = [ordered] @{
        "strategy"  = "oidc"
        "oidc_options" = @{}
    }
    
    if($redirect_uris){ 
        $body.oidc_options.add("redirect_uris",$redirect_uris)
    }else{ 
        return "Missing Callback URLs. Please try again." }

    if($clientsecureinfo){
        Write-Debug "What is my credential client_id? $($clientsecureinfo.username)" 
        Write-debug "What is my credential client_secret? $($clientsecureinfo.password | ConvertFrom-SecureString)"
        $body.oidc_options.add('client_id', $clientsecureinfo.username)
        $body.oidc_options.add('client_secret', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientsecureinfo.password)))
    }else{
        if($client_id){ $body.oidc_options.add('client_id', $client_id) }
        if($client_secret){ $body.oidc_options.add('client_secret', $client_secret) }
    }

    if($discovery_uri) { $body.oidc_options.add('discovery_uri', $discovery_uri) }
    if($flow_type){ $body.oidc_options.add("flow_type",$flow_type) }
    if($groups_claim){ $body.oidc_options.add("groups_claim",$groups_claim) }

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
        $response = Invoke-RestMethod  -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' -ErrorVariable apiError
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
    Write-Debug "Connection updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}"
#"#/v1/usermgmt/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager Identity Provider (IdP) Connection
    .DESCRIPTION
        Delete a CipherTrust Manager Identity Provider (IdP) Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the Identity Provider (IdP) connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMIdPConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLDAPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -force
        Using the id of the connection. And bypass confirmations.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMIdPConnection{
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

    Write-Debug "Preparing to remove LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
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

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}"
#"#/v1/usermgmt/connections/{id} - delete"

<#
    .SYNOPSIS
        LDAP-ONLY: Delete a CipherTrust Manager Identity Provider (IdP) Connection
    .DESCRIPTION
        LDAP-ONLY: Deletes the specified connection to a bound LDAP server. Delete sub-domain groupmaps and users associated with the LDAP connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the LDAP connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMIdPConnectionLDAPInUse -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMIdPConnectionLDAPInUse -id "27657168-c3fb-47a7-9cd7-72d69d48d48b" -force
        Using the id of the connection. And bypass confirmations.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMIdPConnectionLDAPInUse{
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

    Write-Debug "Preparing to remove LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
        $endpoint += "/" + $id + "/delete"
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
        Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json' | Out-Null
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



#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters and a user account against a set of LDAP conneciton parameters.This does not create a persistent connection.
    .PARAMETER root_dn
        REQUIRED: Starting point to use when searching for users.
    .PARAMETER server_url
        REQUIRED: LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER uid_field
        Attribute inside the user object which contains the user id.
        Default: sAMAccountName
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users. This value can be left empty to disable group support for this connection.
    .PARAMETER bind_pass
        Password for the Bind DN object. This value can be left empty to disable group support for this connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection
    .PARAMETER group_filter
        REQUIRED FOR GROUP MAPPING: Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains the group identifier (name). This value can be left empty to disable group support for this connection.
        
        For example:
        In a standard Windows AD Schema, if "cn" is used for this parameter it will return the groups short/friendly/display name. Or if "distinguishedName" (not dn) is used, it will return the group's full Distinguished Name. 
    .PARAMETER group_member_field
        REQUIRED FOR GROUP MAPPING: Attribute inside the group object which contains group membership information, basically which users are members of the group. This value can be left empty to disable group support for this connection.
    .PARAMETER guid_field
        Attribute inside the group object which contains the globally unique identifier of the group. On bind, if guid_field is not provided, it will default to whatever is in uid_field. However, on uid_field update, guid_field will not update automatically.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER root_cas
        (Optional) CA certificate in PEM format.
        While it can be used from the command-line, the switch is best used when running automation scripts. Populate a variable with the PEM-formatted certificate then pass the variable to the command.
    .PARAMETER root_ca_file
        (Optional) Specify the filename for a PEM certificate for LDAPS CA certificate. 
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_field
        Attribute inside the user object which contains the user distingushed name. If user_dn_field is not provided, an attempt is made to determine default value based on uid_field. If uid_field is provided as sAMAccountName, Active Directory configuration is assumed and 'distingushedName' is used as default for user_dn_field. Otherwise, it will default to 'dn'.

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_field" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_field" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .PARAMETER test_user
        Username to test the connection with.
    .PARAMETER test_pass
        Password that authenticates the username.
    .PARAMETER securetestcreds
        PS Credential object containing the User Credentials for testing a LDAP connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMIdPLDAPConnParameters{
    param(
        [Parameter(Mandatory)] [string] $root_dn,
        [Parameter(Mandatory)] [string] $server_url,
        [Parameter()] [string] $uid_field="sAMAccountName",
        [Parameter()] [switch] $disable_auto_create,
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_field,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $guid_field,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_field,
        [Parameter()] [string[]] $root_cas,
        [Parameter()] [string] $root_ca_file,
        [Parameter()] [switch] $insecure_skip_verify,
        [Parameter()] [string] $test_user, 
        [Parameter()] [string] $test_pass, 
        [Parameter()] [pscredential] $securetestcreds


    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing LDAP Connection details."
    $endpoint = $CM_Session.REST_URL + $target_uri_test
    Write-Debug "Endpoint: $($endpoint)"


    # Mandatory Parameters
    $body = [ordered] @{
        "credentials"   = @{}
    }

    $connection = [ordered] @{
        "strategy"  = "ldap"
    }

    $body.add("connection",$connection)    

    if(!$test_user -and !$test_pass -and !$securetestcreds) { return "Missing credentials to test with. Please try again."}
    
    if($securetestcreds){
        Write-Debug "What is my credential bind_dn? $($securetestcreds.username)" 
        Write-debug "What is my credential password? $($securetestcreds.password | ConvertFrom-SecureString)"
        $body.credentials.add('username', $securetestcreds.username)
        $body.credentials.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securetestcreds.password)))

    }else{
        if($test_user){ $body.credentials.add('username', $test_user)}
        if($test_pass){ $body.credentials.add('password', $test_pass)}
    }

    $connection_options = [ordered] @{}

    if ($server_url.Substring(4,1) -eq "s"){
        if(!$root_cas -and !$root_ca_file){ 
            return "Missing LDAPS Certificate. Please try again."
        }
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $connection_options.add("root_cas",$root_cas)
        }elseif($root_cas){
            $connection_options.add("root_cas",$root_cas)
        }
    }

    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $connection_options.add('bind_dn', $bindsecurecredentials.username)
        $connection_options.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $connection_options.add('bind_dn', $bind_dn)}
        if($bind_pass){ $connection_options.add('bind_password', $bind_pass)}
    }

    if($root_dn){ $connection_options.add("root_dn",$root_dn) }
    if($server_url){ $connection_options.add("server_url",$server_url) }
    if($uid_field){ $connection_options.add("uid_field",$uid_field) }
    if($group_base_dn){ $connection_options.add("group_base_dn",$group_base_dn) }
    if($group_dn_attribute){ $connection_options.add("group_dn_attribute",$group_dn_attribute) }
    if($group_filter){ $connection_options.add("group_filter",$group_filter) }
    if($group_id_field){ $connection_options.add("group_id_attribute",$group_id_field) }
    if($group_member_field){ $connection_options.add("group_member_field",$group_member_field) }
    if($group_name_attribute){ $connection_options.add("group_name_attribute",$group_name_attribute) }
    if($search_filter){ $connection_options.add("search_filter",$search_filter) }
    if($user_dn_attribute){ $connection_options.add("user_dn_attribute",$user_dn_attribute) }
    if($user_member_field){ $connection_options.add("user_member_field",$user_member_field) }
    if($insecure_skip_verify){ $connection_options.add("insecure_skip_verify",[bool]$true) }

    Write-Debug "These are the connection Options:`n$([array]$connection_options | Out-String)"
    
    $body.connection.add("options",$connection_options)

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
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::UnprocessableEntity) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Invalid JSON.`n$($apiError.Message)" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Connection tested"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}  

#Connection Manager - Connections (IdP)
#"#/v1/usermgmt/connections/{id}/users/"
#"#/v1/usermgmt/connections/{id}/users/ - get"
#"#/v1/usermgmt/connections/{id}/users/{user_id} - get"

<#
    .SYNOPSIS
        Returns a list of users belonging to an IdP connection.
    .DESCRIPTION
        Returns a list of users belonging to an IdP connection.
    .PARAMETER connection_name
        The complete name of the Identity Provider (IdP) connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMIdPConnections cmdlet to find the appropriate id value.
    .PARAMETER username
        Optional: Filter by the user's username. Note: OIDC Users do not have a standard username.
    .PARAMETER email
        Optional: Filter by the user's email address.
    .PARAMETER user_id
        Optional: User's full user id. Using <ConnectionName>|<username> format. 
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Get-CMIdPConnectionUsers -name "contoso.com"
        Use the complete name of the connection.
    .EXAMPLE
        PS> Get-CMIdPConnectionUsers -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMIdPConnectionUsers{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName)]
        [string] $id,
        [Parameter(ValueFromPipelineByPropertyName)] 
        [string] $username,
        [Parameter(ValueFromPipelineByPropertyName)] 
        [string] $email,
        [Parameter()] [int] $skip,
        [Parameter()] [int] $limit,
        [Parameter(ValueFromPipelineByPropertyName)] 
        [string] $user_id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Preparing to retrive IdP Connection User List"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"


    if($id){
        $endpoint += "/" + $id + "/users/"   
    }elseif($name){ 
        $idpList = Find-CMIdPConnections
        $targetIndex = $idpList.resources.name.IndexOf($name)
        Write-Debug "Target Index is $($targetIndex)"
        if($targetIndex -eq -1){ return "Connection not found."}
        $id = $idpList.resources[$targetIndex].id
        Write-Debug "ID of Target Connection is $($id)" 
        $endpoint += "/" + $id + "/users"
    }else{
        return "Missing Connection Identifier."
    }

    if($username -or $email -or $skip -or $limit){
        #Set query
        $firstset = $false
        if ($username) {
            $endpoint += "?username="
            $firstset = $true
            $endpoint += $username
        }
        if ($email) {
            if ($firstset) {
                $endpoint += "&email="
            }
            else {
                $endpoint += "?email="
                $firstset = $true
            }
            $endpoint += $email
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
    }elseif($user_id){
        $endpoint += "/" + $user_id
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


####
# Export Module Members
####
#Connection Manager - Connections (IdP)
#/v1/usermgmt/connections/"

Export-ModuleMember -Function Find-CMIdPConnections #/v1/usermgmt/connections/ - get"
Export-ModuleMember -Function New-CMIdPConnectionLDAP #/v1/usermgmt/connections/ - post"
Export-ModuleMember -Function New-CMIdPConnectionOIDC #/v1/usermgmt/connections/ - post"

#Connection Manager - Connections (IdP)
#/v1/usermgmt/connections/{id}"
Export-ModuleMember -Function Get-CMIdPConnection #/v1/usermgmt/connections/{id} - get"
Export-ModuleMember -Function Update-CMIdPConnectionLDAP #/v1/usermgmt/connections/{id} - patch"
Export-ModuleMember -Function Update-CMIdPConnectionOIDC #/v1/usermgmt/connections/{id} - patch or post"
Export-ModuleMember -Function Remove-CMIdPConnection #/v1/usermgmt/connections/{id} - delete"
Export-ModuleMember -Function Remove-CMIdPConnectionLDAPInUse #/v1/usermgmt/connections/{id} - post"
Export-ModuleMember -Function Get-CMIdPConnectionUsers #/v1/usermgmt/connections/{id}/users/ - get


#Connection Manager - Connections (IdP)
#/v1/connectionmgmt/services/ldap/connection-test"
Export-ModuleMember -Function Test-CMIdPLDAPConnParameters #/v1/connectionmgmt/services/ldap/connection-test - post"




