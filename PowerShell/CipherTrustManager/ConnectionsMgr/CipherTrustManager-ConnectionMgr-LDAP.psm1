#######################################################################################################################
# File:             CipherTrustManager-ConnectionMgr-LDAP.psm1                                                        #
# Author:           Rick Leon, Professional Services                                                                  #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/connectionmgmt/services/ldap/connections"
$target_uri_test = "/connectionmgmt/services/ldap/connection-test"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - Connections LDAP Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - Connections LDAP Module"
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


#This project mirrors the "Connection Manager - LDAP Connections" section of the API Playground of CM (/playground_v2/api/Connection Manager/LDAP Connections)

#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections"
#"#/v1/connectionmgmt/services/ldap/connections - get"

<#
    .SYNOPSIS
        List all CipherTrust Manager LDAP Connections
    .DESCRIPTION
        Returns a list of all connections. The results can be filtered using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters. 
        For additional information on query parameters consult the API Playground (https://<CM_Appliance>/playground_v2/api/Connection Manager/LDAP Connections).   
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
    .PARAMETER server_url
        Filter the results based on the LDAP Server URL.
    .PARAMETER base_dn
        Filter the results based on the LDAP Base Distinguished Name value.
    .PARAMETER user_login_attribute
        Filter the results based on the User Login Attribute (sAMAccountName or dn)
    .PARAMETER group_base_dn
        Filter the results based on the Group Base Distinguished Name value.
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
        PS> Find-CMLDAPConnections -name tar*
        Returns a list of all Connections whose name starts with "tar" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMLDAPConnections {
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
        [Parameter()] [string] $server_url,
        [Parameter()] [string] $base_dn,
        [Parameter()] [string] $user_login_attribute,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $meta_contains, 
        [Parameter()] [string] $createdBefore, 
        [Parameter()] [string] $createdAfter, 
        [Parameter()] [string] $last_connection_ok, 
        [Parameter()] [string] $last_connection_before, 
        [Parameter()] [string] $last_connection_after
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of all LDAP Connections in CM"
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
    if ($server_url) {
        if ($firstset) {
            $endpoint += "&server_url="
        }
        else {
            $endpoint += "?server_url="
            $firstset = $true
        }
        $endpoint += $server_url
    }
    if ($base_dn) {
        if ($firstset) {
            $endpoint += "&base_dn="
        }
        else {
            $endpoint += "?base_dn="
            $firstset = $true
        }
        $endpoint += $base_dn
    }
    if ($user_login_attribute) {
        if ($firstset) {
            $endpoint += "&user_login_attribute="
        }
        else {
            $endpoint += "?user_login_attribute="
            $firstset = $true
        }
        $endpoint += $user_login_attribute
    }
    if ($group_base_dn) {
        if ($firstset) {
            $endpoint += "&group_base_dn="
        }
        else {
            $endpoint += "?group_base_dn="
            $firstset = $true
        }
        $endpoint += $group_base_dn
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
    Write-Debug "List of all CM LDAP Connections with supplied parameters."
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections"
#"#/v1/connectionmgmt/services/ldap/connections - post"

<#
    .SYNOPSIS
        Create a new CipherTrust Manager LDAP Connection. 
    .DESCRIPTION
        Creates a new LDAP connection. 
    .PARAMETER name
        Unique connection name. This will be used in the future during login to speficy the remote connection. 
    .PARAMETER base_dn
        Starting point to use when searching for users.
    .PARAMETER server_url
        LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER user_login_attribute
        Attribute inside the user object which contains the username used to login with.
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users.
    .PARAMETER bind_password
        Password for the Bind DN object of the LDAP connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_dn_attribute
        Attribute inside the group object which contains the group's distinguished name. When this property is set, it uses the specified attribute to test for group equality. Example: dn, gidNumber
        For example:
        If a groups's LDAP entry has "cn=ship_crew,ou=people,dc=planetexpress,dc=com" and the LDAP configuration has "group_dn_attribute" set to "dn", then LDAP user entry must have membership attribute exactly "cn=ship_crew,ou=people,dc=planetexpress,dc=com", in order for the user to be considered part of group.
    .PARAMETER group_filter
        Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_attribute
        Attribute inside the group object which contains the group identifier (name). This value should be unique and can be left empty to disable group support for this connection. If group_id_attribute is not provided, it will default to 'group_name_attribute'.
    .PARAMETER group_member_field
        Attribute inside the group object which contains group membership information, basically which users are members of the group. Example: member, memberUid This value can be left empty to disable group membership support for this connection.
    .PARAMETER group_name_attribute
        Attribute inside the group object which contains the friendly name of the group.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_attribute
        Attribute inside the user object which contains the user distingushed name. Example: uid, dn

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_attribute" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_attribute" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .PARAMETER user_member_field
        Attribute inside user object which contains user membership information, this gives details about group which user is member of. Example: memberOf, gidNumber. In case, when both user_member_field and group_member_field are provided in the LDAP configuration then by default user_member_field will be chosen.
    .PARAMETER products
        -cte
        -blank for CM LDAP Authentication 
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        e.g. -metadata "red:stop,green:go,blue:ocean"
    .EXAMPLE
        PS> New-CMLDAPConnection -name ricky.local -base_dn "DC=ricky,DC=local" -server_url "ldap://192.168.1.12" -user_login_attribute "sAMAccountName" -bind_dn "CN=ldap_bind,OU=MyUsers,DC=ricky,DC=local" -bind_pass "Thales123!"
    .EXAMPLE
        PS> New-CMLDAPConnection -name ricky.local -base_dn "DC=ricky,DC=local" -server_url "ldaps://lab2019dc.ricky.local:636" -user_login_attribute "sAMAccountName" -root_ca_file 'C:\myfiles\mydc-root.cer' -bindsecurecredentials $bindcreds
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMLDAPConnection{
    param(
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory)] [string] $base_dn,
        [Parameter(Mandatory)] [string] $server_url,
        [Parameter(Mandatory)] [string] $user_login_attribute="sAMAccountName",
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_dn_attribute,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_attribute,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $group_name_attribute,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_attribute,
        [Parameter()] [string] $user_member_field,
        [Parameter()] [string[]] $root_cas,
        [Parameter()] [string] $root_ca_file,
        [Parameter()] [switch] $insecure_skip_verify,
        [Parameter()] [string] $description,
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating an LDAP Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = [ordered] @{
        "name"      = $name
        "base_dn"   = $base_dn
        "server_url" = $server_url
        "user_login_attribute" = $user_login_attribute
        "products"  = @("cte")
    }

    if ($server_url.Substring(4,1) -eq "s"){
        if(!$root_cas -and !$root_ca_file){ 
            return "Missing LDAPS Certificate. Please try again."
        }
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $body.add("root_cas",$root_cas)
        }elseif($root_cas){
            $body.add("root_cas",$root_cas)
        }
    }

    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('bind_dn', $bindsecurecredentials.username)
        $body.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $body.add('bind_dn', $bind_dn)}
        if($bind_pass){ $body.add('bind_password', $bind_pass)}
    }
    
    if($group_base_dn){ $body.add("group_base_dn",$group_base_dn) }
    if($group_dn_attribute){ $body.add("group_dn_attribute",$group_dn_attribute) }
    if($group_filter){ $body.add("group_filter",$group_filter) }
    if($group_id_attribute){ $body.add("group_id_attribute",$group_id_attribute) }
    if($group_member_field){ $body.add("group_member_field",$group_member_field) }
    if($group_name_attribute){ $body.add("group_name_attribute",$group_name_attribute) }
    if($search_filter){ $body.add("search_filter",$search_filter) }
    if($user_dn_attribute){ $body.add("user_dn_attribute",$user_dn_attribute) }
    if($user_member_field){ $body.add("user_member_field",$user_member_field) }
    if($products){ $body.add("products",$products)}
    if($insecure_skip_verify){ $body.add("insecure_skip_verify",[bool]$true) }

    

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


#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections/{id}"
#"#/v1/connectionmgmt/services/ldap/connections/{id} - get"

<#
    .SYNOPSIS
        Get full details on a CipherTrust Manager LDAP Connection
    .DESCRIPTION
        Retriving the full list of LDAP Connections omits certain values. Use this tool to get the complete details.
    .PARAMETER name
        The complete name of the LDAP connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLDAPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Get-CMLDAPConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Get-CMLDAPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMLDAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting details on LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMLDAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLDAPConnections -name $name).resources[0].id 
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

#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections/{id}"
#"#/v1/connectionmgmt/services/ldap/connections/{id} - patch"


<#
    .SYNOPSIS
        Update an existing a new CipherTrust Manager LDAP Connection.
    .DESCRIPTION
        Updates a connection with the given name, ID or URI. The parameters to be updated are specified in the request body.
    .PARAMETER name
        Name of the existing CipherTrust Manager LDAP connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing DSM connection.
    .PARAMETER base_dn
        Starting point to use when searching for users.
    .PARAMETER server_url
        LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER user_login_attribute
        Attribute inside the user object which contains the username used to login with.
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users.
    .PARAMETER bind_password
        Password for the Bind DN object of the LDAP connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_dn_attribute
        Attribute inside the group object which contains the group's distinguished name. When this property is set, it uses the specified attribute to test for group equality. Example: dn, gidNumber
        For example:
        If a groups's LDAP entry has "cn=ship_crew,ou=people,dc=planetexpress,dc=com" and the LDAP configuration has "group_dn_attribute" set to "dn", then LDAP user entry must have membership attribute exactly "cn=ship_crew,ou=people,dc=planetexpress,dc=com", in order for the user to be considered part of group.
    .PARAMETER group_filter
        Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_attribute
        Attribute inside the group object which contains the group identifier (name). This value should be unique and can be left empty to disable group support for this connection. If group_id_attribute is not provided, it will default to 'group_name_attribute'.
    .PARAMETER group_member_field
        Attribute inside the group object which contains group membership information, basically which users are members of the group. Example: member, memberUid This value can be left empty to disable group membership support for this connection.
    .PARAMETER group_name_attribute
        Attribute inside the group object which contains the friendly name of the group.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_attribute
        Attribute inside the user object which contains the user distingushed name. Example: uid, dn

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_attribute" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_attribute" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .PARAMETER user_member_field
        Attribute inside user object which contains user membership information, this gives details about group which user is member of. Example: memberOf, gidNumber. In case, when both user_member_field and group_member_field are provided in the LDAP configuration then by default user_member_field will be chosen.
    .PARAMETER description
        (Optional) Description of the connection.
    .PARAMETER metadata
        (Optional) Optional end-user or service data stored with the connection. Use key/value pairs separated by a semi-colon. Can be a comma-separated list of metadata pairs. 
        Existing meta data can be changed but no keys can be deleted.
        e.g. -metadata "red:stop,green:go,blue:ocean"

        For example: If metadata exists {"red":"stop"} it can be changed to {"red":"fire"), but it cannot be removed.
    .EXAMPLE
        PS> Update-CMLDAPConnection -name contoso.com -bind_dn <newuser> -bind_pass <newpass>
    .EXAMPLE
        PS> Update-CMLDAPConnection -name contoso.com -bindsecurecredentials $newcreds
    .EXAMPLE
        PS> Update-CMLDAPConnections -name MyLDAPConnection -metadata "red:stop,green:go,blue:ocean"
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
function Update-CMLDAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter()] [string] $base_dn,
        [Parameter()] [string] $server_url,
        [Parameter()] [string] $user_login_attribute,
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_dn_attribute,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_attribute,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $group_name_attribute,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_attribute,
        [Parameter()] [string] $user_member_field,
        [Parameter()] [string[]] $root_cas,
        [Parameter()] [string] $root_ca_file,
        [Parameter()] [switch] $insecure_skip_verify,
        [Parameter()] [ValidateSet("cte")] [string] $products=@("cte"),
        [Parameter()] [string] $description, 
        [Parameter()] [string[]] $metadata
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating details on LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id        
    }elseif($name){ 
        if((Find-CMLDAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLDAPConnections -name $name).resources[0].id 
        $endpoint += "/" + $id
    }else{
        return "Missing Connection Identifier."
    }
    
    # Mandatory Parameters
    $body = [ordered] @{}
    
    if($server_url){ $body.add("server_url",$server_url) }
    if($base_dn){ $body.add('ase_dn', $base_dn)}
    if($user_login_attribute){ $body.add("user_login_attribute",$user_login_attribute) }


    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('bind_dn', $bindsecurecredentials.username)
        $body.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $body.add('bind_dn', $bind_dn)}
        if($bind_pass){ $body.add('bind_password', $bind_pass)}
    }
    
    if($group_base_dn){ $body.add("group_base_dn",$group_base_dn) }
    if($group_dn_attribute){ $body.add("group_dn_attribute",$group_dn_attribute) }
    if($group_filter){ $body.add("group_filter",$group_filter) }
    if($group_id_attribute){ $body.add("group_id_attribute",$group_id_attribute) }
    if($group_member_field){ $body.add("group_member_field",$group_member_field) }
    if($group_name_attribute){ $body.add("group_name_attribute",$group_name_attribute) }
    if($search_filter){ $body.add("search_filter",$search_filter) }
    if($user_dn_attribute){ $body.add("user_dn_attribute",$user_dn_attribute) }
    if($user_member_field){ $body.add("user_member_field",$user_member_field) }
    if($products){ $body.add("products",$products)}
    if($insecure_skip_verify){ $body.add("insecure_skip_verify",[bool]$true) }

    if ($server_url.Substring(4,1) -eq "s"){
        if(!$root_cas -and !$root_ca_file){ 
            return "Missing LDAPS Certificate. Please try again."
        }
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $body.add("root_cas",$root_cas)
        }elseif($root_cas){
            $body.add("root_cas",$root_cas)
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


#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections/{id}"
#"#/v1/connectionmgmt/services/ldap/connections/{id} - delete"

<#
    .SYNOPSIS
        Delete a CipherTrust Manager LDAP Connection
    .DESCRIPTION
        Delete a CipherTrust Manager LDAP Connection. USE EXTREME CAUTION. This cannot be undone.
    .PARAMETER name
        The complete name of the LDAP connection. This parameter is case-sensitive.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLDAPConnections cmdlet to find the appropriate id value.
    .PARAMETER force
        Bypass all deletion confirmations. USE EXTREME CAUTION.
    .EXAMPLE
        PS> Remove-CMLDAPConnection -name "contoso.com"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Remove-CMLDAPConnection -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Using the id of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMLDAPConnection{
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
        if((Find-CMLDAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLDAPConnections -name $name).resources[0].id 
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
    
#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections/{id}"
#"#/v1/connectionmgmt/services/ldap/connections/{id}/test - post"

<#
    .SYNOPSIS
        Test existing connection.
    .DESCRIPTION
        Tests that an existing connection with the given name, ID, or URI reaches the DSM Cluster. If no connection parameters are provided in request, the existing parameters will be used. This does not modify a persistent connection.
    .PARAMETER name
        Name of the existing CipherTrust Manager LDAP connection.
    .PARAMETER id
        CipherTrust Manager "id" value of the existing LDAP connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMLDAPConnection{
    param(
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $id, 
        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
        [string] $name 
    )

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Testing LDAP Connection"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    if($id){
        $endpoint += "/" + $id + "/test"    
    }elseif($name){ 
        if((Find-CMLDAPConnections -name $name).total -eq 0){ return "Connection not found."}
        $id = (Find-CMLDAPConnections -name $name).resources[0].id 
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


#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connection-test - post"

<#
    .SYNOPSIS
        Test connection parameters for a non-existent connection. 
    .DESCRIPTION
        Tests that the connection parameters can be used to reach the DSM account. This does not create a persistent connection.
    .PARAMETER base_dn
        Starting point to use when searching for users.
    .PARAMETER server_url
        LDAP URL for your server. (e.g. ldap://172.16.2.2:3268)
    .PARAMETER user_login_attribute
        Attribute inside the user object which contains the username used to login with.
    .PARAMETER bind_dn
        Object which has permission to search under the root DN for users.
    .PARAMETER bind_password
        Password for the Bind DN object of the LDAP connection.
    .PARAMETER bindsecurecredentials
        PS Credential object containing the BIND User and Password for the LDAP connection.
    .PARAMETER group_base_dn
        Starting point to use when searching for groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_dn_attribute
        Attribute inside the group object which contains the group's distinguished name. When this property is set, it uses the specified attribute to test for group equality. Example: dn, gidNumber
        For example:
        If a groups's LDAP entry has "cn=ship_crew,ou=people,dc=planetexpress,dc=com" and the LDAP configuration has "group_dn_attribute" set to "dn", then LDAP user entry must have membership attribute exactly "cn=ship_crew,ou=people,dc=planetexpress,dc=com", in order for the user to be considered part of group.
    .PARAMETER group_filter
        Search filter for listing groups. Searching with this filter should only return groups. This value can be left empty to disable group support for this connection.
    .PARAMETER group_id_attribute
        Attribute inside the group object which contains the group identifier (name). This value should be unique and can be left empty to disable group support for this connection. If group_id_attribute is not provided, it will default to 'group_name_attribute'.
    .PARAMETER group_member_field
        Attribute inside the group object which contains group membership information, basically which users are members of the group. Example: member, memberUid This value can be left empty to disable group membership support for this connection.
    .PARAMETER group_name_attribute
        Attribute inside the group object which contains the friendly name of the group.
    .PARAMETER insecure_skip_verify
        Optional flag to disable verifying the server's certficate. It ignores both the operating system's CAs and root_cas if provided. Only applies if the server_url scheme is ldaps.

        Default: false
    .PARAMETER search_filter
        LDAP search filter which can further restrict the set of users who will be allowed to log in.
    .PARAMETER user_dn_attribute
        Attribute inside the user object which contains the user distingushed name. Example: uid, dn

        When this property is set it uses the specified attribute to test for user equality. This primarily affects LDAP group maps. For example:
            -If a user's LDAP entry has "cn: John Doe" and the LDAP configuration has "user_dn_attribute" set to "cn", then the LDAP group entry must have a member attribute that is exactly "John Doe", not "cn=John Doe", in order for the user to be considered part of the group.
            -If a user's LDAP entry has "customDN: cn=John Doe,ou=Users" and the LDAP configuration has "user_dn_attribute" set to "customDN", then the LDAP group entry must have a member attribute that is exactly "cn=John Doe,ou=Users" in order for the user to be considered part of the group.
    .PARAMETER user_member_field
        Attribute inside user object which contains user membership information, this gives details about group which user is member of. Example: memberOf, gidNumber. In case, when both user_member_field and group_member_field are provided in the LDAP configuration then by default user_member_field will be chosen.
    .PARAMETER test_user
        Username to test the connection with.
    .PARAMETER test_pass
        Password that authenticates the username.
    .PARAMETER securetestcreds
        PS Credential object containing the User Credentials for testing a LDAP connection.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Test-CMLDAPConnParameters{
    param(
        [Parameter()] [string] $base_dn,
        [Parameter()] [string] $server_url,
        [Parameter()] [string] $user_login_attribute,
        [Parameter()] [string] $bind_dn, 
        [Parameter()] [string] $bind_pass, 
        [Parameter()] [pscredential] $bindsecurecredentials,
        [Parameter()] [string] $group_base_dn,
        [Parameter()] [string] $group_dn_attribute,
        [Parameter()] [string] $group_filter,
        [Parameter()] [string] $group_id_attribute,
        [Parameter()] [string] $group_member_field,
        [Parameter()] [string] $group_name_attribute,
        [Parameter()] [string] $search_filter,
        [Parameter()] [string] $user_dn_attribute,
        [Parameter()] [string] $user_member_field,
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
        "base_dn"   = $base_dn
        "server_url" = $server_url
        "user_login_attribute" = $user_login_attribute
        "credentials" = @{}
    }

    if(!$test_user -and !$test_pass -and !$securetestcreds) { return "Missing credentials to test with. Please try again."}

    if ($server_url.Substring(4,1) -eq "s"){
        if(!$root_cas -and !$root_ca_file){ 
            return "Missing LDAPS Certificate. Please try again."
        }
        if($root_ca_file){
            $root_cas = Get-Content -Path $root_ca_file -raw -ErrorAction Stop
            $body.add("root_cas",$root_cas)
        }elseif($root_cas){
            $body.add("root_cas",$root_cas)
        }
    }

    if($bindsecurecredentials){
        Write-Debug "What is my credential bind_dn? $($bindsecurecredentials.username)" 
        Write-debug "What is my credential password? $($bindsecurecredentials.password | ConvertFrom-SecureString)"
        $body.add('bind_dn', $bindsecurecredentials.username)
        $body.add('bind_password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($bindsecurecredentials.password)))
    }else{
        if($bind_dn){ $body.add('bind_dn', $bind_dn)}
        if($bind_pass){ $body.add('bind_password', $bind_pass)}
    }

    
    if($securetestcreds){
        Write-Debug "What is my credential bind_dn? $($securetestcreds.username)" 
        Write-debug "What is my credential password? $($securetestcreds.password | ConvertFrom-SecureString)"
        $body.credentials.add('username', $securetestcreds.username)
        $body.credentials.add('password', [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securetestcreds.password)))

    }else{
        if($test_user){ $body.credentials.add('username', $test_user)}
        if($test_pass){ $body.credentials.add('password', $test_pass)}
    }
    
    if($group_base_dn){ $body.add("group_base_dn",$group_base_dn) }
    if($group_dn_attribute){ $body.add("group_dn_attribute",$group_dn_attribute) }
    if($group_filter){ $body.add("group_filter",$group_filter) }
    if($group_id_attribute){ $body.add("group_id_attribute",$group_id_attribute) }
    if($group_member_field){ $body.add("group_member_field",$group_member_field) }
    if($group_name_attribute){ $body.add("group_name_attribute",$group_name_attribute) }
    if($search_filter){ $body.add("search_filter",$search_filter) }
    if($user_dn_attribute){ $body.add("user_dn_attribute",$user_dn_attribute) }
    if($user_member_field){ $body.add("user_member_field",$user_member_field) }
    if($products){ $body.add("products",$products)}
    if($insecure_skip_verify){ $body.add("insecure_skip_verify",[bool]$true) }

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

#Connection Manager - LDAP Connections
#"#/v1/connectionmgmt/services/ldap/connections/{id}/nodes"
#"#/v1/connectionmgmt/services/ldap/connections/{id}/nodes - get"

<#
    .SYNOPSIS
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .DESCRIPTION
        Get list of nodes attached to a CipherTrust Manager DSM Connection
    .PARAMETER name
        The complete name of the DSM connection. Do not use wildcards.
    .PARAMETER id
        The CipherTrust manager "id" value for the connection.
        Use the Find-CMLDAPConnections cmdlet to find the appropriate id value.
    .EXAMPLE
        PS> Find-CMLDAPConnectionNodes -name "My DSM Connection"
        Use the complete name of the connection. 
    .EXAMPLE
        PS> Find-CMLDAPConnectionNodes -id "27657168-c3fb-47a7-9cd7-72d69d48d48b"
        Use the complete name of the connection. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>


####
# Export Module Members
####
#Connection Manager - LDAP
#/v1/connectionmgmt/services/ldap/connections"

Export-ModuleMember -Function Find-CMLDAPConnections #/v1/connectionmgmt/services/ldap/connections - get"
Export-ModuleMember -Function New-CMLDAPConnection #/v1/connectionmgmt/services/ldap/connections - post"

#Connection Manager - LDAP
#/v1/connectionmgmt/services/ldap/connections/{id}"
Export-ModuleMember -Function Get-CMLDAPConnection #/v1/connectionmgmt/services/ldap/connections/{id} - get"
Export-ModuleMember -Function Update-CMLDAPConnection #/v1/connectionmgmt/services/ldap/connections/{id} - patch"
Export-ModuleMember -Function Remove-CMLDAPConnection #/v1/connectionmgmt/services/ldap/connections/{id} - delete"

#Connection Manager - LDAP
#/v1/connectionmgmt/services/ldap/connections/{id}/test"
Export-ModuleMember -Function Test-CMLDAPConnection #/v1/connectionmgmt/services/ldap/connections/{id}/test - post"

#Connection Manager - LDAP
#/v1/connectionmgmt/services/ldap/connection-test"
Export-ModuleMember -Function Test-CMLDAPConnParameters #/v1/connectionmgmt/services/ldap/connection-test - post"

