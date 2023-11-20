#######################################################################################################################
# File:             CipherTrustManager-Tokens.psm1                                                                    #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# ENUMS
####
#Transport Types
Add-Type -TypeDefinition @"
public enum CM_TokensGrantTypes {
    password,
    refresh_token,
    user_certificate,
    client_credential
}
"@

####
# Local Variables
####
$target_uri = "/auth/tokens"
$target_revoke_uri = "/auth/revoke"
$target_selfdomain_uri = "/auth/self/domains"
$target_authkey_uri = "/auth/auth-key"
$target_authkey_rotation_uri = "/auth/rotate-auth-key"
$target_akeyless_uri = "/auth/akeyless/tokens"
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



#This project mirrors the "Tokens" section of the API Playground of CM (/playground_v2/api/auth/tokens)

#Tokens
#"#/v1/auth/tokens/"
#"#/v1/auth/tokens/-get"

<#
    .SYNOPSIS
        List Tokens
    .DESCRIPTION
        Returns a list of refresh tokens.. The results can be filtered, using the query parameters.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters.
    .PARAMETER user_id
        Filter by the id of a specific user. ID can be discovered using 'Find-CMUser'
    .PARAMETER labels
        Filter by the labels tagged to the refresh token. This can be a comma-separated list of labels (eg label1,label2) - no spaces allowed
    .PARAMETER expired 
        Filter by the expiry state of the token. Defaults to 'false' which will hide expired tokens.
    .PARAMETER revoked 
        Filter by the token revocation flag. Defaults to 'false' which will hide revoked tokens.
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Find-CMSyslogs 

        Returns a list of all syslog connections 
    .EXAMPLE
        PS> Find-CMSyslogs -transport "tls"

        Returns a list of all syslog connections that are using TLS for transport 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMTokens {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $user_id, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $labels,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $expired, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $revoked, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a Authentication Tokens in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    # Mandatory Parameters
    $body = @{
        'name' = $name
    }    
    # Optional Parameters
    if ($user_id) { $body.add('user_id', $user_id) }
    if ($labels) { $body.add('labels', $labels) }
    if ($expired) { $body.add('expired', $true) }
    if ($revoked) { $body.add('revoked', $true) }
    if ($skip) { $body.add('skip', $skip) }
    if ($limit) { $body.add('limit', $limit) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

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
        if ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of users created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    

#Tokens
#"#/v1/auth/tokens/"
#"#/v1/auth/tokens/-post"

<#
    .SYNOPSIS
        Create a new Access/Authentication Token
    .DESCRIPTION
        This is for exchanging a credential for an API authentication token (access token), which can be used to make API calls. The credential can be a username/password, a refresh token, or a certificate
        The username and password or refresh token is passed in the body of the request, and the certificate must be presented during SSL negotion, and issued by a CA trusted by the web interface.
        The response contains the jwt, which is the API authentication token (access token), duration, which is the length of time until the token expires, refresh token that can be used to get a new or additional API authentication token, and the client id of the refresh token.
    .PARAMETER grant_type
        (Optional) The authorization grant type. It is optional and valid values are password, refresh_token, user_certificate, and client_credential.
            password: Authenticates using a password (which is the default), but returns both a JWT and a refresh token. If two-factor authentication is enabled for the user, then authenticates using username-password and user certificate. The DN of the certificate is matched to the "certificate_subject_dn" of the user and returns both a JWT and a refresh token.
            refresh_token: Authenticates using a refresh token. Returns a JWT, and a refresh token if renew_refresh_token is set to true.
            user_certificate: Authenticate using a client certificate presented during SSL negotiaion. The DN of the certificate will be matched to a user's certificate_subject_dn. Returns both a JWT and a refresh token.
            client_credential: Authenticates using a client certificate presented during SSL negotiation. The certifcate will be used to identify a client and an appropriate token returned. Returns only a JWT.
        Currently supported grant types are listed in [CM_TokenGrantTypes] enum
    .PARAMETER auth_domain
        (Optional) The domain where user needs to be authenticated. This is the domain where user is created. Defaults to the root domain.
    .PARAMETER client_id
        (Optional) Client id of the pre-registered api playground client.
    .PARAMETER connection
        (Optional) The friendly name of the server you want to authenticate against. If nothing is provided, it will default to local_account.
    .PARAMETER cookies
        (Optional) Any JWT and refresh token will be returned as cookies rather than in the response body.
    .PARAMETER domain
        (Optional) The domain name or ID to issue the token for. For grant type of 'password' it defaults to the root domain. With 'refresh_token' grant type, refresh token used will be revoked if it was not issued for this domain. Not currently supported for 'client_credential' grant type.
    .PARAMETER labels
        (Optional) The labels are for tagging the token for later searches. 
        Valid with 'password' grant type.
    .PARAMETER ps_creds
        PSCredential of username (use PSCredental or username/SecureString or username/plaintext but not all three)
    .PARAMETER secure_password 
        SecureString password for username (use PSCredental or username/SecureString or username/plaintext but not all three)    
    .PARAMETER password
        The user's password. Required when the grant_type is not specified or 'password'. 
        Use PSCredental or username/SecureString or username/plaintext but not all three)
        Not valid with 'refresh_token' grant type.
    .PARAMETER refresh_token
        The refresh token used to obtain an API authentication token without the user credential. 
        This refresh token will be revoked if token is requested for a different domain the user belongs to. 
        Valid with 'refresh_token' grant type.
    .PARAMETER refresh_token_lifetime
        Lifetime of a refresh token in minutes. By default, refresh tokens have no expiry. 
        Valid with 'password' grant type.
    .PARAMETER refresh_token_revoke_unused_in
        Refresh token inactivity timeout period in minutes. 
        The refresh token will be revoked if not used within the specified time to refresh an access token. Each usage resets refresh token lease. 
        Valid with 'password' grant type.
    .PARAMETER renew_refresh_token
        Get a new refresh token along with the API authentication token and invalidate the current refresh token. 
        Valid with 'refresh_token' grant type.    
    .PARAMETER username
        The user's username. 
        Required when the grant_type is not specified or 'password'. 
        You can specify an LDAP user with the format <connection_name>|<username>. 
        Connection names specified this way override the value specified in the connection field. 
        Not valid with 'refresh_token' grant type.
    .EXAMPLE
        PS> New-CMToken -host <ip address>

        This creates a syslog connection overUser udp with the default message format of rfc5424
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMToken {
    [CmdletBinding(DefaultParameterSetName = 'by PSCredential')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
        '', 
        Justification = 'Allowing for choice. Customer can pass SecureString if they have it')]
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [CM_TokensGrantTypes] $grant_type = [CM_TokensGrantTypes]::password, 
        [Parameter(Mandatory = $true,
        ParameterSetName = 'by PSCredential',
        ValueFromPipelineByPropertyName = $true )]
        [System.Management.Automation.PSCredential] $ps_creds,
        [Parameter(Mandatory = $true,
            ParameterSetName = 'by SecureString',
            ValueFromPipelineByPropertyName = $true )]
        [Parameter(Mandatory = $true,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $username,
        [Parameter(Mandatory = $true,
            ParameterSetName = 'by SecureString',
            ValueFromPipelineByPropertyName = $true )]
        [SecureString] $secure_password, 
        [Parameter(Mandatory = $true,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $password, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $auth_domain,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $client_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $connection,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $cookies = $false,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $domain, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $labels,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $refresh_token,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $refresh_token_lifetime,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $refresh_token_revoke_unused_in,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $renew_refresh_token
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a Syslog Connection in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters - None
    $body = @{}

    if(refresh_token -ne $grant_type) {
        #if we are using PSCredential parameter set
        Write-Debug "ParameterSetName $($PSCmdlet.ParameterSetName)"
        if ($PSCmdlet.ParameterSetName -eq 'by PSCredential') {
            $body.add('username', $ps_creds.UserName)
            $body.add('password', (ConvertFrom-SecureString $ps_creds.Password -AsPlainText))
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'by SecureString') {
            $body.add('username', $username)
            $body.add('password', (ConvertFrom-SecureString $secure_password -AsPlainText)) 
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'by Plaintext') {
            $body.add('username', $username)
            $body.add('password', $password) 
        }
        else {
            Write-Error "Did not get the proper ParameterSetName. Got $($PSCmdlet.ParameterSetName)"
        }
    }
    else{
        if ($refresh_token) { $body.add('refresh_token', $refresh_token) }
    }
    
    # Optional Parameters
    if ($auth_domain) { $body.add('auth_domain', $auth_domain) }
    if ($connection) { $body.add('connection', $connection) }
    if ($client_id) { $body.add('client_id', $client_id) }
    if ($cookies) { $body.add('cookies', $true) }
    
    #...for Grant Type not = client_credential
    if(client_credential -ne $grant_type) {
        if ($domain) { $body.add('domain', $domain) }
    }

    #...for Grant Type = password ONLY
    if(password -eq $grant_type) {
        if ($refresh_token_lifetime) { $body.add('refresh_token_lifetime', $refresh_token_lifetime) }
        if ($refresh_token_revoke_unused_in) { $body.add('refresh_token_revoke_unused_in', $refresh_token_revoke_unused_in) }
    }
    
    #...for Grant Type = refresh_token ONLY
    if(refresh_token -eq $grant_type) {
        if ($renew_refresh_token) { $body.add('renew_refresh_token', $true) }
    }

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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Token already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        elseif ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "User created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    


#Tokens
#"#/v1/auth/tokens/{id}"
#"#/v1/auth/tokens/{id}-get"

<#
    .SYNOPSIS
        Get a single token by ID
    .DESCRIPTION
        Return information about the refresh token. Does not return the token.
    .PARAMETER token_id
        ID of the token to search. Locate the id using 'Find-CMTokens'
    .EXAMPLE
        PS> Get-CMToken -toekn_id <token id>

        This will return the information related to the token of id `token_id`
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMToken {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $token_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a Token by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $endpoint += "/$token_id"
    
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
        elseif ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "User information found"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

#Tokens
#"#/v1/auth/tokens/{id}"
#"#/v1/auth/tokens/{id}-delete"

<#
    .SYNOPSIS
        Delete a Token
    .DESCRIPTION
        Deletes a token given the token's id. Use 'Find-CMTokens' to get the id 
    .PARAMETER token_id
        The ID of the token to be deleted. Can be obtained through Find-CMTokens
    .EXAMPLE
        PS> $toDelete = Find-CMTokens -labels "div42" #assuming there is only ONE token for `div42` in CipherTrust Manager
        PS> Remove-CMToken -token_id $toDelete.resources[0].id

        Deletes the token tagged with the label "div42" by the token's id
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMToken {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $token_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Deleting a Token by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$token_id"

    Write-Debug "Endpoint with ID: $($endpoint)"

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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User set already exists"
            return
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        elseif ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Token deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    

#Tokens
#"#/v1/auth/revoke"
#"#/v1/auth/revoke-post"

<#
    .SYNOPSIS
        Revoke a Refresh Token
    .DESCRIPTION
        Revokes a refresh token given the original token. 
    .PARAMETER token
        The refresh token to be revoked.
    .PARAMETER client_id
        (Optional) The client id of the refresh token. Not required if username and password is specified.
    .PARAMETER connection
        (Optional)The active directory the user is a part of. Defaults to local_account if not provided.
    .PARAMETER ps_creds
        PSCredential of User (use PSCredental or username/SecureString or username/plaintext but not all three)
    .PARAMETER username
        The user's username. Not required if client id is specified. You can specify an LDAP user with the format <connection_name>|<username>. Connection names specified this way override the value specified in the connection field.
        Use PSCredental or username/SecureString or username/plaintext but not all three
        Not required if client_id used
    .PARAMETER secure_password 
        SecureString password for username (use PSCredental or username/SecureString or username/plaintext but not all three)    
    .PARAMETER password 
        Plaintext password for username (use PSCredental or username/SecureString or username/plaintext but not all three)
    .EXAMPLE
        PS> Revoke-CMToken -token <current token>

        Revokes the specific refresh token
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Revoke-CMToken {
    [CmdletBinding(DefaultParameterSetName = 'by ClientID')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
        '', 
        Justification = 'Allowing for choice. Customer can pass SecureString if they have it')]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $token,
        [Parameter(Mandatory = $false,
        ParameterSetName = 'by ClientID',
        ValueFromPipelineByPropertyName = $true)]
        [string] $client_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $connection,
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by PSCredential',
            ValueFromPipelineByPropertyName = $true )]
        [System.Management.Automation.PSCredential] $ps_creds,
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by SecureString',
            ValueFromPipelineByPropertyName = $true )]
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $username,
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by SecureString',
            ValueFromPipelineByPropertyName = $true )]
        [SecureString] $secure_password, 
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $password
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Revoking a Token by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_revoke_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'token' = $token
    }
 
    #if we are using PSCredential parameter set
     Write-Debug "ParameterSetName $($PSCmdlet.ParameterSetName)"
     if ($PSCmdlet.ParameterSetName -eq 'by ClientID') {
        $body.add('client_id', $client_id)
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'by PSCredential') {
         $body.add('username', $ps_creds.UserName)
         $body.add('password', (ConvertFrom-SecureString $ps_creds.Password -AsPlainText))
     }
     elseif ($PSCmdlet.ParameterSetName -eq 'by SecureString') {
         $body.add('username', $username)
         $body.add('password', (ConvertFrom-SecureString $secure_password -AsPlainText)) 
     }
     elseif ($PSCmdlet.ParameterSetName -eq 'by Plaintext') {
         $body.add('username', $username)
         $body.add('password', $password) 
     }
     else {
         Write-Error "Did not get the proper ParameterSetName. Got $($PSCmdlet.ParameterSetName)"
     }
 
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
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Token already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        elseif ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Token revoked"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Tokens
#"#/v1/auth/self/domains"
#"#/v1/auth/self/domains-get"

<#
    .SYNOPSIS
        Get domain(s) on "current user" (ie self)
    .DESCRIPTION
        Returns a list of domains that the current user is member of. The result can be filtered using the query parameters.
    .EXAMPLE
        PS> $selfDomain = Get-CMSelfDomains

        Returns the domain(s) for current user
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMSelfDomains {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting Current User in CM"
    $endpoint = $CM_Session.REST_URL + $target_selfdomain_uri
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
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials"
            return
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Current User information found"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

#Tokens
#"#/v1/auth/rotate-auth-key"
#"#/v1/auth/rotate-auth-key-post"

<#
    .SYNOPSIS
        Rotate Auth Key Token
    .DESCRIPTION
        Rotate the token auth key, new key is effective after restart of CM services.    
    .PARAMETER curve
        (Optional) ECDSA curve, p256 p384 or p521. Defaults to p256. Ignored for hmac.
    .PARAMETER type
        (Optional) Signing key type, hmac or ecdsa. Defaults to hmac.
    .EXAMPLE
        PS> Set-CMAuthKeyRotate

        Rotates the token auth key, new key is effective after restart of CM services.    
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMAuthKeyRotate {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $user_id, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $labels,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $expired, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $revoked, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a Authentication Tokens in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    # Mandatory Parameters
    $body = @{
        'name' = $name
    }    
    # Optional Parameters
    if ($user_id) { $body.add('user_id', $user_id) }
    if ($labels) { $body.add('labels', $labels) }
    if ($expired) { $body.add('expired', $true) }
    if ($revoked) { $body.add('revoked', $true) }
    if ($skip) { $body.add('skip', $skip) }
    if ($limit) { $body.add('limit', $limit) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

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
        if ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of users created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

#Tokens
#"#/v1/auth/auth-key"
#"#/v1/auth/auth-key-get"

<#
    .SYNOPSIS
        Get Auth Key Token
    .DESCRIPTION
        This command lists the keys used for verifying external JWTs. The type of the public key is returned, among other parameters. 
        The type parameter is one of "hmac", "rsa" or "ecdsa". 
        If the Type parameter is "rsa" or "ecdsa", the output contains the public key that is used for verifying the external JWT. 
        The public key is returned in PEM and JWK formats.
    .EXAMPLE
        PS> Get-CMAuthKey

        Get the info related to current Auth Key.    
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMAuthKey {
    param()
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a Authentication Tokens in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
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
        if ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "List of users created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

#Tokens
#"#/v1/auth/akeyless/tokens"
#"#/v1/auth/akeyless/tokens-post"

<#
    .SYNOPSIS
        Get Auth Key Token
    .DESCRIPTION
        Create an akeyless token using the configured akeyless SSO credentials
    .EXAMPLE
        PS> Get-CMAuthKey

        Get the info related to current Auth Key.    
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMAkeylessToken {
    param()
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Creating an Akeyless Token in CM"
    $endpoint = $CM_Session.REST_URL + $target_akeyless_uri
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
        if ([int]$StatusCode -EQ 0) {
            Write-Error "Error $([int]$StatusCode): Not connected to a CipherTrust Manager. Run 'Connect-CipherTrustManager' first" -ErrorAction Stop
            return
        }        
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Akeyless Token created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}

####
# Export Module Members
####
#Tokens
#"#/v1/auth/tokens/"
Export-ModuleMember -Function Find-CMTokens         #List (get)
Export-ModuleMember -Function New-CMToken           #Create (post)

#"#/v1/auth/tokens/{id}"
Export-ModuleMember -Function Get-CMToken           #Get (get)
Export-ModuleMember -Function Remove-CMToken        #Delete (delete)

#"#/v1/auth/revoke"
Export-ModuleMember -Function Revoke-CMToken        #Delete (delete)

#"#/v1/auth/self/domains"
Export-ModuleMember -Function Get-CMSelfDomains     #Get (get)

#"#/v1/auth/rotate-auth-key"
Export-ModuleMember -Function Set-CMAuthKeyRotate   #Rotate (post)

#"#/v1/auth/auth-key"
Export-ModuleMember -Function Get-CMAuthKey         #Get (get)

#"#/v1/auth/akeyless/tokens"
Export-ModuleMember -Function New-CMAkeylessToken   #Create (post)
