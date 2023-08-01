#######################################################################################################################
# File:             CipherTrustManager-Users.psm1                                                                  #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# Local Variables
####
$target_uri = "/usermgmt/users"
$target_self_uri = "/v1/auth/self/user"
$target_changepw_uri = "/v1/auth/changepw"
$target_pwdpolicy_uri = "/v1/usermgmt/pwdpolicies/global"
####

#This project mirrors the "Users" section of the API Playground of CM (/playground_v2/api/Users)

#Users
#"#/v1/usermgmt/users/"
#"#/v1/usermgmt/users/-get"

<#
    .SYNOPSIS
        List Users
    .DESCRIPTION
        Returns a list of all user resources. The results can be filtered, using the query parameters. Wildcards are supported.
        Results are returned in pages. Each page of results includes the total results found, and information for requesting the next page of results, using the skip and limit query parameters.    
    .PARAMETER name
        Filter by the User's Full name/Display name
    .PARAMETER username
        Filter by the Username/Account name of User
    .PARAMETER email 
        Filter by the User's Email address
    .PARAMETER groups 
        Filter by the Users in the given group name. Using `nil` as the group name will return users that are not part of any group.
    .PARAMETER auth_domain_name
        Filter by the User's Auth Domain
    .PARAMETER skip
        The index of the first resource to return. Equivalent to `offset` in SQL.
    .PARAMETER limit
        The max number of resources to return. Equivalent to `limit` in SQL.
    .EXAMPLE
        PS> Find-CMUsers -name "Bob*"

        Returns a list of all users whose name starts with "Bob" 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Find-CMUsers {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $username,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [mailaddress] $email, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $groups, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $auth_domain_name, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $skip,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $limit
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a List of Users in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    $firstset = $false
    if ($name) {
        $endpoint += "?name="
        $firstset = $true
        $endpoint += $name
    }
    if ($username) {
        if ($firstset) {
            $endpoint += "&username="
        }
        else {
            $endpoint += "?username="
            $firstset = $true
        }
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
    if ($groups) {
        if ($firstset) {
            $endpoint += "&groups="
        }
        else {
            $endpoint += "?groups="
            $firstset = $true
        }
        $endpoint += $groups
    }
    if ($auth_domain_name) {
        if ($firstset) {
            $endpoint += "&auth_domain_name="
        }
        else {
            $endpoint += "?auth_domain_name="
            $firstset = $true
        }
        $endpoint += $auth_domain_name
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    Write-Debug "List of users created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}    
    
#Users
#"#/v1/usermgmt/users/"
#"#/v1/usermgmt/users/-post"

<#
    .SYNOPSIS
        Create a new User
    .DESCRIPTION
        Create a new user in the root domain, or add an existing root domain user to a sub-domain. Users are always created in the local, internal user database, but might be references to external identity providers.
        The connection property is optional. If this property is specified when creating new users, it can be the name of a connection or local_account for a local user.
        The connection property is only used in the body of the create-user request. It is not present in either request or response bodies of the other user endpoints.
        Required fields when creating a root domain user are username and password for local users, other connections might not require a password.
        The certificate_subject_dn property is optional, in order to enable certificate based authentication for the user it is required to set certificate_subject_dn and set enable_cert_auth to true. This functionality is available only for local users.
        When adding existing root domain users to a sub-domain, the users are added to the domain of the user who is logging in, and the connection property should be left empty. The user_id or username fields are the only ones that are used while adding existing users to sub-domains; all other fields are ignored.    
    .PARAMETER name
        Full name/Display name of User 
    .PARAMETER ps_creds
        PSCredential of User (use PSCredental or username/SecureString or username/plaintext but not all three)
    .PARAMETER username
        The login name of the user. This is the identifier used to login.
        This parameter is required to create a user, but is omitted when getting or listing user resources. It cannot be updated.
        This parameter may also be used (instead of the user_id) when adding an existing root domain user to a different domain.
        This parameter must be used un conjunction with with -secure_password or -password or as part of PSCredential
    .PARAMETER secure_password 
        SecureString password for User (use PSCredental or username/SecureString or username/plaintext but not all three)    
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER password 
        Plaintext password for User (use PSCredental or username/SecureString or username/plaintext but not all three)
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER email 
        Email address for User. Must be UNIQUE for all of CipherTrust Manager
    .PARAMETER user_id
        The user_id is the ID of an existing root domain user. This field is used only when adding an existing root domain user to a different domain.
    .PARAMETER certificate_subject_dn
        This attribute is required to create a user, but is not included in user resource responses. 
        Can be the name of a connection or "local_account" for a local user, defaults to "local_account".
    .PARAMETER connection
        This attribute is required to create a user, but is not included in user resource responses. 
        Can be the name of a connection or "local_account" for a local user, defaults to "local_account".
    .PARAMETER PasswordChangeRequired
        Password change required flag. If set to true, user will be required to change their password on next successful login.
    .PARAMETER EnableCertAuth
        The Distinguished Name of the user in certificate
    .PARAMETER isDomainUser
        This flag can be used to create the user in a non-root domain where user management is allowed.
    .PARAMETER PreventUILogin
        If true, user is not allowed to login from Web UI. Default - false
    .PARAMETER app_metadata 
        A schema-less object, which can be used by applications to store information about the resource. `app_metadata` is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles.
    .PARAMETER user_metadata        
        A schema-less object, which can be used by applications to store information about the resource. `user_metadata` is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences.
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -ps_creds <PSCredential>

        This creates a User with basic settings using a PSCredential.
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -username <account name> -secure_password <SecureString>

        This creates a User with basic settings. Password is provided in SecureString
    .EXAMPLE
        PS> New-CMUser -email <email> -name <full name> -username <account name> -password <plaintext>

        This creates a User with basic settings. Password is provided in plaintext (least secure)
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CMUser {
    [CmdletBinding(DefaultParameterSetName = 'by PSCredential')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
        '', 
        Justification = 'Allowing for choice. Customer can pass SecureString if they have it')]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
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
        [string] $email, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $user_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $certificate_subject_dn,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $connection,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $PasswordChangeRequried, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $EnableCertAuth,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $isDomainUser,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $PreventUILogin,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $app_metadata, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $user_metadata
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Creating a User in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'name' = $name
    }

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

    # Optional Parameters
    if ($certificate_subject_dn) { $body.add('certificate_subject_dn', $certificate_subject_dn) }
    if ($connection) { $body.add('connection', $connection) }
    if ($EnableCertAuth) { $body.add('enable_cert_auth', $true) }
    if ($isDomainUser) { $body.add('is_domain_user', $true) }
    if ($PreventUILogin) {
        $login_flags = @{}
        $login_flags.add('prevent_ui_login', $true)
        $body.add('login_flags', $login_flags)
    }

    if ($PasswordChangeRequried) { $body.add('password_change_required', $true) }
    if ($user_id) { $body.add('user_id', $user_id) }

    if ('app_metadata') {
        $body.add('app_metadata', $app_metadata)
    }
    if ('user_metadata') {
        $body.add('user_metadata', $user_metadata)
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): User already exists" -ErrorAction Continue
        }
        elseif ($StatusCode -EQ [System.Net.HttpStatusCode]::Unauthorized) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Unable to connect to CipherTrust Manager with current credentials" -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "User created"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"

    return $response
}    

#Users
#"#/v1/usermgmt/users/{user_id}"
#"#/v1/usermgmt/users/{user_id}-get"

<#
    .SYNOPSIS
        Get a single User by ID
    .DESCRIPTION
        Returns a single user resource. If the user_id "self" is provided, it will return the current user's information.
    .PARAMETER user_id
        User ID of the user to return.
    .EXAMPLE
        PS> Get-CMUser -user_id <user id>

        This will return the information related to the user of id `user_id`
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMUser {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $user_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting a User by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #Set query
    if ($user_id) {
        $endpoint += "/"
        $endpoint += $user_id
    }
    
    Write-Debug "Endpoint w Query: $($endpoint)"
    
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    Write-Debug "User information found"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $response
}


#Users
#"#/v1/usermgmt/users/{user_id}"
#"#/v1/usermgmt/users/{user_id}-delete"

<#
    .SYNOPSIS
        Delete User
    .DESCRIPTION
        Deletes a user given the user's user-id. 
        If the current user is logged into a sub-domain, the user is deleted from that sub-domain. 
        If the current user is logged into the root domain, the user is deleted from all domains it belongs to.    
    .PARAMETER user_id
        The ID of the user to be deleted. Can be obtained through Find-CMUsers
    .EXAMPLE
        PS> $toDelete = Find-CMUsers -name "Bob Smith" #assuming there is only ONE `Bob Smith` in CipherTrust Manager
        PS> Remove-CMUser -id $toDelete.resources[0].user_id

        Deletes the user `Bob Smith` by the user's id
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Remove-CMUser {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $user_id
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Deleting a User by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$user_id"

    Write-Debug "Endpoint with ID: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "User deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    

#Users
#"#/v1/usermgmt/users/{user_id}"
#"#/v1/usermgmt/users/{user_id}-patch"

<#
    .SYNOPSIS
        Update a User
    .DESCRIPTION
        Change the properties of a user. For instance the name, the password, or metadata. 
        Permissions would normally restrict this route to users with admin privileges. 
        Non admin users wishing to change their own passwords should use the change password route. 
        The user will not be able to change their password to the same password.
    .PARAMETER user_id
        The user_id of the User to update. Use Find-CMUser to get the user_id 
    .PARAMETER name
        Full name/Display name of User 
    .PARAMETER ps_creds
        PSCredential of User (use PSCredental or username/SecureString or username/plaintext but not all three)
    .PARAMETER username
        The login name of the user. This is the identifier used to login.
        This parameter is required to create a user, but is omitted when getting or listing user resources. It cannot be updated.
        This parameter may also be used (instead of the user_id) when adding an existing root domain user to a different domain.
        This parameter must be used un conjunction with with -secure_password or -password or as part of PSCredential
    .PARAMETER secure_password 
        SecureString password for User (use PSCredental or username/SecureString or username/plaintext but not all three)    
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER password 
        Plaintext password for User (use PSCredental or username/SecureString or username/plaintext but not all three)
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER email 
        Email address for User. Must be UNIQUE for all of CipherTrust Manager
    .PARAMETER certificate_subject_dn
        This attribute is required to create a user, but is not included in user resource responses. 
        Can be the name of a connection or "local_account" for a local user, defaults to "local_account".
    .PARAMETER PasswordChangeRequired
        Password change required flag. If set to true, user will be required to change their password on next successful login.
    .PARAMETER EnableCertAuth
        The Distinguished Name of the user in certificate
    .PARAMETER UnlockUILogin
        This flag can be used to unlock an account that is currently prevented from loging into the UI.
    .PARAMETER PreventUILogin
        If true, user is not allowed to login from Web UI. Default - false
    .PARAMETER user_metadata        
        A schema-less object, which can be used by applications to store information about the resource. `user_metadata` is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences.
    .EXAMPLE
        PS> Set-CMUser -user_id <userId> -email <email> -name <full name> -ps_creds <PSCredential>

        This updates a user's name, email, username and password by ID.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMUser {
    [CmdletBinding(DefaultParameterSetName = 'by PSCredential')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
        '', 
        Justification = 'Allowing for choice. Customer can pass SecureString if they have it')]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $user_id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
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
        [string] $password, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $email, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $certificate_subject_dn,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $PasswordChangeRequried, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $EnableCertAuth,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $PreventUILogin,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [switch] $UnlockUILogin,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $user_metadata
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating a User by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$user_id"

    Write-Debug "Endpoint with ID: $($endpoint)"


    # Mandatory Parameters
    $body = @{} #No manatory params

    # Optional Parameters    
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
    
    if ($certificate_subject_dn) { $body.add('certificate_subject_dn', $certificate_subject_dn) }
    if ($email) { $body.add('email', $email) }
    #Set it to 0 to unlock a locked user account.
    if ($EnableCertAuth) { $body.add('enable_cert_auth', $true) }
    $login_flags = @{}
    if ($PreventUILogin) {
        $login_flags.add('prevent_ui_login', $true)
    }
    else {
        $login_flags.add('prevent_ui_login', $false)
    }
    $body.add('login_flags', $login_flags)

    if ($PasswordChangeRequried) { $body.add('password_change_required', $true) }
    if ($UnlockUILogin) { $body.add('failed_logins_count', 0) }
    
    if ('user_metadata') {
        $body.add('user_metadata', $user_metadata)
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "User deleted"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    

#Users
#"#/v1/auth/self/user"
#"#/v1/auth/self/user-get"

<#
    .SYNOPSIS
        Get info on "current user" (ie self)
    .DESCRIPTION
        Returns a single user resource. It will return the current user's information.   
    .EXAMPLE
        PS> $self = Get=CMSelf

        Returns the user resource for current user
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMSelf {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting Current User in CM"
    $endpoint = $CM_Session.REST_URL + $target_self_uri
    Write-Debug "Endpoint: $($endpoint)"
        
    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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


#Users
#"#/v1/auth/self/user"
#"#/v1/auth/self/user-patch"

<#
    .SYNOPSIS
        Update Current User (ie self)
    .DESCRIPTION
        Change the properties of the current user. For instance the email, or metadata.
    .PARAMETER email 
        Email address for User. Must be UNIQUE for all of CipherTrust Manager
    .PARAMETER user_metadata        
        A schema-less object, which can be used by applications to store information about the resource. `user_metadata` is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences.
    .EXAMPLE
        PS> Set-CMself -email <email>

        This updates current user's email address.
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMSelf {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Updating Current User in CM"
    $endpoint = $CM_Session.REST_URL + $target_self_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{} #No manatory params

    # Optional Parameters    
    if ($email) { $body.add('email', $email) }
    
    if ('user_metadata') {
        $body.add('user_metadata', $user_metadata)
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "Current User updated"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

#Users
#"#/v1/auth/changepw"
#"#/v1/auth/changepw-patch"

<#
    .SYNOPSIS
        Change the password of the Current User (ie self)
    .DESCRIPTION
        Change the current user's password. Can only be used to change the password of the currently authenticated user. The user will not be able to change their password to the same password.
    .PARAMETER current_ps_creds
        The CURRENT PSCredential of User.
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.
    .PARAMETER new_ps_creds
        The NEW PSCredential of User.
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.
    .PARAMETER username
        The login name of the user. This is the identifier used to login.
    .PARAMETER current_secure_password 
        The CURRENT SecureString password for User.
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.
    .PARAMETER new_secure_password 
        The NEW SecureString password for User
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.    
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER current_password 
        The CURRENT plaintext password for User.
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.    
    .PARAMETER new_password 
        The NEW plaintext password for User.
        Use PSCredental or username/SecureString or username/plaintext but not all three. Do not mix types.    
        The password used to secure the users account. Allowed passwords are defined by the password policy.
        This attribute is required to create a local user, but is not included in user resource responses.
    .PARAMETER auth_domain 
        The domain where user needs to be authenticated. This is the domain where user is created. Defaults to the root domain.
    .EXAMPLE
        PS> Set-SelfPwd -current_ps_creds <PSCredential> -new_ps_creds <PSCredential>

        This updates password for current user using a PSCredential.
    .EXAMPLE
        PS> Set-SelfPwd -username <account name> -current_secure_password <SecureString> -new_secure_password <SecureString>

        This updates password for current user. Passwords are provided by SecureString
    .EXAMPLE
        PS> Set-SelfPwd -username <account name> -current_password <plaintext> -new_secure_password <plaintext>

        This updates password for current user. Passwords are provided by plaintext (least secure)
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMSelfPwd {
    [CmdletBinding(DefaultParameterSetName = 'by PSCredential')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 
        '', 
        Justification = 'Allowing for choice. Customer can pass SecureString if they have it')]
    param
    (
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by PSCredential',
            ValueFromPipelineByPropertyName = $true )]
        [System.Management.Automation.PSCredential] $current_ps_creds,
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by PSCredential',
            ValueFromPipelineByPropertyName = $true )]
        [System.Management.Automation.PSCredential] $new_ps_creds,
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
        [SecureString] $current_secure_password, 
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by SecureString',
            ValueFromPipelineByPropertyName = $true )]
        [SecureString] $new_secure_password, 
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $current_password, 
        [Parameter(Mandatory = $false,
            ParameterSetName = 'by Plaintext',
            ValueFromPipelineByPropertyName = $true )]
        [string] $new_password 
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Changing Password for Current User in CM"
    $endpoint = $CM_Session.REST_URL + $target_changepw_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{} #No manatory params

    #if we are using PSCredential parameter set
    Write-Debug "ParameterSetName $($PSCmdlet.ParameterSetName)"
    if ($PSCmdlet.ParameterSetName -eq 'by PSCredential') {
        if ($current_ps_creds.UserName -eq $new_ps_creds.UserName) {
            $body.add('username', $current_ps_creds.UserName)
            $body.add('password', (ConvertFrom-SecureString $current_ps_creds.Password -AsPlainText))
            $body.add('new_password', (ConvertFrom-SecureString $new_ps_creds.Password -AsPlainText))
        } 
        else {
            throw "Error: PSCredentials were not created for same username"
        }   
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'by SecureString') {
        $body.add('username', $username)
        $body.add('password', (ConvertFrom-SecureString $current_secure_password -AsPlainText)) 
        $body.add('password', (ConvertFrom-SecureString $new_secure_password -AsPlainText)) 
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'by Plaintext') {
        $body.add('username', $username)
        $body.add('password', $current_password) 
        $body.add('password', $new_password) 
    }
    else {
        throw "Error: One set of PSCredental or username/SecureString or username/plaintext is required"
    }
    
    # Optional Parameters    
    if ($auth_domain) { $body.add('auth_domain', $auth_domain) }
    
    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "Password Changed for Current User"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}    

#Users
#"#/v1/usermgmt/pwdpolicies/global"
#"#/v1/usermgmt/pwdpolicies/global-patch"

<#
    .SYNOPSIS
        Change current password policy for all users.
    .DESCRIPTION
        Change the current password policy for all users. Can only be used to by a member of the admin group. Currently, a single policy named 'global' is applied to all users.
    .PARAMETER failed_logins_lockout_thresholds
        List of lockout durations in minutes for failed login attempts. 
        For example, with input of [0, 5, 30], the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, the third and subsequent failed login attempts will lockout for 30 minutes. 
        Set an empty array '[]' to disable the user account lockout.
    .PARAMETER inclusive_max_total_length
        The maximum length of the password. Value 0 is ignored.
    .PARAMETER inclusive_min_digits
        The minimum number of digits
    .PARAMETER inclusive_min_lower_case
        The minimum number of lower cases
    .PARAMETER inclusive_min_other
        The minimum number of other characters
    .PARAMETER inclusive_min_total_length
        The minimum length of the password. Value 0 is ignored.
    .PARAMETER inclusive_min_upper_case
        The minimum number of upper cases
    .PARAMETER password_change_min_days
        The minimum period in days between password changes. Value 0 is ignored.
    .PARAMETER password_history_threshold
        Determines the number of past passwords a user cannot reuse. Even with value 0, the user will not be able to change their password to the same password.
    .PARAMETER password_lifetime
        The maximum lifetime of the password in days. Value 0 is ignored.
    .EXAMPLE
        PS> Set-CMGlobalPwdPolicies -failed_logins_lockout_thresholds @(0,5,30)

        This creates a policy where the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, and the third and subsequent failed login attempts will lockout for 30 minutes.
    .EXAMPLE
        PS> Set-CMGlobalPwdPolicies -failed_logins_lockout_thresholds @()

        This disables user account lockout
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMGlobalPwdPolicies {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $failed_logins_lockout_thresholds,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_max_total_length,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_min_digits,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_min_lower_case,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_min_other,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_min_total_length,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $inclusive_min_upper_case,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $password_change_min_days,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $password_history_threshold,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int[]] $password_lifetime
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Changing Password Policy for ALL Users in CM"
    $endpoint = $CM_Session.REST_URL + $target_pwdpolicy_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{} #No manatory params

    # Optional Parameters    
    if ($failed_logins_lockout_thresholds) { $body.add('failed_logins_lockout_thresholds', $failed_logins_lockout_thresholds) }    
    if ($inclusive_max_total_length) { $body.add('inclusive_max_total_length', $inclusive_max_total_length) }
    if ($inclusive_min_digits) { $body.add('inclusive_min_digits', $inclusive_min_digits) }    
    if ($inclusive_min_lower_case) { $body.add('inclusive_min_lower_case', $inclusive_min_lower_case) }
    if ($inclusive_min_other) { $body.add('inclusive_min_other', $inclusive_min_other) }    
    if ($inclusive_min_total_length) { $body.add('inclusive_min_total_length', $inclusive_min_total_length) }
    if ($inclusive_min_upper_case) { $body.add('inclusive_min_upper_case', $inclusive_min_upper_case) }    
    if ($password_change_min_days) { $body.add('password_change_min_days', $password_change_min_days) }
    if ($password_history_threshold) { $body.add('password_history_threshold', $password_history_threshold) }
    if ($password_lifetime) { $body.add('password_lifetime', $password_lifetime) }
    
    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "Password Policy Changed for ALL User"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

#Users
#"#/v1/usermgmt/pwdpolicies/global"
#"#/v1/usermgmt/pwdpolicies/global-get"

<#
    .SYNOPSIS
        Change current password policy for all users.
    .DESCRIPTION
        Change the current password policy for all users. Can only be used to by a member of the admin group. Currently, a single policy named 'global' is applied to all users.
    .PARAMETER failed_logins_lockout_thresholds
        List of lockout durations in minutes for failed login attempts. 
        For example, with input of [0, 5, 30], the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, the third and subsequent failed login attempts will lockout for 30 minutes. 
        Set an empty array '[]' to disable the user account lockout.
    .PARAMETER inclusive_max_total_length
        The maximum length of the password. Value 0 is ignored.
    .PARAMETER inclusive_min_digits
        The minimum number of digits
    .PARAMETER inclusive_min_lower_case
        The minimum number of lower cases
    .PARAMETER inclusive_min_other
        The minimum number of other characters
    .PARAMETER inclusive_min_total_length
        The minimum length of the password. Value 0 is ignored.
    .PARAMETER inclusive_min_upper_case
        The minimum number of upper cases
    .PARAMETER password_change_min_days
        The minimum period in days between password changes. Value 0 is ignored.
    .PARAMETER password_history_threshold
        Determines the number of past passwords a user cannot reuse. Even with value 0, the user will not be able to change their password to the same password.
    .PARAMETER password_lifetime
        The maximum lifetime of the password in days. Value 0 is ignored.
    .EXAMPLE
        PS> Set-CMGlobalPwdPolicies -failed_logins_lockout_thresholds @(0,5,30)

        This creates a policy where the first failed login attempt with duration of zero will not lockout the user account, the second failed login attempt will lockout the account for 5 minutes, and the third and subsequent failed login attempts will lockout for 30 minutes.
    .EXAMPLE
        PS> Set-CMGlobalPwdPolicies -failed_logins_lockout_thresholds @()

        This disables user account lockout
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMGlobalPwdPolicies {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Getting Current Password Policy for ALL Users in CM"
    $endpoint = $CM_Session.REST_URL + $target_pwdpolicy_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: "
        Write-HashtableArray $($headers)      
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    Write-Debug "Current Password Policy information returned"
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

####
# Export Module Members
####
#Users
#"#/v1/usermgmt/users/"
Export-ModuleMember -Function Find-CMUsers  #List (get)
Export-ModuleMember -Function New-CMUser    #Create (post)

#"#/v1/usermgmt/users/{user_id}"
Export-ModuleMember -Function Get-CMUser    #Get (get)
Export-ModuleMember -Function Remove-CMUser #Delete (delete)
Export-ModuleMember -Function Set-CMUser    #Update (patch)

#"#/v1/auth/self/user"
Export-ModuleMember -Function Get-CMSelf    #Get (get)
Export-ModuleMember -Function Set-CMSelf    #Update (patch)

#"#/v1/auth/changepw"
Export-ModuleMember -Function Set-CMUserPwd #Change (patch)

#"#/v1/usermgmt/pwdpolicies/global"
Export-ModuleMember -Function Set-CMGlobalPwdPolicies #Change (patch)
Export-ModuleMember -Function Get-CMGlobalPwdPolicies #Get (get)

