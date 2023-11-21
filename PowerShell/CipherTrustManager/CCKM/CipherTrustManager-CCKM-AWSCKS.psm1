#######################################################################################################################
# File:             CipherTrustManager-CCKM-AWSCKS.psm1                                                               #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2023 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

####
# ENUMS
####
#Custom Key Store Types
Add-Type -TypeDefinition @"
public enum CM_CKSTypes {
    EKS,
    CloudHSM
}
"@
#XKS Proxy Connectivity Types
Add-Type -TypeDefinition @"
public enum CM_XKSProxyConnTypes {
    VPC,
    Public
}
"@
#XKS Proxy Connectivity Types
Add-Type -TypeDefinition @"
public enum CM_SourceKeyTiers {
    Local,
    HSM
}
"@
#CKS OPs Types
Add-Type -TypeDefinition @"
public enum CM_CKSOps {
    CreateAWSKey,
    Block,
    UnBlock,
    Connect,
    Disconnect,
    Link,
    RotateCred
}
"@
####

####
# Support Variables
####
# Text string relating to CM_RevealTypes enum
$CM_CKSTypesDef = @{
    [CM_CKSTypes]::EKS        = "EXTERNAL_KEY_STORE" 
    [CM_CKSTypes]::CloudHSM   = "AWS_CLOUDHSM"
}
# Text string relating to CM_XKSProxyConnTypes enum
$CM_XKSProxyConnTypesDef = @{
    [CM_CKSTypes]::VPC        = "VPC_ENDPOINT_SERVICE" 
    [CM_CKSTypes]::Public     = "PUBLIC_ENDPOINT"
}
# Text string relating to CM_SourceKeyTiers enum
$CM_SourceKeyTiersDef = @{
    [CM_CKSTypes]::Local      = "local" 
    [CM_CKSTypes]::HSM        = "luna-hsm"
}
# Text string relating to CM_CKSOps enum
$CM_CKSOpsDef = @{
    [CM_CKSOps]::CreateAWSKey = "create-aws-key" 
    [CM_CKSOps]::Block        = "block"
    [CM_CKSOps]::UnBlock      = "unblock"
    [CM_CKSOps]::Connect      = "connect"
    [CM_CKSOps]::Disconnect   = "disconnect"
    [CM_CKSOps]::Link         = "link"
    [CM_CKSOps]::RotateCred   = "rotate-credential"
}
####

####
# Local Variables
####
$target_uri_cks = "/cckm/aws/custom-key-stores"
$target_uri_vkey = "/cckm/virtual/keys"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - CCKM AWS CKS Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - CCKM AWS CKS Module"
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


<#
    .SYNOPSIS
        Create a new AWS Custom Key Store
    .DESCRIPTION
        This allows you to create the a new Custom Key Store on AWS with help of CCKM and CipherTrust Manager.
    .PARAMETER name
        Unique name for the custom key store.
    .PARAMETER aws_param
        Parameters related to AWS interaction with a custom key store.
    .PARAMETER kms
        Name or ID of the AWS Account container in which to create the key store.
    .PARAMETER region
        Name of the available AWS regions.
    .PARAMETER linked_state
        Indicates whether the custom key store is linked with AWS. Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.
    .PARAMETER local_hosted_params
        Parameters for a custom key store that is locally hosted.
#    .EXAMPLE
#        PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>
#
#        This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
#    .EXAMPLE
#        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable
#
#        This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
#    .EXAMPLE
#        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable
#
#        This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
#    .EXAMPLE
#        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey
#
#        This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>

function New-CKSAWSParam {
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $cloud_hsm_cluster_id,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $custom_key_store_type,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [SecureString] $key_store_password,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $trust_anchor_certificate,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $xks_proxy_connectivity,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $xks_proxy_uri_endpoint,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $xks_proxy_vpc_endpoint_service_name

    $aws_param = @()

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    #Optional
    Write-Debug "Creating aws_param section for CKS"
    if ($cloud_hsm_cluster_id) { $aws_param.add('cloud_hsm_cluster_id', $cloud_hsm_cluster_id) }
    if ($custom_key_store_type) { $aws_param.add('custom_key_store_type', $CM_CKSTypesDef[$custom_key_store_type]) }
    if ($key_store_password) { $aws_param.add('key_store_password', $key_store_password.Clear()) }
    if ($trust_anchor_certificate) { $aws_param.add('trust_anchor_certificate', $trust_anchor_certificate) }
    if ($xks_proxy_connectivity) { $aws_param.add('xks_proxy_connectivity', $CM_XKSProxyConnTypesDef[$xks_proxy_connectivity]) }
    if ($xks_proxy_uri_endpoint) { $aws_param.add('xks_proxy_uri_endpoint', $xks_proxy_uri_endpoint) }
    if ($xks_proxy_vpc_endpoint_service_name) { $aws_param.add('xks_proxy_vpc_endpoint_service_name', $xks_proxy_vpc_endpoint_service_name) }
    Write-Debug "aws_param updated: $($aws_param)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $aws_param
}

function New-CKSAWSKeyParamTags {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]] $tags, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $key,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $value
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($tags) {
        Write-Debug "existing tags: $($tags)"
    }
    else {
        Write-Debug "tags are empty"
        $tags =@()
    }

    $temp_hash = @{}

    if ($key) { $temp_hash.add('TagKey', $key) }
    if ($value) { $temp_hash.add('TagValue', $value) }
    Write-Debug "temp_hash: $($temp_hash)"

    #Add this current policy to the list of user set policies
    $tags += $temp_hash
    Write-Debug "tags updated: $($tags)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $tags
}

function New-CKSAWSKeyParam {
    [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true)]
    [string] $alias,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $description,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [hashtable] $policy,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [hashtable[]] $tags

    $aws_key_param = @()

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    #Optional
    Write-Debug "Creating aws_param section for CKS"
    if ($alias) { $aws_param.add('Alias', $alias) }
    if ($description) { $aws_param.add('Description', $description) }
    if ($policy) { $aws_param.add('Policy', $policy) }
    if ($tags) { $aws_param.add('Tags', $tags) }
    Write-Debug "aws_param updated: $($aws_key_param)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $aws_key_param
}

function New-CKSLocalHostedParam {
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [bool] $blocked,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $health_check_key_id,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $max_credentials,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $partition_id,
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [string] $source_key_tier,

    $local_hosted_params = @()

    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    #Optional
    Write-Debug "Creating local_hosted_params section for CKS"
    if ($blocked) { $local_hosted_params.add('blocked', $blocked) }
    if ($health_check_key_id) { $local_hosted_params.add('health_check_key_id', $health_check_key_id) }
    if ($max_credentials) { $local_hosted_params.add('max_credentials', $max_credentials) }
    if ($partition_id) { $local_hosted_params.add('partition_id', $partition_id) }
    if ($source_key_tier) { $local_hosted_params.add('source_key_tier', $CM_SourceKeyTiersDef[$source_key_tier]) }
    Write-Debug "aws_param updated: $($local_hosted_params)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $local_hosted_params
}

function New-CKS {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $aws_param,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $kms,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $name,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $region,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $linked_state,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $local_hosted_params
    )

    Write-Debug "Creating a new CKS on AWS"
    $endpoint = $CM_Session.REST_URL + $target_uri_cks
    Write-Debug "Endpoint: $($endpoint)"

    $cksId = $null

    # Mandatory Parameters
    $body = @{
        'aws_param'               = $aws_param
        'kms'                     = $kms
        'name'                    = $name
        'region'                  = $region
    }

    # Optional Parameters
    if ($linked_state) { $body.add('linked_state', $linked_state) }
    if ($local_hosted_params) { $body.add('local_hosted_params', $local_hosted_params) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"
    $jsonBody | Out-File -FilePath .\jsonBody.json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $cksId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Custom Key Store already exists"
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
    Write-Debug "AWS CKS created"
    return $cksId
}


function Edit-CKS {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $aws_param,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $local_hosted_params
    )

    Write-Debug "Update existing CKS on AWS"
    $endpoint = $CM_Session.REST_URL + $target_uri_cks
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id"

    # Mandatory Parameters
    $body = @{}

    # Optional Parameters
    if ($aws_param) { $body.add('aws_param', $aws_param) }
    if ($name) { $body.add('name', $name) }
    if ($local_hosted_params) { $body.add('local_hosted_params', $local_hosted_params) }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"
    $jsonBody | Out-File -FilePath .\jsonBody.json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'PATCH' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $cksId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Custom Key Store already exists"
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
    Write-Debug "AWS CKS created"
    return $cksId
}

function Remove-CKS {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Deleting CKS by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri_cks
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id"

    Write-Debug "Endpoint with ID: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
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
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }
    }
    Write-Debug "AWS CKS deleted"
    return
}

function Update-CKSPerformOperation {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $op_type,
        # Below params are for create-aws-key in a CKS
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $aws_key_param,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $external_accounts,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_admins,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_admins_roles,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_users,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_users_roles,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string] $policytemplate,
        # Below params are for connect op in a CKS
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [SecureString] $key_store_password,
        # Below params are for link op in a CKS
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $aws_param
    )

    Write-Debug "Perform operation on a CKS"
    $endpoint = $CM_Session.REST_URL + $target_uri_cks
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id" + "/" + $CM_CKSOpsDef[$op_type]

    $body = @{}

    # Conditional Parameters
    switch ($CM_CKSOpsDef[$op_type]) {
        "create-aws-key" { 
            # Mandatory param for op_type create-aws-key
            $body = @{
                'aws_param' = $aws_key_param
            }
            if ($external_accounts) { $body.add('external_accounts', $external_accounts) }
            if ($key_admins) { $body.add('key_admins', $key_admins) }
            if ($key_admins_roles) { $body.add('key_admins_roles', $key_admins_roles) }
            if ($key_users) { $body.add('key_users', $key_users) }
            if ($key_users_roles) { $body.add('key_users_roles', $key_users_roles) }
            if ($policytemplate) { $body.add('policytemplate', $policytemplate) }
        }
        "block" {}
        "unblock" {}
        "connect" {
            if ($key_store_password) { $body.add('key_store_password', $key_store_password) }
        }
        "disconnect" {}
        "link" {
            $body = @{
                'aws_param' = $aws_param
            }
        }
        "rotate-credential" {}
        Default {
            Write-Error "Invalid op_type value" 
            Stop
        }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"
    $jsonBody | Out-File -FilePath .\jsonBody.json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $cksId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Resource already exists"
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
    Write-Debug "CKS Operation Initialized!"
    return $cksId
}

# WIP
function New-VirtualKey {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $source_key_id
    )

    Write-Debug "Creating virtual key, which will be linked to a real key (in Luna HSM)."
    $endpoint = $CM_Session.REST_URL + $target_uri_vkey
    Write-Debug "Endpoint: $($endpoint)"

    $keyId = $null

    # Mandatory Parameters
    $body = @{
        'source_key_id'               = $source_key_id
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"
    $jsonBody | Out-File -FilePath .\jsonBody.json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $keyId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Virtual Key already exists"
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
    Write-Debug "Virtual Key Created"
    return $keyId
}

function New-HYOKKey {
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $aws_key_param,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $external_accounts,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_admins,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_admins_roles,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_users,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string[]] $key_users_roles,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false )]
        [string] $policytemplate,        
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable] $local_hosted_params
    )

    Write-Debug "Creating virtual key, which will be linked to a real key (in Luna HSM)."
    $endpoint = $CM_Session.REST_URL + $target_uri_vkey
    Write-Debug "Endpoint: $($endpoint)"

    $keyId = $null

    # Mandatory Parameters
    $body = @{
        'source_key_id'               = $source_key_id
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"
    $jsonBody | Out-File -FilePath .\jsonBody.json

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $keyId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Virtual Key already exists"
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
    Write-Debug "Virtual Key Created"
    return $keyId
}

Export-ModuleMember -Function New-CKS
Export-ModuleMember -Function New-CKSLocalHostedParam
Export-ModuleMember -Function New-CKSAWSParam
Export-ModuleMember -Function Remove-CKS
Export-ModuleMember -Function Edit-CKS
Export-ModuleMember -Function Update-CKSPerformOperation
Export-ModuleMember -Function New-VirtualKey