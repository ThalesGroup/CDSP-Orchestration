#######################################################################################################################
# File:             CipherTrustManager-DPGPolicies.psm1                                                        #
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
#Interface Types
Add-Type -TypeDefinition @"
   public enum CM_ApplicationOperations {
    Protect,
    Reveal
}
"@
####

####
# Local Variables
####
$target_uri = "/data-protection/dpg-policies"
####

#Allow for backwards compatibility with PowerShell 5.1
#Set default Param for Invoke-RestMethod in PS 6+ to "-SkipCertificateCheck" to true.
#For PS 5.x to use SSL handler bypass code.

if($PSVersionTable.PSVersion.Major -ge 6){
    Write-Debug "Setting PS6+ Defaults - DPG Policies Module"
    $PSDefaultParameterValues = @{
        "Invoke-RestMethod:SkipCertificateCheck"=$True
        "ConvertTo-JSON:Depth"=5
    }
}else{
    Write-Debug "Setting PS5.1 Defaults - DPG Policies Module"
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
        Create a new DPG policy
    .DESCRIPTION
        This allows you to create the configuration for DPG describing the endpoints with the data protection rules for data on those endpoints.
    .PARAMETER name
        Name to use for the DPG policy.
    .PARAMETER description
        Description of the DPG policy.
    .PARAMETER proxy_config
        List of API urls to be added to the proxy configuration.
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
function New-CMDPGPolicy {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $description,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $proxy_config
    )

    Write-Debug "Creating a DPG Policy in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    $dpgPolicyId = $null

    # Mandatory Parameters
    $body = @{
        'name'               = $name
    }

    # Optional Parameters
    if ($description) { $body.add('description', $description) }
    if ($proxy_config) { $body.add('proxy_config', $proxy_config) }

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
        $dpgPolicyId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Protection Policy already exists"
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
    Write-Debug "DPG Policy created"
    return $dpgPolicyId
}    


function Find-CMDPGPolicies {
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

    Write-Debug "Getting a List of DPG Policies configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    #$firstset = $false
    if ($name) {
        $endpoint += "?name="
        #$firstset = $true
        $endpoint += $name            
    }

    if ($skip) {
        $endpoint += "&skip="
        $endpoint += $skip
    }

    if ($limit) {
        $endpoint += "&limit="
        $endpoint += $limit
    }

    Write-Debug "Endpoint w Query: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod  -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "List of DPG Policies created"
    return $response
}    


function Remove-CMDPGPolicy {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Deleting a DPG Policy by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri
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
    Write-Debug "DPG Policy deleted"
    return
}    

 
function New-CMDPGProxyConfig {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$proxy_config,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
            ($_ -match '^/*') #must start with a forward slash (endpoint urls)
            })]
        [string] $api_url, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]] $json_request_post_tokens, 
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]] $json_response_get_tokens
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($proxy_config) {
        Write-Debug "proxy_config: $($proxy_config)"
    }
    else {
        Write-Debug "proxy_config is empty"
        $proxy_config = @()
    }

    $temp_hash = @{}

    #Mandatory
    $temp_hash.add('api_url', $api_url)
    
    #Optional
    if ($json_request_post_tokens -AND $json_response_get_tokens) {
        Write-Error "Require either $json_request_post_tokens -OR $json_response_get_tokens but not both. Use separate calls." -ErrorAction Stop
    } 

    if (-NOT ($json_request_post_tokens -OR $json_response_get_tokens)) {
        Write-Error "Require either $json_request_post_tokens -OR $json_response_get_tokens" -ErrorAction Stop
    }

    if ($json_request_post_tokens) {
        $temp_hash.add('json_request_post_tokens', $json_request_post_tokens)
    }
    if ($json_response_get_tokens) {
        $temp_hash.add('json_response_get_tokens', $json_response_get_tokens)
    }

    #Add this current policy to the list of user set policies
    $proxy_config += $temp_hash
    Write-Debug "proxy_config updated: $($proxy_config)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $proxy_config
}

function New-CMDPGJSONRequestResponse {
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]] $json_tokens, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [CM_ApplicationOperations] $operation, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true )]
        [string] $protection_policy,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $access_policy
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($json_request_post_tokens) {
        Write-Debug "json_tokens: $($json_tokens)"
    }
    else {
        Write-Debug "json_tokens is empty"
        $json_tokens = @()

    }

    $temp_hash = @{}

    #Mandatory
    $temp_hash.add('name', $name)
    if ([CM_ApplicationOperations]::Protect -eq $operation) {
        $temp_hash.add('operation', 'protect')
    }
    if ([CM_ApplicationOperations]::Reveal -eq $operation) {
        $temp_hash.add('operation', 'reveal')
    }
    $temp_hash.add('protection_policy', $protection_policy)
    
    #Optional
    if ([CM_ApplicationOperations]::Reveal -eq $operation) {
        if ($access_policy) { 
            $temp_hash.add('access_policy', $access_policy) 
        }
        else {
            Write-Error "Missing access_policy to go with '-operation [CM_ApplicationOperations]::Reveal'" -ErrorAction Stop
        }
    }

    #Add this current policy to the list of user set policies
    $json_tokens += $temp_hash
    Write-Debug "json_tokens updated: $($json_tokens)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $json_tokens
}

Export-ModuleMember -Function Find-CMDPGPolicies
Export-ModuleMember -Function New-CMDPGPolicy
Export-ModuleMember -Function Remove-CMDPGPolicy
Export-ModuleMember -Function New-CMDPGProxyConfig
Export-ModuleMember -Function New-CMDPGJSONRequestResponse