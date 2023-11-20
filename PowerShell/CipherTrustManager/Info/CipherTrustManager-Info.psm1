#######################################################################################################################
# File:             CipherTrustManager-Info.psm1                                                                  #
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
$target_uri = "/system/info"
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


#This project mirrors the "INfo" section of the API Playground of CM (/playground_v2/api/Info)

#Info
#"#/v1/system/info"

<#
    .SYNOPSIS
        Get Info
    .DESCRIPTION
        Returns this system's info attributes.
    .EXAMPLE
        PS> Get-CMInfo

        Returns this system's info attributes. 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMInfo {
    param()
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting System Info of CipherTrust Manager"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"
    
    #No query to set
    
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
        elseif ([int]$StatusCode -EQ 0) {
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
    
<#
    .SYNOPSIS
        Get Version
    .DESCRIPTION
        Helper fucntion to Get-CMInfo that returns the CM version (major, minor) only
    .EXAMPLE
        PS> Get-CMVersion

        Returns the major and minor version numbers as an object 
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Get-CMVersion {
    param()
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"
    
    Write-Debug "Getting the version of CipherTrust Manager"    
    $CM_Info = Get-CMInfo
    Write-Debug "Info data was: $($CM_Info)"    
    
    $CM_Version = @{}
    $version_info = ($CM_Info.version).Split(".")
    Write-Debug "vsrion_info was: $($version_info)"    
    $CM_Version.add('major', $version_info[0]) 
    $CM_Version.add('minor', $version_info[1])
    $patch_info = $version_info[2].Split("-") 
    $CM_Version.add('patch', $patch_info[0]) 
    $CM_Version.add('build', $patch_info[1])
    Write-Debug "Version data is: $($CM_Version)"    
    

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $CM_Version
}    

#Info
#"#/v1/system/info/"

<#
    .SYNOPSIS
        Set Name of CipherTrust Manager server
    .DESCRIPTION
        Set the NAME of CipherTrust Manager server through system info. Only the name can be set - other attributes in the body are invalid.    
    .PARAMETER name
        New name for CipherTrust Manager server 
    .EXAMPLE
        PS> Set-CMName -name <server name>

        This sets the name of the server to "server name".
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function Set-CMName {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Setting the name of CM Server"
    $endpoint = $CM_Session.REST_URL + $target_uri
    Write-Debug "Endpoint: $($endpoint)"

    # Mandatory Parameters
    $body = @{
        'name' = $name
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


####
# Export Module Members
####
#Info
#"#/v1/system/info/"
Export-ModuleMember -Function Get-CMInfo    #List (get)
Export-ModuleMember -Function Get-CMVersion #List (get)
Export-ModuleMember -Function Set-CMName    #Change (patch)
