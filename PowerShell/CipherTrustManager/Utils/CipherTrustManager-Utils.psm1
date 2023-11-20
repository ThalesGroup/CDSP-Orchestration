#######################################################################################################################
# File:             CipherTrustManager-Tokens.psm1                                                                    #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Notes:            This module is loaded by the master module, CipherTrustManager                                    #
#                   Do not load this directly                                                                         #
#######################################################################################################################

#Need JWTDetails module to see how much time is left on a JWT
Install-Module -name JWTDetails -Force

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


<#
    .SYNOPSIS
        Authenitcate with CipherTrust Manager, get a JWT and store it in the header as a BEARER token for use in future calls

    .DESCRIPTION
        This function gets all of its necessary information from $CM_Session variables within this module
    .EXAMPLE
        PS> Get-CMJWT
    .NOTES
        NOT EXPORTED. INTERNAL ONLY
#>
function Get-CMJWT {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    $CM_Session.AuthToken = $null
    $REST_URL = $CM_Session.REST_URL + "/auth/tokens"

    if($CM_Session.Pass){
        $Body = @{
            grant_type = "password"
            username = $CM_Session.User
            password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CM_Session.Pass))
            domain   = $CM_Session.Domain
        }
    }elseif($CM_Session.refresh_token){
        $Body = @{
            grant_type = "refresh_token"
            refresh_token = $CM_Session.refresh_token
        }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "Current JSON Body: `n$($jsonBody)"

    Try {
        $response = Invoke-RestMethod -Method 'POST' -Uri $REST_URL -Body $jsonBody -ContentType 'application/json'
        Write-Debug "Response: $($response)"
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($null -eq $StatusCode) {
            Write-Error "Connection Timeout Error. Unable to reach CipherTrust Manager." -ErrorAction Stop
        }
        else {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): $($_.Exception.Response.ReasonPhrase)" -ErrorAction Stop
        }    
    }

    $CM_Session.AuthToken = $response.jwt 
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}

<#
    .SYNOPSIS
        Authenitcate with CipherTrust Manager, get a JWT and store it in the header as a BEARER token for use in future calls

    .DESCRIPTION
        This function gets all of its necessary information from $CM_Session variables within this module
    .EXAMPLE
        PS> Get-CMJWT
    .NOTES
        NOT EXPORTED. INTERNAL ONLY
#>
function Test-CMJWT {
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "Time to expire (sec): $((get-jwtdetails $CM_Session.AuthToken).timeToExpiry.TotalSeconds)"
    try {
        if ((get-jwtdetails $CM_Session.AuthToken).timeToExpiry.TotalSeconds -lt 60) {
            Write-Debug "JWT is close to or past expiry. Refreshing token."
            Get-CMJWT
        }
        else {
            Write-Debug "JWT not close to or past expiry"
        }
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

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return
}
####

<#
    .SYNOPSIS
        Display a Hashtable Array ([hashtable[]]) in a decent format
    .DESCRIPTION
        This walks through a Hashtable Array and displays it well on the screen when in DEBUG mode
    .EXAMPLE
        PS> Write-HashtableArray $hashtable_array

        Display contents of Hashtable Array when DEBUG mode is on
    .EXAMPLE
        PS> Write-HashtableArray $hashtable_array

        Force the display even if the code being run is NOT in DEBUG mode 
    .NOTES
        NOT EXPORTED. INTERNAL ONLY
#>
function Write-HashtableArray {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [AllowEmptyCollection()]
        [hashtable[]]$Hashtables
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    Write-Debug "@("
    foreach ($hashtable in $Hashtables) {
        Write-Debug "  @{"
        foreach ($entry in $hashtable.GetEnumerator()) {
            Write-Debug "     $($entry.Key) = $($entry.Value)"
        }
        Write-Debug "  }"
    }
    Write-Debug ")"    
    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
}

Export-ModuleMember -Function Get-CMJWT
Export-ModuleMember -Function Test-CMJWT
Export-ModuleMember -Function Write-HashtableArray
