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

    $Body = @{
        #        grant_type = "password"
        username = $CM_Session.User
        password = $CM_Session.Pass
    }
    
    Try {
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $REST_URL -Body $Body
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
