#######################################################################################################################
# File:             CipherTrustManager-ResourceSets.psm1                                                             #
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
# ResourceSet Types
Add-Type -TypeDefinition @"
public enum CM_CTEResourceSetTypes {
    Directory,
    Classification
}
"@
# Policy Element Types
Add-Type -TypeDefinition @"
public enum CM_CTEPolicyElementTypes {
    resourcesets,
    usersets,
    processsets,
    signaturesets
}
"@
####

####
# Support Variables
####
# Text string relating to CM_CTEResourceSetTypes enum
$CM_CTEResourceSetTypeDef = @{
    [CM_CTEResourceSetTypes]::Directory      = "Directory" 
    [CM_CTEResourceSetTypes]::Classification = "Classification"
}
#
# Text string relating to CM_CTEPolicyElementTypes enum
$CM_CTEPolicyElementTypeDef = @{
    [CM_CTEPolicyElementTypes]::resourcesets  = "resourcesets" 
    [CM_CTEPolicyElementTypes]::usersets      = "usersets"
    [CM_CTEPolicyElementTypes]::processsets   = "processsets"
    [CM_CTEPolicyElementTypes]::signaturesets = "signaturesets"
}
#
####

####
# Local Variables
####
$target_uri = "/transparent-encryption"
####

<#
    .SYNOPSIS
        Create a new resource set
    .DESCRIPTION
        This allows you to create a resource set on CipherTrust Manager and control a series of its parameters. Those parameters include: type, resources, resourceSetName
    .EXAMPLE
        PS> New-CMKey -keyname <keyname> -usageMask <usageMask> -algorithm <algorithm> -size <size>

        This shows the minimum parameters necessary to create a key. By default, this key will be created as a versioned key that can be exported and can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Undeleteable

        This shows the minimum parameters necessary to create a key that CANNOT BE DELETED. By default, this key will be created as a versioned key that can be exported
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -Unexportable

        This shows the minimum parameters necessary to create a key that CANNOT BE EXPORTED. By default, this key will be created as a versioned key that can be deleted
    .EXAMPLE
        PS> New-CMKey -keyname $keyname -usageMask $usageMask -algorithm $algorithm -size $size -NoVersionedKey

        This shows the minimum parameters necessary to create a key with NO VERSION CONTROL. By default, this key will be created can be exported and can be deleted
    .LINK
        https://github.com/thalescpl-io/CDSP_Orchestration/tree/main/PowerShell/CipherTrustManager
#>
function New-CTEPolicyElement {
    # classification_tags not supported yet
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $description,        
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $type,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $elementsList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string[]] $source_list
    )

    Write-Debug "Creating a policy element for a CTE policy in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $policyElementType
    Write-Debug "Endpoint: $($endpoint)"

    $elementId = $null

    # Mandatory Parameters
    $body = @{
        'name'  = $name
    }

    # Optional Parameters
    if ($description) { $body.add('description', $description) }

    if ([CM_CTEPolicyElementTypes]::resourcesets -eq $policyElementType) {
        if ($type) { $body.add('type', $type) }
        if ($elementsList.Length -gt 0) { $body.add('resources', $elementsList) }
    } elseif ([CM_CTEPolicyElementTypes]::usersets -eq $policyElementType) {
        if ($elementsList.Length -gt 0) { $body.add('users', $elementsList) }
    } elseif ([CM_CTEPolicyElementTypes]::processsets -eq $policyElementType) {
        if ($source_list.Length -gt 0) { $body.add('source_list', $source_list) }
    } elseif ([CM_CTEPolicyElementTypes]::signaturesets -eq $policyElementType) {
        if ($elementsList.Length -gt 0) { $body.add('processes', $elementsList) }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Write-Debug "Testing JWT"
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'POST' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
        Write-Debug "Response: $($response)"  
        $elementId = $response.id  
    }
    Catch {
        $StatusCode = $_.Exception.Response.StatusCode
        if ($StatusCode -EQ [System.Net.HttpStatusCode]::Conflict) {
            Write-Error "Error $([int]$StatusCode) $($StatusCode): Resource Set already exists"
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
    Write-Debug "Policy Element created"
    return $elementId
}

# Create a new array to hold resourceSet resources
function New-CTEElementsList {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [hashtable[]]$elementsList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $directory,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $file,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $hdfs,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [bool] $include_subfolders,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $signature,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $gid,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $gname,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $os_domain,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $uid,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $uname,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $file_name,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $hash_value
    )
    Write-Debug "Start: $($MyInvocation.MyCommand.Name)"

    if ($elementsList) {
        Write-Debug "array: $($elementsList)"
    }
    else {
        Write-Debug "array is empty"
        $elementsList = @()
    }

    $temp_hash = @{}
    
    #Optional
    if ([CM_CTEPolicyElementTypes]::resourcesets -eq $policyElementType) {
        if ($directory) {
            $temp_hash.add('directory', $directory)
        }
        if ($file) {
            $temp_hash.add('file', $file)
        }    
        if ($hdfs -ne $null) {
            $temp_hash.add('hdfs', $hdfs)
        }
        if ($include_subfolders -ne $null) {
            $temp_hash.add('include_subfolders', $include_subfolders)
        }
    } elseif ([CM_CTEPolicyElementTypes]::usersets -eq $policyElementType) {
        if ($gid) {
            $temp_hash.add('gid', $gid)
        }
        if ($gname) {
            $temp_hash.add('gname', $gname)
        }    
        if ($os_domain) {
            $temp_hash.add('os_domain', $os_domain)
        }
        if ($uid) {
            $temp_hash.add('uid', $uid)
        }
        if ($uname) {
            $temp_hash.add('uname', $uname)
        }
    } elseif ([CM_CTEPolicyElementTypes]::processsets -eq $policyElementType) {
        if ($directory) {
            $temp_hash.add('directory', $directory)
        }
        if ($file) {
            $temp_hash.add('file', $file)
        }
        if ($signature) {
            $temp_hash.add('signature', $signature)
        }
    } elseif ([CM_CTEPolicyElementTypes]::signaturesets -eq $policyElementType) {
        if ($file_name) {
            $temp_hash.add('file_name', $file_name)
        }
        if ($hash_value) {
            $temp_hash.add('hash_value', $hash_value)
        }
    }
    

    #Add this current policy to the list of user set policies
    $elementsList += $temp_hash
    Write-Debug "array updated: $($elementsList)"

    Write-Debug "End: $($MyInvocation.MyCommand.Name)"
    return $elementsList
}

function Find-CTEPolicyElementsByType {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
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

    Write-Debug "Getting a List of Policy Elements configured in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $policyElementType
    Write-Debug "Endpoint: $($endpoint)"

    #Set query
    if ($name) {
        $endpoint += "?name="
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Uri $endpoint -Body $jsonBody -Headers $headers -ContentType 'application/json'
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
    Write-Debug "List of Policy Elements created"
    return $response
}

function Remove-CTEPolicyElement {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Deleting a Policy Element by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $policyElementType
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
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    Write-Debug "CTE Policy Element deleted"
    return
}

function Update-CTEPolicyElement {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $description,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $elementsList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string[]] $source_list
    )

    Write-Debug "Update a Policy Element by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $CM_CTEPolicyElementTypeDef[$policyElementType]
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    $endpoint += "/$id"

    Write-Debug "Endpoint with ID: $($endpoint)"

    $body = @{}

    # Optional Parameters
    if ($description) { $body.add('description', $description) }

    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        if ($elementsList.Length -gt 0) { $body.add('resources', $elementsList) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        if ($elementsList.Length -gt 0) { $body.add('users', $elementsList) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "signaturesets") {
        if ($source_list.Length -gt 0) { $body.add('source_list', $source_list) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        if ($elementsList.Length -gt 0) { $body.add('processes', $elementsList) }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
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
    Write-Debug "Resource Set updated"
    return
}

function Update-CTEPolicyElementAddElements {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [hashtable[]] $elementsList,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string[]] $source_list
    )

    Write-Debug "Add elements to a Policy Element by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $CM_CTEPolicyElementTypeDef[$policyElementType]
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        $endpoint += "/$id" + "/addresources"
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        $endpoint += "/$id" + "/addusers"
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "signaturesets") {
        $endpoint += "/$id" + "/addsignatures"
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        $endpoint += "/$id" + "/addprocesses"
    }
    

    Write-Debug "Endpoint with ID: $($endpoint)"

    $body = @{}

    # Optional Parameters
    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        if ($elementsList.Length -gt 0) { $body.add('resources', $elementsList) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        if ($elementsList.Length -gt 0) { $body.add('users', $elementsList) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "signaturesets") {
        if ($elementsList.Length -gt 0) { $body.add('signatures', $elementsList) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        if ($elementsList.Length -gt 0) { $body.add('processes', $elementsList) }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
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
    Write-Debug "Resource Set updated"
    return
}

function Remove-CTEPolicyElementDeleteElements {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $policyElementType,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id
    )

    Write-Debug "Delete elements from a Policy Element by ID in CM"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $CM_CTEPolicyElementTypeDef[$policyElementType]
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        $endpoint += "/$id" + "/delresources"
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        $endpoint += "/$id" + "/delusers"
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        $endpoint += "/$id" + "/delprocesses"
    }

    Write-Debug "Endpoint with ID: $($endpoint)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
        $response = Invoke-RestMethod -SkipCertificateCheck -Method 'DELETE' -Uri $endpoint -Headers $headers -ContentType 'application/json'
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
    Write-Debug "Resource Set delete resources"
    return
}

function Update-CTEPolicyElementUpdateElementByIndex {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $id,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string] $elementIndex,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $directory,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string] $file,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $hdfs,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool] $include_subfolders,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $signature,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $gid,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $gname,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $os_domain,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [int] $uid,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true )]
        [string] $uname
    )

    Write-Debug "Update resource in a Policy Element by index"
    $endpoint = $CM_Session.REST_URL + $target_uri + "/" + $CM_CTEPolicyElementTypeDef[$policyElementType]
    Write-Debug "Endpoint: $($endpoint)"

    #Set ID
    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        $endpoint += "/$id" + "/updateresource" + "/" + $elementIndex
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        $endpoint += "/$id" + "/updateuser" + "/" + $elementIndex
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        $endpoint += "/$id" + "/updateprocess" + "/" + $elementIndex
    }

    Write-Debug "Endpoint with ID: $($endpoint)"

    $body = @{}

    # Optional Parameters
    if ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "resourcesets") {
        if ($directory) { $body.add('directory', $directory) }
        if ($file) { $body.add('file', $file) }
        if ($include_subfolders) { $body.add('include_subfolders', $include_subfolders) }
        if ($hdfs) { $body.add('hdfs', $hdfs) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "usersets") {
        if ($gid) { $body.add('gid', $gid) }
        if ($gname) { $body.add('gname', $gname) }
        if ($os_domain) { $body.add('os_domain', $os_domain) }
        if ($uid) { $body.add('uid', $uid) }
        if ($uname) { $body.add('uname', $uname) }
    } elseif ($CM_CTEPolicyElementTypeDef[$policyElementType] -eq "processsets") {
        if ($directory) { $body.add('directory', $directory) }
        if ($file) { $body.add('file', $file) }
        if ($signature) { $body.add('signature', $signature) }
    }
    

    $jsonBody = $body | ConvertTo-Json -Depth 5
    Write-Debug "JSON Body: $($jsonBody)"

    Try {
        Test-CMJWT #Make sure we have an up-to-date jwt
        $headers = @{
            Authorization = "Bearer $($CM_Session.AuthToken)"
        }
        Write-Debug "Headers: $($headers)"    
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
    Write-Debug "Resource Set delete resources"
    return
}

Export-ModuleMember -Function New-CTEPolicyElement
Export-ModuleMember -Function New-CTEElementsList
Export-ModuleMember -Function Find-CTEPolicyElementsByType
Export-ModuleMember -Function Remove-CTEPolicyElement
Export-ModuleMember -Function Update-CTEPolicyElement
Export-ModuleMember -Function Update-CTEPolicyElementAddElements
Export-ModuleMember -Function Remove-CTEPolicyElementDeleteElements
Export-ModuleMember -Function Update-CTEPolicyElementUpdateElementByIndex