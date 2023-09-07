#######################################################################################################################
# File:             CipherTrustManager.psd1                                                                           #
# Author:           Anurag Jain, Developer Advocate                                                                   #
# Author:           Marc Seguin, Developer Advocate                                                                   #
# Publisher:        Thales Group                                                                                      #
# Copyright:        (c) 2022 Thales Group. All rights reserved.                                                       #
# Usage:            To load this module in your PowerShell:                                                           #
#                   1. Open PowerShell (or PowerShell ISE).                                                           #
#                   2. Run the following commands                                                                     #
#                      Import-Module -Name CipherTrustManager                                                         #
#######################################################################################################################

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'CipherTrustManager.psm1'

    # Version number of this module.
    ModuleVersion     = '0.0.1'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = '26a7684c-a2f4-4a44-814b-23fa6871d0e7'

    # Author of this module
    Author            = 'Anurag Jain & Marc Seguin, Developer Advocates'

    # Company or vendor of this module
    CompanyName       = 'Thales Group'

    # Copyright statement for this module
    Copyright         = '(c) Thales Group. All rights reserved.'

    # Description of the functionality provided by this module
    # Description = ''

    # Minimum version of the PowerShell engine required by this module
    # PowerShellVersion = '5.1'
    PowerShellVersion = '7.0'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()   

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules     = @(
        "JWTDetails",
        "Utils/CipherTrustManager-Utils",
        "CertificateAuthority/CipherTrustManager-CAs",
        "DataProtection/CipherTrustManager-CharacterSets",
        "DataProtection/CipherTrustManager-UserSets",
        "DataProtection/CipherTrustManager-MaskingFormats",
        "DataProtection/CipherTrustManager-ProtectionPolicies",
        "DataProtection/CipherTrustManager-AccessPolicies",
        "DataProtection/CipherTrustManager-DPGPolicies",
        "DataProtection/CipherTrustManager-ClientProfiles",
        "Info/CipherTrustManager-Info",
        "Interfaces/CipherTrustManager-Interfaces",
        "Keys/CipherTrustManager-Keys",
        "Users/CipherTrustManager-Users",
        "SyslogConnections/CipherTrustManager-SyslogConnections",
        "CTE/CipherTrustManager-CTEPolicyElements",
        "CTE/CipherTrustManager-CTEPolicies",
        "CTE/CipherTrustManager-CTEClients",
        "CTE/CipherTrustManager-CSIStorageGroups",
        "Client-Management/CipherTrustManager-Tokens"
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        "Connect-CipherTrustManager",
        "Disconnect-CipherTrustManager",
        "Find-CMKeys",
        "New-CMKey",
        "Remove-CMKey",
        "Find-CMUsers",
        "New-CMUser",
        "Get-CMUser",
        "Remove-CMUser",
        "Get-CMInfo",
        "Get-CMVersion",
        "Set-CMName",
        "Find-CMInterfaces",
        "New-CMInterface",
        "Remove-CMInterface",
        "Find-CMCAs",
        "Find-CMCharacterSets",
        "New-CMCharacterSet",
        "Remove-CMCharacterSet",
        "Find-CMUserSets",
        "New-CMUserSet",
        "Remove-CMUserSet",
        "Find-CMMaskingFormats",
        "New-CMMaskingFormat",
        "Remove-CMMaskingFormat",
        "Find-CMProtectionPolicies",
        "New-CMProtectionPolicy",
        "Remove-CMProtectionPolicy",
        "Find-CMAccessPolicies",
        "New-CMAccessPolicy",
        "Remove-CMAccessPolicy",
        "New-CMUserSetPolicy",
        "Find-CMDPGPolicies",
        "New-CMDPGPolicy",
        "Remove-CMDPGPolicy",
        "New-CMDPGProxyConfig",
        "New-CMDPGJSONRequestResponse",
        "Find-CMClientProfiles",
        "New-CMClientProfiles",
        "Remove-CMClientProfiles",        
        "Get-CMJWT",
        "Test-CMJWT",
        "Write-HashtableArray",
        #"New-CKSAWSParam",
        #"New-CKSLocalHostedParam",
        #"New-CKS",
        #"Remove-CKS",
        #"Edit-CKS",
        #"Update-CKSPerformOperation",
        "Find-CMSyslogs",
        "New-CMSyslog",
        "Get-CMSyslog",
        "Remove-CMSyslog",
        "Set-CMSyslog" ,
        # CTE Specific Stuff
        "New-CTEPolicyElement",
        "New-CTEElementsList",
        "Find-CTEPolicyElementsByType",
        #"Remove-CTEPolicyElement",
        #"Update-CTEPolicyElement",
        #"Update-CTEPolicyElementAddElements",
        #"Remove-CTEPolicyElementDeleteElements",
        #"Update-CTEPolicyElementUpdateElementByIndex",
        "New-CTEPolicy",
        "New-CTEPolicyDataTxRulesList",
        "New-CTEPolicyIDTKeyRulesList",
        "New-CTEPolicyKeyRulesList",
        "New-CTEPolicyLDTKeyRulesList",
        "New-CTEPolicySecurityRulesList",
        "New-CTEPolicySignatureRulesList",
        "New-CTELDTKey",
        "New-CTEPolicyMetadata",
        "New-CTEClient",
        "Find-CTEClients",
        "Update-CTEClient",
        "New-CTEGuardPointParams",
        "New-CTEClientGuardPoint",
        "Find-CTEClientGuardPoints",
        "Remove-CTEClientGuardPoint",
        "New-CTECSIStorageGroup",
        "Find-CTECSIStorageGroups",
        "Remove-CTECSIStorageGroup",
        "New-CTEAddClientsStorageGroup",
        "New-CTEAddGuardPoliciesStorageGroup",
        # Added next 3
        "New-CMKeyMeta",
        "New-CMKeyMetaPermission",
        "New-CMKeyMetaCTEParams",
        "New-CM_ClientToken"
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            # ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}

