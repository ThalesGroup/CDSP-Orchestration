# PowerShell Module for CipherTrust Manager (CDSP_Orchestration)
This PowerShell Module offers simple integration between a PowerShell script and CipherTrust Manager

## Prerequisite

Download this module (available as [CipherTrustManager.zip](CipherTrustManager.zip) for simplicity) and put it in the Modules directory on your Windows computer. These Modules are usually put in C:\Users\<current user>\Documents\WindowsPowerShell\Modules but you can install it anywhere the $Env:PSModulePath can find it


## Usage

1. In your PowerShell script, add `Import-Module CipherTrustManager -Force -ErrorAction Stop`. The `-Force` will ensure that the module is overwritten if already loaded. The `-ErrorAction Stop` will abort your script if the module cannot be found.
2. #Initialize and authenticate a connection with CipherTrust Manager

```powershell
Connect-CipherTrustManager `
    -server <ip_address_of_CipherTrust_Manager> `
    -user <account_with_access> `
    -pass <password_for_that_account> `
    -domain <sub-domain_to_authenticate_into> #(optional)
```
```powershell
Connect-CipherTrustManager `
    -server <ip_address_of_CipherTrust_Manager> `
    -refresh_token <CM_generated_refresh_token> `
    -domain <sub-domain_to_authenticate_into> #(optional)
```

3. At this point, you are connected and authenticated so you can make any calls that the REST API and PowerShell Module supports

## What's in the Module so far

    .
    ├── README.md              
    ├── CipherTrustManager.psd1                             	# Module Manafest
    ├── CipherTrustManager.psm1                             	# Primary Module (Loads all submodules)
    ├── CertificateAuthority                                	# A Certificate Authority (CA) issues and installs digital certificates and certificate signing requests (CSR).
    │   ├── CipherTrustManager-CAs.psm1                     	# Module to configure the Certificat Authority (CA).    
    ├── Connections                                         	# CipherTrust Manager Connections (Identity Providers - IdP)
    │   ├── CipherTrustManager-Connections-IdP 	            	# Manage the creation, deletion, and testing of connection to an LDAP or OIDC Identity Provider for CM Authentication.
    ├── ConnectionsMgr                                      	# CipherTrust Manager Connection Manager
    │   ├── CipherTrustManager-ConnectionMgr-Main           	# Main Module - Used for find all connections within CipherTrust Manager.
    │   ├── CipherTrustManager-ConnectionMgr-AWS            	# Manage the creation, deletion, and testing of connection to AWS for CCKM.
    │   ├── CipherTrustManager-ConnectionMgr-Akeyless       	# Manage the creation, deletion, and testing of connection to Akeyless for CCKM.
    │   ├── CipherTrustManager-ConnectionMgr-Azure          	# Manage the creation, deletion, and testing of connection to Azure for CCKM.
    │   ├── CipherTrustManager-ConnectionMgr-DSM            	# Manage the creation, deletion, and testing of connection to DSMs for CCKM.
    │   ├── CipherTrustManager-ConnectionMgr-Elasticsearch  	# Manage the creation, deletion, and testing of connection to Elasticsearch for Log Forwarding.
    │   ├── CipherTrustManager-ConnectionMgr-Google         	# Manage the creation, deletion, and testing of connection to Google Cloud for CCKM.
    │   ├── CipherTrustManager-ConnectionMgr-Hadoop         	# Manage the creation, deletion, and testing of connection to Hadoop for DDC.
    │   ├── CipherTrustManager-ConnectionMgr-LDAP           	# Manage the creation, deletion, and testing of connection to an LDAP Provider for CTE Usage.
    │   ├── CipherTrustManager-ConnectionMgr-Loki           	# Manage the creation, deletion, and testing of connection to Loki for Log Forwarding.
    │   ├── CipherTrustManager-ConnectionMgr-LunaHSMConnections # Manage the creation, deletion, and testing of connection Luna HSM Partitions.
    │   ├── CipherTrustManager-ConnectionMgr-LunaHSMServer  	# Manage the creation, deletion, and testing of connection to Luna Network HSMs.
    │   ├── CipherTrustManager-ConnectionMgr-LunaHSMSTCPartitions # Manage the creation, deletion, and testing of connection of Luna STC Partitions. (EXPERIMENTAL)
    │   ├── CipherTrustManager-ConnectionMgr-OIDC               # Manage the creation, deletion, and testing of connection to an OIDC Provider for CTE Usage.
    │   ├── CipherTrustManager-ConnectionMgr-Oracle             # Manage the creation, deletion, and testing of connection to an Oracle Cloud Infrastructure instance..
    │   ├── CipherTrustManager-ConnectionMgr-SAP               	# Manage the creation, deletion, and testing of connection to a SAP Data Custodian instance.
    │   ├── CipherTrustManager-ConnectionMgr-SCP               	# Manage the creation, deletion, and testing of connection to a SCP Connections for Backups..
    │   ├── CipherTrustManager-ConnectionMgr-SMB               	# Manage the creation, deletion, and testing of connection to a SMB Connections for CTE over CIFS.
    │   ├── CipherTrustManager-ConnectionMgr-Salesforce         # Manage the creation, deletion, and testing of connection to a Salesforce Shield Key Management.
    │   ├── CipherTrustManager-ConnectionMgr-Syslog             # Manage the creation, deletion, and testing of connection to a Syslog for Log Forwarding.
    ├── CCKM                                                	# CipherTrust Cloud Key Manager can manage the lifecycle of CSP keys as well as create them
    │   ├── CipherTrustManager-CCKM-AWSCKS.psm1             	# Manage keys within AWS
    ├── DataProtection                                      	# Data protection is a centralized place for all Application and Database encryption configuration.
    │   ├── CipherTrustManager-AccessPolicies.psm1          	# Manage how a user/app can `access` data through the `Reveal` API
    │   ├── CipherTrustManager-ClientProfiles.psm1          	# Create the Client Profile of how an Application or Database is protected as seen in `Application Data Protection` tile of CipherTrust Manager
    │   ├── CipherTrustManager-CharacterSets.psm1           	# A character set is used with format preserving algorithms to define characters that are to be included for protection. For example when encrypting a credit card number a user will want the encrypted data to only contain numbers.
    │   ├── CipherTrustManager-DPGPolicies.psm1             	# Configure the DPG Policy that contains a set of URLs tied with encryption parameters
    │   ├── CipherTrustManager-MaskingFormats.psm1          	# Create a set of Masking Formats that determine HOW data will be revealed (e.g. Show last four chars, Hide first six chars)
    │   ├── CipherTrustManager-ProtectionPolicies.psm1      	# Manage how specific data is protected by defining critical parameters like the cipher and key to use through the `Protect` API
    │   ├── CipherTrustManager-UserSets.psm1                	# Manage lists of users that can be assigned to HOW data is presented by the `Reveal` API
    ├── Domains
    │   ├── CipherTrustManager-Domains.psm1                 	# Manage the creation and deletion of domains. 
    ├── Info                                                	# These endpoints allow the user to query for some basic information from CipherTrust Manager - the name, version and model number, vendor of the platform. It is also possible to update the platform name to something that is illustrative to the user.
    │   ├── CipherTrustManager-Info.psm1                    	# Manage System Information inclding ability to change name of CipherTrust Manager server
    ├── Interfaces                                          	# Interfaces are the services the CipherTrust Manager is hosting. Most interfaces are listening on a particular port, but may also represent other input channels, like local shell access or serial port access.
    │   ├── CipherTrustManager-Interfaces.psm1              	# Manage interfaces
    ├── Keys                                                	# Keys are the cryptographic material used in crypto operations.
    │   ├── CipherTrustManager-Keys.psm1                    	# Manage keys
    ├── Syslog Connections                                  	# Users are unique individuals or systems using the API.
    │   ├── CipherTrustManager-SyslogConnections.psm1       	# Manage connections to remote syslog servers.
    ├── Users                                               	# Users are unique individuals or systems using the API.
    │   ├── CipherTrustManager-Users.psm1                   	# Manage Users.
    └── Utils                                               	# Miscellaneous Utilities including managing lifecycle of the Authentication Token (JWT).
        └── CipherTrustManager-Utils.psm1                   

## Notes
As best we could, we have added documentation and help to the module. To see what a command can do AND get examples:

* For basic help
  
```powershell
Get-Help Connect-CipherTrustManager
```

* To see examples

```powershell
Get-Help Connect-CipherTrustManager -examples
```

* For full help

```powershell
Get-Help Connect-CipherTrustManager -full
```



