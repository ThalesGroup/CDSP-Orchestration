#Test
Import-Module CipherTrustManager -Force -ErrorAction Stop
Connect-CipherTrustManager -server 192.168.2.187 -user "admin" -pass "ChangeIt01!"

# Get CA ID
$CA = Find-CMCAs -subject '/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA'
Write-Output $CA

# Create Key
## Get User ID from username
$user = Find-CMUsers -username 'admin'
$user_id = $user.resources.user_id

## Create Key Metadata
$permissions = @('CTE Clients')
$keyMetaPermissions = New-CMKeyMetaPermission -DecryptWithKey $permissions -EncryptWithKey $permissions -ExportKey $permissions -MACVerifyWithKey $permissions -MACWithKey $permissions -ReadKey $permissions -SignVerifyWithKey $permissions -SignWithKey $permissions -UseKey $permissions
$keyMetaCTE = New-CMKeyMetaCTEParams -persistent_on_client $true -encryption_mode 'CBC' -cte_versioned $false
$keyMeta = New-CMKeyMeta -ownerId $user_id -permissions $keyMetaPermissions -cte $keyMetaCTE

## Create CTE Key
$key = New-CMKey -name 'CTE_HIPAA_Key' -usageMask 76 -algorithm 'aes' -size 256 -Undeletable $false -Unexportable $false -meta $keyMeta -xts $false

Write-Output $key

# Create Client Registration Token
$token = New-CM_ClientToken -ca_id $CA -name_prefix 'PowerShell'
Write-Output $token

# Create CTE client first
New-CTEClient -name 'ps_cteclient' -client_locked $false -client_type 'FS' -registration_allowed $true -system_locked $false
$clients = Find-CTEClients -name 'ps_cteclient'

## Enable LDT for the above client
# This is not working as of now...
#Update-CTEClient -id $clients.resources.id -enabled_capabilities 'LDT'

# Creating CTE Policy Element ResourceSet
$rsetList = New-CTEElementsList -policyElementType 'resourcesets' -directory '/opt/path1/' -file '*' -hdfs $False -include_subfolders $False
$resourceSet = New-CTEPolicyElement -policyElementType 'resourcesets' -name 'ps_resource_set' -type 'Directory' -elementsList $rsetList

# Creating security_rules list for CTE Policy
$secRulesList = New-CTEPolicySecurityRulesList -action 'key_op' -effect 'permit,applykey' -partial_match $false
$secRulesList = New-CTEPolicySecurityRulesList -securityRulesList $secRulesList -resource_set_id $resourceSet -exclude_resource_set $false -action 'all_ops' -effect 'permit,applykey' -partial_match $true

# Creating LDT Key Rules list for CTE Policy
$current_key = New-CTELDTKey -key_id $key
$transformation_key = New-CTELDTKey -key_id 'clear_key' -key_type 'name'
$ldtKeyRulesList = New-CTEPolicyLDTKeyRulesList -is_exclusion_rule $false -resource_set_id $resourceSet -current_key $current_key -transformation_key $transformation_key

# Create CTE Policy
$cteMeta = New-CTEPolicyMetadata -restrict_update $false
$policy=New-CTEPolicy -name 'psPolicy' -policy_type 'LDT' -never_deny $false -security_rules $secRulesList -ldt_key_rules $ldtKeyRulesList -meta $cteMeta

Write-Output $policy

$params = New-CTEGuardPointParams -guard_point_type 'directory_auto' -policy_id 'psPolicy'
$paths = @('/opt/path1/')

New-CTEClientGuardPoint -client_id $clients.resources.id -guard_paths $paths -guard_point_params $params