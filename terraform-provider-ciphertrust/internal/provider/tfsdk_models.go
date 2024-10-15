package provider

import "github.com/hashicorp/terraform-plugin-framework/types"

type HKDFParameters struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	IKMKeyName    types.String `tfsdk:"ikm_key_name"`
	Info          types.String `tfsdk:"info"`
	Salt          types.String `tfsdk:"salt"`
}

type KeyMetadataPermissions struct {
	DecryptWithKey    []types.String `tfsdk:"decrypt_with_key"`
	EncryptWithKey    []types.String `tfsdk:"encrypt_with_key"`
	ExportKey         []types.String `tfsdk:"export_key"`
	MACVerifyWithKey  []types.String `tfsdk:"mac_verify_with_key"`
	MACWithKey        []types.String `tfsdk:"mac_with_key"`
	ReadKey           []types.String `tfsdk:"read_key"`
	SignVerifyWithKey []types.String `tfsdk:"sign_verify_with_key"`
	SignWithKey       []types.String `tfsdk:"sign_with_key"`
	UseKey            []types.String `tfsdk:"use_key"`
}

type KeyMetadataCTE struct {
	PersistentOnClient types.Bool   `tfsdk:"persistent_on_client"`
	EncryptionMode     types.String `tfsdk:"encryption_mode"`
	CTEVersioned       types.Bool   `tfsdk:"cte_versioned"`
}

type KeyMetadata struct {
	OwnerId     types.String           `tfsdk:"owner_id"`
	Permissions KeyMetadataPermissions `tfsdk:"permissions"`
	CTE         KeyMetadataCTE         `tfsdk:"cte"`
}

type KeyAlias struct {
	Alias types.String `tfsdk:"alias"`
	Index types.Int64  `tfsdk:"index"`
	Type  types.String `tfsdk:"type"`
}

type PublicKeyParameters struct {
	ActivationDate   types.String `tfsdk:"activation_date"`
	Aliases          []KeyAlias   `tfsdk:"aliases"`
	ArchiveDate      types.String `tfsdk:"archive_date"`
	DeactivationDate types.String `tfsdk:"deactivation_date"`
	Name             types.String `tfsdk:"name"`
	State            types.String `tfsdk:"state"`
	UnDeletable      types.Bool   `tfsdk:"undeletable"`
	UnExportable     types.Bool   `tfsdk:"unexportable"`
	UsageMask        types.Int64  `tfsdk:"usage_mask"`
}

type WrapHKDF struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	Info          types.String `tfsdk:"info"`
	OKMLen        types.Int64  `tfsdk:"okm_len"`
	Salt          types.String `tfsdk:"salt"`
}

type WrapPBE struct {
	DKLen                  types.Int64  `tfsdk:"dklen"`
	HashAlgorithm          types.String `tfsdk:"hash_algorithm"`
	Iteration              types.Int64  `tfsdk:"iteration"`
	Password               types.String `tfsdk:"password"`
	PasswordIdentifier     types.String `tfsdk:"password_identifier"`
	PasswordIdentifierType types.String `tfsdk:"password_identifier_type"`
	Purpose                types.String `tfsdk:"purpose"`
	Salt                   types.String `tfsdk:"salt"`
}

type WrapRSAAES struct {
	AESKeySize types.Int64  `tfsdk:"aes_key_size"`
	Padding    types.String `tfsdk:"padding"`
}

type tfsdkCMKeyModel struct {
	ID                       types.String        `tfsdk:"id"`
	ActivationDate           types.String        `tfsdk:"activation_date"`
	Algorithm                types.String        `tfsdk:"algorithm"`
	ArchiveDate              types.String        `tfsdk:"archive_date"`
	AssignSelfAsOwner        types.Bool          `tfsdk:"assign_self_as_owner"`
	CertType                 types.String        `tfsdk:"cert_type"`
	CompromiseDate           types.String        `tfsdk:"compromise_date"`
	CompromiseOccurrenceDate types.String        `tfsdk:"compromise_occurrence_date"`
	Curveid                  types.String        `tfsdk:"curveid"`
	DeactivationDate         types.String        `tfsdk:"deactivation_date"`
	DefaultIV                types.String        `tfsdk:"default_iv"`
	Description              types.String        `tfsdk:"description"`
	DestroyDate              types.String        `tfsdk:"destroy_date"`
	EmptyMaterial            types.Bool          `tfsdk:"empty_material"`
	Encoding                 types.String        `tfsdk:"encoding"`
	Format                   types.String        `tfsdk:"format"`
	GenerateKeyId            types.Bool          `tfsdk:"generate_key_id"`
	HKDFCreateParameters     HKDFParameters      `tfsdk:"hkdf_create_parameters"`
	IDSize                   types.Int64         `tfsdk:"id_size"`
	KeyId                    types.String        `tfsdk:"key_id"`
	MacSignBytes             types.String        `tfsdk:"mac_sign_bytes"`
	MacSignKeyIdentifier     types.String        `tfsdk:"mac_sign_key_identifier"`
	MacSignKeyIdentifierType types.String        `tfsdk:"mac_sign_key_identifier_type"`
	Material                 types.String        `tfsdk:"material"`
	MUID                     types.String        `tfsdk:"muid"`
	ObjectType               types.String        `tfsdk:"object_type"`
	Name                     types.String        `tfsdk:"name"`
	Metadata                 KeyMetadata         `tfsdk:"meta"`
	Padded                   types.Bool          `tfsdk:"padded"`
	Password                 types.String        `tfsdk:"password"`
	ProcessStartDate         types.String        `tfsdk:"process_start_date"`
	ProtectStopDate          types.String        `tfsdk:"protect_stop_date"`
	RevocationReason         types.String        `tfsdk:"revocation_reason"`
	RevocationMessage        types.String        `tfsdk:"revocation_message"`
	RotationFrequencyDays    types.String        `tfsdk:"rotation_frequency_days"`
	SecretDataEncoding       types.String        `tfsdk:"secret_data_encoding"`
	SecretDataLink           types.String        `tfsdk:"secret_data_link"`
	SigningAlgo              types.String        `tfsdk:"signing_algo"`
	Size                     types.Int64         `tfsdk:"size"`
	UnExportable             types.Bool          `tfsdk:"unexportable"`
	UnDeletable              types.Bool          `tfsdk:"undeletable"`
	State                    types.String        `tfsdk:"state"`
	TemplateID               types.String        `tfsdk:"template_id"`
	UsageMask                types.Int64         `tfsdk:"usage_mask"`
	UUID                     types.String        `tfsdk:"uuid"`
	WrapKeyIDType            types.String        `tfsdk:"wrap_key_id_type"`
	WrapKeyName              types.String        `tfsdk:"wrap_key_name"`
	WrapPublicKey            types.String        `tfsdk:"wrap_public_key"`
	WrapPublicKeyPadding     types.String        `tfsdk:"wrap_public_key_padding"`
	WrappingEncryptionAlgo   types.String        `tfsdk:"wrapping_encryption_algo"`
	WrappingHashAlgo         types.String        `tfsdk:"wrapping_hash_algo"`
	WrappingMethod           types.String        `tfsdk:"wrapping_method"`
	XTS                      types.Bool          `tfsdk:"xts"`
	Aliases                  []KeyAlias          `tfsdk:"aliases"`
	PublicKeyParameters      PublicKeyParameters `tfsdk:"public_key_parameters"`
	HKDFWrap                 WrapHKDF            `tfsdk:"wrap_hkdf"`
	PBEWrap                  WrapPBE             `tfsdk:"wrap_pbe"`
	RSAAESWrap               WrapRSAAES          `tfsdk:"wrap_rsaaes"`
	Labels                   types.Map           `tfsdk:"labels"`
	AllVersions              types.Bool          `tfsdk:"all_versions"`
}

type tfsdkCMKeysListModel struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	Application      types.String `tfsdk:"application"`
	DevAccount       types.String `tfsdk:"dev_account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	Name             types.String `tfsdk:"name"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	UsageMask        types.Int64  `tfsdk:"usage_mask"`
	Version          types.Int64  `tfsdk:"version"`
	Algorithm        types.String `tfsdk:"algorithm"`
	Size             types.Int64  `tfsdk:"size"`
	Format           types.String `tfsdk:"format"`
	Unexportable     types.Bool   `tfsdk:"unexportable"`
	Undeletable      types.Bool   `tfsdk:"undeletable"`
	ObjectType       types.String `tfsdk:"object_type"`
	ActivationDate   types.String `tfsdk:"activation_date"`
	DeactivationDate types.String `tfsdk:"deactivation_date"`
	ArchiveDate      types.String `tfsdk:"archive_date"`
	DestroyDate      types.String `tfsdk:"destroy_date"`
	RevocationReason types.String `tfsdk:"revocation_reason"`
	State            types.String `tfsdk:"state"`
	UUID             types.String `tfsdk:"uuid"`
	Description      types.String `tfsdk:"description"`
}

type tfsdkCMRegTokenModel struct {
	ID                        types.String `tfsdk:"id"`
	CAID                      types.String `tfsdk:"ca_id"`
	CertDuration              types.Int64  `tfsdk:"cert_duration"`
	ClientManagementProfileID types.String `tfsdk:"client_management_profile_id"`
	Label                     types.Map    `tfsdk:"label"`
	Labels                    types.Map    `tfsdk:"labels"`
	Lifetime                  types.String `tfsdk:"lifetime"`
	MaxClients                types.Int64  `tfsdk:"max_clients"`
	NamePrefix                types.String `tfsdk:"name_prefix"`
}

type tfsdkCMRegTokensListModel struct {
	ID                types.String `tfsdk:"id"`
	URI               types.String `tfsdk:"uri"`
	Account           types.String `tfsdk:"account"`
	Application       types.String `tfsdk:"application"`
	DevAccount        types.String `tfsdk:"dev_account"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
	Token             types.String `tfsdk:"token"`
	ValidUntil        types.String `tfsdk:"valid_until"`
	MaxClients        types.Int64  `tfsdk:"max_clients"`
	ClientsRegistered types.Int64  `tfsdk:"clients_registered"`
	CAID              types.String `tfsdk:"ca_id"`
	NamePrefix        types.String `tfsdk:"name_prefix"`
}

type tfsdkCMGroupModel struct {
	Name           types.String `tfsdk:"name"`
	AppMetadata    types.Map    `tfsdk:"app_metadata"`
	ClientMetadata types.Map    `tfsdk:"client_metadata"`
	Description    types.String `tfsdk:"description"`
	UserMetadata   types.Map    `tfsdk:"user_metadata"`
}

type tfsdkCMUserModel struct {
	UserID                 types.String `tfsdk:"user_id"`
	Name                   types.String `tfsdk:"full_name"`
	UserName               types.String `tfsdk:"username"`
	Nickname               types.String `tfsdk:"nickname"`
	Email                  types.String `tfsdk:"email"`
	Password               types.String `tfsdk:"password"`
	IsDomainUser           types.Bool   `tfsdk:"is_domain_user"`
	PreventUILogin         types.Bool   `tfsdk:"prevent_ui_login"`
	PasswordChangeRequired types.Bool   `tfsdk:"password_change_required"`
}

type tfsdkCTEClientModel struct {
	ID                     types.String   `tfsdk:"id"`
	Name                   types.String   `tfsdk:"name"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	ClientType             types.String   `tfsdk:"client_type"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Description            types.String   `tfsdk:"description"`
	Password               types.String   `tfsdk:"password"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ProfileIdentifier      types.String   `tfsdk:"profile_identifier"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	ClientMFAEnabled       types.Bool     `tfsdk:"client_mfa_enabled"`
	DelClient              types.Bool     `tfsdk:"del_client"`
	DisableCapability      types.String   `tfsdk:"disable_capability"`
	DynamicParameters      types.String   `tfsdk:"dynamic_parameters"`
	EnableDomainSharing    types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	LGCSAccessOnly         types.Bool     `tfsdk:"lgcs_access_only"`
	MaxNumCacheLog         types.Int64    `tfsdk:"max_num_cache_log"`
	MaxSpaceCacheLog       types.Int64    `tfsdk:"max_space_cache_log"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	SharedDomainList       []types.String `tfsdk:"shared_domain_list"`
	Labels                 types.Map      `tfsdk:"labels"`
}

type tfsdkCTEClientGroupModel struct {
	ID                      types.String   `tfsdk:"id"`
	ClusterType             types.String   `tfsdk:"cluster_type"`
	Name                    types.String   `tfsdk:"name"`
	CommunicationEnabled    types.Bool     `tfsdk:"communication_enabled"`
	Description             types.String   `tfsdk:"description"`
	LDTDesignatedPrimarySet types.String   `tfsdk:"ldt_designated_primary_set"`
	Password                types.String   `tfsdk:"password"`
	PasswordCreationMethod  types.String   `tfsdk:"password_creation_method"`
	ProfileID               types.String   `tfsdk:"profile_id"`
	ClientLocked            types.Bool     `tfsdk:"client_locked"`
	EnableDomainSharing     types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities     types.String   `tfsdk:"enabled_capabilities"`
	SharedDomainList        []types.String `tfsdk:"shared_domain_list"`
	SystemLocked            types.Bool     `tfsdk:"system_locked"`
	AuthBinaries            types.String   `tfsdk:"auth_binaries"`
	ReSign                  types.Bool     `tfsdk:"re_sign"`
	ClientList              []types.String `tfsdk:"client_list"`
	InheritAttributes       types.Bool     `tfsdk:"inherit_attributes"`
	ClientID                types.String   `tfsdk:"client_id"`
	OpType                  types.String   `tfsdk:"op_type"`
	Paused                  types.Bool     `tfsdk:"paused"`
}

type tfsdkCTECSIGroupModel struct {
	ID            types.String   `tfsdk:"id"`
	Namespace     types.String   `tfsdk:"kubernetes_namespace"`
	StorageClass  types.String   `tfsdk:"kubernetes_storage_class"`
	ClientProfile types.String   `tfsdk:"client_profile"`
	Name          types.String   `tfsdk:"name"`
	Description   types.String   `tfsdk:"description"`
	ClientList    []types.String `tfsdk:"client_list"`
	PolicyList    []types.String `tfsdk:"policy_list"`
	ClientID      types.String   `tfsdk:"client_id"`
	GuardEnabled  types.Bool     `tfsdk:"guard_enabled"`
	GPID          types.String   `tfsdk:"gp_id"`
	OpType        types.String   `tfsdk:"op_type"`
}

type tfsdkCTEClientsListModel struct {
	ID                     types.String   `tfsdk:"id"`
	URI                    types.String   `tfsdk:"uri"`
	Account                types.String   `tfsdk:"account"`
	App                    types.String   `tfsdk:"application"`
	DevAccount             types.String   `tfsdk:"dev_account"`
	CreatedAt              types.String   `tfsdk:"created_at"`
	UpdatedAt              types.String   `tfsdk:"updated_at"`
	Name                   types.String   `tfsdk:"name"`
	OSType                 types.String   `tfsdk:"os_type"`
	OSSubType              types.String   `tfsdk:"os_sub_type"`
	ClientRegID            types.String   `tfsdk:"client_reg_id"`
	ServerHostname         types.String   `tfsdk:"server_host_name"`
	Description            types.String   `tfsdk:"description"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ClientVersion          types.Int64    `tfsdk:"client_version"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Capabilities           types.String   `tfsdk:"capabilities"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	ClientType             types.String   `tfsdk:"client_type"`
	ProfileName            types.String   `tfsdk:"profile_name"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	LDTEnabled             types.Bool     `tfsdk:"ldt_enabled"`
	ClientHealthStatus     types.String   `tfsdk:"client_health_status"`
	Errors                 []types.String `tfsdk:"errors"`
	Warnings               []types.String `tfsdk:"warnings"`
	ClientErrors           []types.String `tfsdk:"client_errors"`
	ClientWarnings         []types.String `tfsdk:"client_warnings"`
}

type DataTransformationRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRule struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type KeyRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CurrentKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRule struct {
	CurrentKey        CurrentKey        `tfsdk:"current_key"`
	TransformationKey TransformationKey `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool        `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String      `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadata struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRule struct {
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	UserSetID          types.String `tfsdk:"user_set_id"`
}

type SignatureRule struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type tfsdkCTEPolicyModel struct {
	ID                  types.String             `tfsdk:"id"`
	Name                types.String             `tfsdk:"name"`
	Description         types.String             `tfsdk:"description"`
	PolicyType          types.String             `tfsdk:"policy_type"`
	Metadata            CTEPolicyMetadata        `tfsdk:"metadata"`
	NeverDeny           types.Bool               `tfsdk:"never_deny"`
	DataTransformRules  []DataTransformationRule `tfsdk:"data_transform_rules"`
	IDTKeyRules         []IDTKeyRule             `tfsdk:"idt_key_rules"`
	KeyRules            []KeyRule                `tfsdk:"key_rules"`
	LDTKeyRules         []LDTKeyRule             `tfsdk:"ldt_key_rules"`
	SecurityRules       []SecurityRule           `tfsdk:"security_rules"`
	SignatureRules      []SignatureRule          `tfsdk:"signature_rules"`
	ForceRestrictUpdate types.Bool               `tfsdk:"force_restrict_update"`
}

type CTEProcess struct {
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	ResourceSetId types.String `tfsdk:"resource_set_id"`
	Signature     types.String `tfsdk:"signature"`
}

type tfsdkCTEProcessSetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Processes   []CTEProcess `tfsdk:"processes"`
}

type ClassificationTagAttributes struct {
	DataType types.String `tfsdk:"data_type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

type ClassificationTag struct {
	Description types.String                  `tfsdk:"description"`
	Name        types.String                  `tfsdk:"name"`
	Attributes  []ClassificationTagAttributes `tfsdk:"attributes"`
}

type CTEResource struct {
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
}

type tfsdkCTEResourceSetModel struct {
	ID                 types.String        `tfsdk:"id"`
	Name               types.String        `tfsdk:"name"`
	Description        types.String        `tfsdk:"description"`
	Resources          []CTEResource       `tfsdk:"resources"`
	Type               types.String        `tfsdk:"type"`
	ClassificationTags []ClassificationTag `tfsdk:"classification_tags"`
}

type tfsdkCTESignatureSetModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Type        types.String   `tfsdk:"type"`
	Sources     []types.String `tfsdk:"source_list"`
}

type CTEUser struct {
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type tfsdkCTEUserSetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Users       []CTEUser    `tfsdk:"users"`
}

type tfsdkCTEUserSet struct {
	Index    types.Int64  `tfsdk:"index"`
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type tfsdkCTEUserSetsListModel struct {
	ID          types.String      `tfsdk:"id"`
	Name        types.String      `tfsdk:"name"`
	Description types.String      `tfsdk:"description"`
	URI         types.String      `tfsdk:"uri"`
	Account     types.String      `tfsdk:"account"`
	CreateAt    types.String      `tfsdk:"created_at"`
	UpdatedAt   types.String      `tfsdk:"updated_at"`
	Users       []tfsdkCTEUserSet `tfsdk:"users"`
}

type tfsdkCTEResourceSet struct {
	Index             types.Int64  `tfsdk:"index"`
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
}

type tfsdkCTEResourceSetsListModel struct {
	ID          types.String          `tfsdk:"id"`
	Name        types.String          `tfsdk:"name"`
	Description types.String          `tfsdk:"description"`
	URI         types.String          `tfsdk:"uri"`
	Account     types.String          `tfsdk:"account"`
	CreateAt    types.String          `tfsdk:"created_at"`
	UpdatedAt   types.String          `tfsdk:"updated_at"`
	Type        types.String          `tfsdk:"type"`
	Resources   []tfsdkCTEResourceSet `tfsdk:"resources"`
}

type tfsdkCTEProcessSet struct {
	Index         types.Int64  `tfsdk:"index"`
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	Signature     types.String `tfsdk:"signature"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type tfsdkCTEProcessSetsListModel struct {
	ID          types.String         `tfsdk:"id"`
	Name        types.String         `tfsdk:"name"`
	Description types.String         `tfsdk:"description"`
	URI         types.String         `tfsdk:"uri"`
	Account     types.String         `tfsdk:"account"`
	CreateAt    types.String         `tfsdk:"created_at"`
	UpdatedAt   types.String         `tfsdk:"updated_at"`
	Processes   []tfsdkCTEProcessSet `tfsdk:"resources"`
}

type tfsdkCTESignatureSetsListModel struct {
	ID                 types.String   `tfsdk:"id"`
	URI                types.String   `tfsdk:"uri"`
	Account            types.String   `tfsdk:"account"`
	CreatedAt          types.String   `tfsdk:"created_at"`
	UpdatedAt          types.String   `tfsdk:"updated_at"`
	Name               types.String   `tfsdk:"name"`
	Type               types.String   `tfsdk:"type"`
	Description        types.String   `tfsdk:"description"`
	ReferenceVersion   types.Int64    `tfsdk:"reference_version"`
	SourceList         []types.String `tfsdk:"source_list"`
	SigningStatus      types.String   `tfsdk:"signing_status"`
	PercentageComplete types.Int64    `tfsdk:"percentage_complete"`
	UpdatedBy          types.String   `tfsdk:"updated_by"`
	DockerImgID        types.String   `tfsdk:"docker_img_id"`
	DockerContID       types.String   `tfsdk:"docker_cont_id"`
}

type tfsdkCTEClientGuardPointParamsModel struct {
	GPType                         types.String `tfsdk:"guard_point_type"`
	PolicyID                       types.String `tfsdk:"policy_id"`
	IsAutomountEnabled             types.Bool   `tfsdk:"automount_enabled"`
	IsCIFSEnabled                  types.Bool   `tfsdk:"cifs_enabled"`
	IsDataClassificationEnabled    types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled           types.Bool   `tfsdk:"data_lineage_enabled"`
	DiskName                       types.String `tfsdk:"disk_name"`
	DiskgroupName                  types.String `tfsdk:"diskgroup_name"`
	IsEarlyAccessEnabled           types.Bool   `tfsdk:"early_access"`
	IsIntelligentProtectionEnabled types.Bool   `tfsdk:"intelligent_protection"`
	IsDeviceIDTCapable             types.Bool   `tfsdk:"is_idt_capable_device"`
	IsMFAEnabled                   types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID           types.String `tfsdk:"network_share_credentials_id"`
	PreserveSparseRegions          types.Bool   `tfsdk:"preserve_sparse_regions"`
}

type tfsdkCTEClientGuardPoint struct {
	CTEClientID      types.String                        `tfsdk:"cte_client_id"`
	GuardPaths       []types.String                      `tfsdk:"guard_paths"`
	GuardPointParams tfsdkCTEClientGuardPointParamsModel `tfsdk:"guard_point_params"`
}

type tfsdkUpdateGPModel struct {
	CTEClientID                 types.String `tfsdk:"cte_client_id"`
	GPID                        types.String `tfsdk:"cte_client_gp_id"`
	IsDataClassificationEnabled types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled        types.Bool   `tfsdk:"data_lineage_enabled"`
	IsGuardEnabled              types.Bool   `tfsdk:"guard_enabled"`
	IsMFAEnabled                types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID        types.String `tfsdk:"network_share_credentials_id"`
}

type tfsdkAddDataTXRulePolicy struct {
	CTEClientPolicyID types.String           `tfsdk:"policy_id"`
	DataTXRuleID      types.String           `tfsdk:"rule_id"`
	OrderNumber       types.Int64            `tfsdk:"order_number"`
	DataTXRule        DataTransformationRule `tfsdk:"rule"`
}

type tfsdkAddKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	KeyRuleID         types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	KeyRule           KeyRule      `tfsdk:"rule"`
}

type tfsdkAddLDTKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	LDTKeyRuleID      types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	LDTKeyRule        LDTKeyRule   `tfsdk:"rule"`
}

type tfsdkAddSecurityRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	SecurityRuleID    types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	SecurityRule      SecurityRule `tfsdk:"rule"`
}

type tfsdkAddSignatureRulePolicy struct {
	CTEClientPolicyID types.String   `tfsdk:"policy_id"`
	SignatureRuleID   types.String   `tfsdk:"rule_id"`
	SignatureSetList  []types.String `tfsdk:"signature_set_id_list"`
	SignatureSetID    types.String   `tfsdk:"signature_set_id"`
}

type tfsdkUpdateIDTKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	IDTKeyRuleID      types.String `tfsdk:"rule_id"`
	IDTKeyRule        IDTKeyRule   `tfsdk:"rule"`
}

type tfsdkCTEPolicyDataTxRulesListModel struct {
	ID            types.String `tfsdk:"id"`
	URI           types.String `tfsdk:"uri"`
	Account       types.String `tfsdk:"account"`
	Application   types.String `tfsdk:"application"`
	DevAccount    types.String `tfsdk:"dev_account"`
	CreateAt      types.String `tfsdk:"created_at"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
	PolicyID      types.String `tfsdk:"policy_id"`
	OrderNumber   types.Int64  `tfsdk:"order_number"`
	KeyID         types.String `tfsdk:"key_id"`
	NewKeyRule    types.Bool   `tfsdk:"new_key_rule"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type tfsdkCTEPolicyIDTKeyRulesListModel struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type tfsdkCTEPolicyLDTKeyRulesListModel struct {
	ID                    types.String `tfsdk:"id"`
	PolicyID              types.String `tfsdk:"policy_id"`
	OrderNumber           types.Int64  `tfsdk:"order_number"`
	ResourceSetID         types.String `tfsdk:"resource_set_id"`
	CurrentKeyID          types.String `tfsdk:"current_key_id"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKeyID   types.String `tfsdk:"transformation_key_id"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
	ISExclusionRule       types.Bool   `tfsdk:"is_exclusion_rule"`
}

type tfsdkCTEPolicySecurityRulesListModel struct {
	ID                 types.String `tfsdk:"id"`
	URI                types.String `tfsdk:"uri"`
	Account            types.String `tfsdk:"account"`
	Application        types.String `tfsdk:"application"`
	DevAccount         types.String `tfsdk:"dev_account"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	PolicyID           types.String `tfsdk:"policy_id"`
	OrderNumber        types.Int64  `tfsdk:"order_number"`
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	UserSetID          types.String `tfsdk:"user_set_id"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
}

type tfsdkCTEPolicySignatureRulesListModel struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	PolicyID         types.String `tfsdk:"policy_id"`
	SignatureSetID   types.String `tfsdk:"signature_set_id"`
	SignatureSetName types.String `tfsdk:"signature_set_name"`
}

type tfsdkCTEProfileCacheSettings struct {
	MaxFiles types.Int64 `tfsdk:"max_files"`
	MaxSpace types.Int64 `tfsdk:"max_space"`
}

type tfsdkCTEProfileDuplicateSettings struct {
	SuppressInterval  types.Int64 `tfsdk:"suppress_interval"`
	SuppressThreshold types.Int64 `tfsdk:"suppress_threshold"`
}

type tfsdkCTEProfileFileSettings struct {
	AllowPurge    types.Bool   `tfsdk:"allow_purge"`
	FileThreshold types.String `tfsdk:"file_threshold"`
	MaxFileSize   types.Int64  `tfsdk:"max_file_size"`
	MaxOldFiles   types.Int64  `tfsdk:"max_old_files"`
}

type tfsdkCTEProfileManagementServiceLogger struct {
	Duplicates    types.String `tfsdk:"duplicates"`
	FileEnabled   types.Bool   `tfsdk:"file_enabled"`
	SyslogEnabled types.Bool   `tfsdk:"syslog_enabled"`
	Threshold     types.String `tfsdk:"threshold"`
	UploadEnabled types.Bool   `tfsdk:"upload_enabled"`
}

type tfsdkCTEProfileQOSSchedule struct {
	EndTimeHour   types.Int64  `tfsdk:"end_time_hour"`
	EndTimeMin    types.Int64  `tfsdk:"end_time_min"`
	EndWeekday    types.String `tfsdk:"end_weekday"`
	StartTimeHour types.Int64  `tfsdk:"start_time_hour"`
	StartTimeMin  types.Int64  `tfsdk:"start_time_min"`
	StartWeekday  types.String `tfsdk:"start_weekday"`
}

type tfsdkCTEProfileServiceSetting struct {
	HostName types.String `tfsdk:"host_name"`
	Priority types.Int64  `tfsdk:"priority"`
}

type tfsdkCTEProfileSyslogSettingServer struct {
	CACert        types.String `tfsdk:"caCertificate"`
	Certificate   types.String `tfsdk:"certificate"`
	MessageFormat types.String `tfsdk:"message_format"`
	Name          types.String `tfsdk:"name"`
	Port          types.Int64  `tfsdk:"port"`
	PrivateKey    types.String `tfsdk:"privateKey"`
	Protocol      types.String `tfsdk:"protocol"`
}

type tfsdkCTEProfileSyslogSettings struct {
	Local     types.Bool                           `tfsdk:"local"`
	Servers   []tfsdkCTEProfileSyslogSettingServer `tfsdk:"servers"`
	Threshold types.String                         `tfsdk:"syslog_threshold"`
}

type tfsdkCTEProfileUploadSettings struct {
	ConnectionTimeout    types.Int64  `tfsdk:"connection_timeout"`
	DropIfBusy           types.Bool   `tfsdk:"drop_if_busy"`
	JobCompletionTimeout types.Int64  `tfsdk:"job_completion_timeout"`
	MaxInterval          types.Int64  `tfsdk:"max_interval"`
	MaxMessages          types.Int64  `tfsdk:"max_messages"`
	MinInterval          types.Int64  `tfsdk:"min_interval"`
	Threshold            types.String `tfsdk:"upload_threshold"`
}

type tfsdkCTEProfileCreate struct {
	ID                      types.String                           `tfsdk:"id"`
	Name                    types.String                           `tfsdk:"name"`
	CacheSettings           tfsdkCTEProfileCacheSettings           `tfsdk:"cache_settings"`
	ConciseLogging          types.Bool                             `tfsdk:"concise_logging"`
	ConnectTimeout          types.Int64                            `tfsdk:"connect_timeout"`
	Description             types.String                           `tfsdk:"description"`
	DuplicateSettings       tfsdkCTEProfileDuplicateSettings       `tfsdk:"duplicate_settings"`
	FileSettings            tfsdkCTEProfileFileSettings            `tfsdk:"file_settings"`
	Labels                  types.Map                              `tfsdk:"labels"`
	LDTQOSCapCPUAllocation  types.Bool                             `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent     types.Int64                            `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption       types.String                           `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate         types.Int64                            `tfsdk:"ldt_qos_rekey_rate"`
	LDTQOSSchedule          types.String                           `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate   types.Int64                            `tfsdk:"ldt_qos_status_check_rate"`
	ManagementServiceLogger tfsdkCTEProfileManagementServiceLogger `tfsdk:"management_service_logger"`
	MetadataScanInterval    types.Int64                            `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID      types.String                           `tfsdk:"mfa_exempt_user_set_id"`
	OIDCConnectionID        types.String                           `tfsdk:"oidc_connection_id"`
	PolicyEvaluationLogger  tfsdkCTEProfileManagementServiceLogger `tfsdk:"policy_evaluation_logger"`
	QOSSchedules            []tfsdkCTEProfileQOSSchedule           `tfsdk:"qos_schedules"`
	RWPOperation            types.String                           `tfsdk:"rwp_operation"`
	RWPProcessSet           types.String                           `tfsdk:"rwp_process_set"`
	SecurityAdminLogger     tfsdkCTEProfileManagementServiceLogger `tfsdk:"security_admin_logger"`
	ServerResponseRate      types.Int64                            `tfsdk:"server_response_rate"`
	ServerSettings          []tfsdkCTEProfileServiceSetting        `tfsdk:"server_settings"`
	SyslogSettings          tfsdkCTEProfileSyslogSettings          `tfsdk:"syslog_settings"`
	SystemAdminLogger       tfsdkCTEProfileManagementServiceLogger `tfsdk:"system_admin_logger"`
	UploadSettings          tfsdkCTEProfileUploadSettings          `tfsdk:"upload_settings"`
}

type tfsdkCMSSHKeyModel struct {
	Key types.String `tfsdk:"key"`
}

type tfsdkCMPwdChangeModel struct {
	Username    types.String `tfsdk:"username"`
	Password    types.String `tfsdk:"password"`
	NewPassword types.String `tfsdk:"new_password"`
}

type tfsdkCTEProfilesList struct {
	ID                     types.String `tfsdk:"id"`
	URI                    types.String `tfsdk:"uri"`
	Account                types.String `tfsdk:"account"`
	Application            types.String `tfsdk:"application"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	LDTQOSCapCPUAllocation types.Bool   `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    types.Int64  `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      types.String `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        types.Int64  `tfsdk:"ldt_qos_rekey_rate"`
	ConciseLogging         types.Bool   `tfsdk:"concise_logging"`
	ConnectTimeout         types.Int64  `tfsdk:"connect_timeout"`
	LDTQOSSchedule         types.String `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  types.Int64  `tfsdk:"ldt_qos_status_check_rate"`
	MetadataScanInterval   types.Int64  `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID     types.String `tfsdk:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   types.String `tfsdk:"mfa_exempt_user_set_name"`
	OIDCConnectionID       types.String `tfsdk:"oidc_connection_id"`
	OIDCConnectionName     types.String `tfsdk:"oidc_connection_name"`
	RWPOperation           types.String `tfsdk:"rwp_operation"`
	RWPProcessSet          types.String `tfsdk:"rwp_process_set"`
	ServerResponseRate     types.Int64  `tfsdk:"server_response_rate"`
	//QOSSchedules            []tfsdkCTEProfileQOSSchedule           `tfsdk:"qos_schedules"`
	//ServerSettings          []tfsdkCTEProfileServiceSetting        `tfsdk:"server_settings"`
	// ManagementServiceLogger tfsdkCTEProfileManagementServiceLogger `tfsdk:"management_service_logger"`
	// PolicyEvaluationLogger  tfsdkCTEProfileManagementServiceLogger `tfsdk:"policy_evaluation_logger"`
	// SecurityAdminLogger     tfsdkCTEProfileManagementServiceLogger `tfsdk:"security_admin_logger"`
	// SystemAdminLogger       tfsdkCTEProfileManagementServiceLogger `tfsdk:"system_admin_logger"`
	// FileSettings            tfsdkCTEProfileFileSettings            `tfsdk:"file_settings"`
	// SyslogSettings          tfsdkCTEProfileSyslogSettings          `tfsdk:"syslog_settings"`
	// UploadSettings          tfsdkCTEProfileUploadSettings          `tfsdk:"upload_settings"`
	// DuplicateSettings       tfsdkCTEProfileDuplicateSettings       `tfsdk:"duplicate_settings"`
	// CacheSettings           tfsdkCTEProfileCacheSettings           `tfsdk:"cache_settings"`
}

type tfsdkLDTGroupCommSvc struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	OpType      types.String   `tfsdk:"op_type"`
	ClientList  []types.String `tfsdk:"client_list"`
}

type TFSDK_IAMRoleAnywhere struct {
	AnywhereRoleARN types.String `tfsdk:"anywhere_role_arn"`
	Certificate     types.String `tfsdk:"certificate"`
	ProfileARN      types.String `tfsdk:"profile_arn"`
	TrustAnchorARN  types.String `tfsdk:"trust_anchor_arn"`
	PrivateKey      types.String `tfsdk:"private_key"`
}

type tfsdkAWSConnectionModel struct {
	ID                      types.String          `tfsdk:"id"`
	Name                    types.String          `tfsdk:"name"`
	Description             types.String          `tfsdk:"description"`
	AccessKeyID             types.String          `tfsdk:"access_key_id"`
	AssumeRoleARN           types.String          `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID    types.String          `tfsdk:"assume_role_external_id"`
	AWSRegion               types.String          `tfsdk:"aws_region"`
	AWSSTSRegionalEndpoints types.String          `tfsdk:"aws_sts_regional_endpoints"`
	CloudName               types.String          `tfsdk:"cloud_name"`
	IsRoleAnywhere          types.Bool            `tfsdk:"is_role_anywhere"`
	IAMRoleAnywhere         TFSDK_IAMRoleAnywhere `tfsdk:"iam_role_anywhere"`
	Labels                  types.Map             `tfsdk:"labels"`
	Meta                    types.Map             `tfsdk:"meta"`
	Products                []types.String        `tfsdk:"products"`
	SecretAccessKey         types.String          `tfsdk:"secret_access_key"`
}
