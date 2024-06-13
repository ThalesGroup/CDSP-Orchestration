package provider

import "github.com/hashicorp/terraform-plugin-framework/types"

type HKDFParameters struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	IKMKeyName    types.String `tfsdk:"ikm_key_name"`
	Info          types.String `tfsdk:"info"`
	Salt          types.String `tfsdk:"salt"`
}

type KeyMetadata struct {
	OwnerId types.String `tfsdk:"owner_id"`
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
	Deletable        types.Bool   `tfsdk:"undeletable"`
	Exportable       types.Bool   `tfsdk:"unexportable"`
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
	Exportable               types.Bool          `tfsdk:"unexportable"`
	Deletable                types.Bool          `tfsdk:"undeletable"`
	State                    types.String        `tfsdk:"state"`
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
}

type tfsdkCMGroupModel struct {
	Name           types.String           `tfsdk:"name"`
	AppMetadata    map[string]interface{} `tfsdk:"app_metadata"`
	ClientMetadata map[string]interface{} `tfsdk:"client_metadata"`
	Description    types.String           `tfsdk:"description"`
	UserMetadata   map[string]interface{} `tfsdk:"user_metadata"`
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
