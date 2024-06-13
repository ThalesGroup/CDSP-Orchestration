package provider

type UserLoginFlagsJSON struct {
	PreventUILogin bool `json:"prevent_ui_login"`
}

type UserJSON struct {
	UserID                 string             `json:"user_id"`
	Name                   string             `json:"full_name"`
	UserName               string             `json:"username"`
	Nickname               string             `json:"nickname"`
	Email                  string             `json:"email"`
	Password               string             `json:"password"`
	IsDomainUser           bool               `json:"is_domain_user"`
	LoginFlags             UserLoginFlagsJSON `json:"login_flags"`
	PasswordChangeRequired bool               `json:"password_change_required"`
}

type GroupJSON struct {
	Name string `json:"name"`
}

type KeyJSON struct {
	KeyID            string `json:"id"`
	URI              string `json:"uri"`
	Account          string `json:"account"`
	Application      string `json:"application"`
	DevAccount       string `json:"devAccount"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	UsageMask        int64  `json:"usageMask"`
	Version          int64  `json:"version"`
	Algorithm        string `json:"algorithm"`
	Size             int64  `json:"size"`
	Format           string `json:"format"`
	Exportable       bool   `json:"unexportable"`
	Deletable        bool   `json:"undeletable"`
	ObjectType       string `json:"objectType"`
	ActivationDate   string `json:"activationDate"`
	DeactivationDate string `json:"deactivationDate"`
	ArchiveDate      string `json:"archiveDate"`
	DestroyDate      string `json:"destroyDate"`
	RevocationReason string `json:"revocationReason"`
	State            string `json:"state"`
	UUID             string `json:"uuid"`
	Description      string `json:"description"`
	Name             string `json:"name"`
}

type CTEUserJSON struct {
	GID      int    `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int    `json:"uid"`
	UName    string `json:"uname"`
}

type ClassificationTagAttributesJSON struct {
	DataType string `json:"data_type"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ClassificationTagJSON struct {
	Description string                            `json:"description"`
	Name        string                            `json:"name"`
	Attributes  []ClassificationTagAttributesJSON `json:"attributes"`
}

type CTEResourceJSON struct {
	Directory         string `json:"directory"`
	File              string `json:"file"`
	HDFS              bool   `json:"hdfs"`
	IncludeSubfolders bool   `json:"include_subfolders"`
}

type CTEResourceSetModelJSON struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Description        string                  `json:"description"`
	Resources          []CTEResourceJSON       `json:"resources"`
	Type               string                  `json:"type"`
	ClassificationTags []ClassificationTagJSON `json:"classification_tags"`
}

type CTEProcessJSON struct {
	Directory     string `json:"directory"`
	File          string `json:"file"`
	ResourceSetId string `json:"resource_set_id"`
	Signature     string `json:"signature"`
}

type CTEProcessSetModelJSON struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Processes   []CTEProcessJSON `json:"processes"`
}

type CTESignatureSetModelJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Sources     []string `json:"source_list"`
}

// CTE Policy related structs
type DataTxRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type IDTRuleJSON struct {
	CurrentKey            string `json:"current_key"`
	CurrentKeyType        string `json:"current_key_type"`
	TransformationKey     string `json:"transformation_key"`
	TransformationKeyType string `json:"transformation_key_type"`
}

type KeyRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type CurrentKeyJSON struct {
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type"`
}

type TransformationKeyJSON struct {
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type"`
}

type LDTRuleJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule"`
	ResourceSetID     string                `json:"resource_set_id"`
}

type CTEPolicyMetadataJSON struct {
	RestrictUpdate bool `json:"restrict_update"`
}

type SecurityRuleJSON struct {
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	PartialMatch       bool   `json:"partial_match"`
	ProcessSetID       string `json:"process_set_id"`
	ResourceSetID      string `json:"resource_set_id"`
	UserSetID          string `json:"user_set_id"`
}

type SignatureRuleJSON struct {
	SignatureSetID string `json:"signature_set_id"`
}

type CTEPolicyModelJSON struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	PolicyType          string                `json:"policy_type"`
	Metadata            CTEPolicyMetadataJSON `json:"metadata"`
	NeverDeny           bool                  `json:"never_deny"`
	DataTransformRules  []DataTxRuleJSON      `json:"data_transform_rules"`
	IDTKeyRules         []IDTRuleJSON         `json:"idt_key_rules"`
	KeyRules            []KeyRuleJSON         `json:"key_rules"`
	LDTKeyRules         []LDTRuleJSON         `json:"ldt_key_rules"`
	SecurityRules       []SecurityRuleJSON    `json:"security_rules"`
	SignatureRules      []SignatureRuleJSON   `json:"signature_rules"`
	ForceRestrictUpdate bool                  `json:"force_restrict_update"`
}

type CTEClientModelJSON struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	ClientLocked           bool     `json:"client_locked"`
	ClientType             string   `json:"client_type"`
	CommunicationEnabled   bool     `json:"communication_enabled"`
	Description            string   `json:"description"`
	Password               string   `json:"password"`
	PasswordCreationMethod string   `json:"password_creation_method"`
	ProfileIdentifier      string   `json:"profile_identifier"`
	RegistrationAllowed    bool     `json:"registration_allowed"`
	SystemLocked           bool     `json:"system_locked"`
	ClientMFAEnabled       bool     `tfsdk:"client_mfa_enabled"`
	DelClient              bool     `tfsdk:"del_client"`
	DisableCapability      string   `tfsdk:"disable_capability"`
	DynamicParameters      string   `tfsdk:"dynamic_parameters"`
	EnableDomainSharing    bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities    string   `tfsdk:"enabled_capabilities"`
	LGCSAccessOnly         bool     `tfsdk:"lgcs_access_only"`
	MaxNumCacheLog         int64    `tfsdk:"max_num_cache_log"`
	MaxSpaceCacheLog       int64    `tfsdk:"max_space_cache_log"`
	ProfileID              string   `tfsdk:"profile_id"`
	ProtectionMode         string   `tfsdk:"protection_mode"`
	SharedDomainList       []string `tfsdk:"shared_domain_list"`
}

type UserSetJSON struct {
	ID          string            `json:"id"`
	URI         string            `json:"uri"`
	Account     string            `json:"account"`
	CreatedAt   string            `json:"createdAt"`
	Name        string            `json:"name"`
	UpdatedAt   string            `json:"updatedAt"`
	Description string            `json:"description"`
	Users       []UserSetUserJSON `json:"users"`
}

type UserSetUserJSON struct {
	Index    int64  `json:"index"`
	GID      int64  `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int64  `json:"uid"`
	UName    string `json:"uname"`
}
