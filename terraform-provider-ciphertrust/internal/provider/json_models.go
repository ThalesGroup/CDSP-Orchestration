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

type AddSignaturesToRuleJSON struct {
	SignatureSets []string `json:"signature_set_id_list"`
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
	ClientMFAEnabled       bool     `json:"client_mfa_enabled"`
	DelClient              bool     `json:"del_client"`
	DisableCapability      string   `json:"disable_capability"`
	DynamicParameters      string   `json:"dynamic_parameters"`
	EnableDomainSharing    bool     `json:"enable_domain_sharing"`
	EnabledCapabilities    string   `json:"enabled_capabilities"`
	LGCSAccessOnly         bool     `json:"lgcs_access_only"`
	MaxNumCacheLog         int64    `json:"max_num_cache_log"`
	MaxSpaceCacheLog       int64    `json:"max_space_cache_log"`
	ProfileID              string   `json:"profile_id"`
	ProtectionMode         string   `json:"protection_mode"`
	SharedDomainList       []string `json:"shared_domain_list"`
}

type UserSetJSON struct {
	ID          string             `json:"id"`
	URI         string             `json:"uri"`
	Account     string             `json:"account"`
	CreatedAt   string             `json:"createdAt"`
	Name        string             `json:"name"`
	UpdatedAt   string             `json:"updatedAt"`
	Description string             `json:"description"`
	Users       []UserSetEntryJSON `json:"users"`
}

type UserSetEntryJSON struct {
	Index    int64  `json:"index"`
	GID      int64  `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int64  `json:"uid"`
	UName    string `json:"uname"`
}

type ResourceSetJSON struct {
	ID          string                 `json:"id"`
	URI         string                 `json:"uri"`
	Account     string                 `json:"account"`
	CreatedAt   string                 `json:"createdAt"`
	Name        string                 `json:"name"`
	UpdatedAt   string                 `json:"updatedAt"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Resources   []ResourceSetEntryJSON `json:"resources"`
}

type ResourceSetEntryJSON struct {
	Index             int64  `json:"index"`
	Directory         string `json:"directory"`
	File              string `json:"file"`
	IncludeSubfolders bool   `json:"include_subfolders"`
	HDFS              bool   `json:"hdfs"`
}

type ProcessSetJSON struct {
	ID          string                `json:"id"`
	URI         string                `json:"uri"`
	Account     string                `json:"account"`
	CreatedAt   string                `json:"createdAt"`
	Name        string                `json:"name"`
	UpdatedAt   string                `json:"updatedAt"`
	Description string                `json:"description"`
	Processes   []ProcessSetEntryJSON `json:"resources"`
}

type ProcessSetEntryJSON struct {
	Index         int64  `json:"index"`
	Directory     string `json:"directory"`
	File          string `json:"file"`
	Signature     string `json:"signature"`
	ResourceSetID string `json:"resource_set_id"`
}

type SignatureSetJSON struct {
	ID                 string   `json:"id"`
	URI                string   `json:"uri"`
	Account            string   `json:"account"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	ReferenceVersion   int64    `json:"reference_version"`
	SourceList         []string `json:"source_list"`
	SigningStatus      string   `json:"signing_status"`
	PercentageComplete int64    `json:"percentage_complete"`
	UpdatedBy          string   `json:"updated_by"`
	DockerImgID        string   `json:"docker_img_id"`
	DockerContID       string   `json:"docker_cont_id"`
}

type CTEClientGuardPointParamsJSON struct {
	GPType                         string `json:"guard_point_type"`
	PolicyID                       string `json:"policy_id"`
	IsAutomountEnabled             bool   `json:"automount_enabled"`
	IsCIFSEnabled                  bool   `json:"cifs_enabled"`
	IsDataClassificationEnabled    bool   `json:"data_classification_enabled"`
	IsDataLineageEnabled           bool   `json:"data_lineage_enabled"`
	DiskName                       string `json:"disk_name"`
	DiskgroupName                  string `json:"diskgroup_name"`
	IsEarlyAccessEnabled           bool   `json:"early_access"`
	IsIntelligentProtectionEnabled bool   `json:"intelligent_protection"`
	IsDeviceIDTCapable             bool   `json:"is_idt_capable_device"`
	IsMFAEnabled                   bool   `json:"mfa_enabled"`
	NWShareCredentialsID           string `json:"network_share_credentials_id"`
	PreserveSparseRegions          bool   `json:"preserve_sparse_regions"`
}

type CTEClientGuardPointJSON struct {
	CTEClientID      string                        `json:"cte_client_id"`
	GuardPaths       []string                      `json:"guard_paths"`
	GuardPointParams CTEClientGuardPointParamsJSON `json:"guard_point_params"`
}

type UpdateGPJSON struct {
	CTEClientID                 string `json:"cte_client_id"`
	GPID                        string `json:"cte_client_gp_id"`
	IsDataClassificationEnabled bool   `json:"data_classification_enabled"`
	IsDataLineageEnabled        bool   `json:"data_lineage_enabled"`
	IsGuardEnabled              bool   `json:"guard_enabled"`
	IsMFAEnabled                bool   `json:"mfa_enabled"`
	NWShareCredentialsID        string `json:"network_share_credentials_id"`
}

// type jsonAddDataTXRulePolicy struct {
// 	CTEClientPolicyID string         `json:"policy_id"`
// 	DataTXRuleID      string         `json:"rule_id"`
// 	DataTXRule        DataTxRuleJSON `json:"rule"`
// }

// type jsonAddKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	KeyRuleID         string      `json:"rule_id"`
// 	KeyRule           KeyRuleJSON `json:"rule"`
// }

// type jsonAddLDTKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	LDTKeyRuleID      string      `json:"rule_id"`
// 	LDTKeyRule        LDTRuleJSON `json:"rule"`
// }

// type jsonAddSecurityRulePolicy struct {
// 	CTEClientPolicyID string           `json:"policy_id"`
// 	SecurityRuleID    string           `json:"rule_id"`
// 	SecurityRule      SecurityRuleJSON `json:"rule"`
// }

// type jsonAddSignatureRulePolicy struct {
// 	CTEClientPolicyID string            `json:"policy_id"`
// 	SignatureRuleID   string            `json:"rule_id"`
// 	SignatureRule     SignatureRuleJSON `json:"rule"`
// }

type DataTxRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
	OrderNumber   int64  `json:"order_number"`
}

type KeyRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
	OrderNumber   int64  `json:"order_number"`
}

type LDTRuleUpdateJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule"`
	ResourceSetID     string                `json:"resource_set_id"`
	OrderNumber       int64                 `json:"order_number"`
}

type SecurityRuleUpdateJSON struct {
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	PartialMatch       bool   `json:"partial_match"`
	ProcessSetID       string `json:"process_set_id"`
	ResourceSetID      string `json:"resource_set_id"`
	UserSetID          string `json:"user_set_id"`
	OrderNumber        int64  `json:"order_number"`
}
