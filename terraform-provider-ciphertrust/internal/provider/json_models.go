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

type CTEPolicyDataTxRulesJSON struct {
	ID            string `json:"id"`
	URI           string `json:"uri"`
	Account       string `json:"account"`
	Application   string `json:"application"`
	DevAccount    string `json:"dev_account"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	PolicyID      string `json:"policy_id"`
	OrderNumber   int64  `json:"order_number"`
	KeyID         string `json:"key_id"`
	NewKeyRule    bool   `json:"new_key_rule"`
	ResourceSetID string `json:"resource_set_id"`
}

type CTEPolicyIDTKeyRulesJSON struct {
	ID                string `json:"id"`
	PolicyID          string `json:"policy_id"`
	CurrentKey        string `json:"current_key"`
	TransformationKey string `json:"transformation_key"`
}

type CTEPolicyLDTKeyRulesJSON struct {
	ID                string                `json:"id"`
	PolicyID          string                `json:"policy_id"`
	OrderNumber       int64                 `json:"order_number"`
	ResourceSetID     string                `json:"resource_set_id"`
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	ISExclusionRule   bool                  `json:"is_exclusion_rule"`
}

type CTEPolicySecurityRulesJSON struct {
	ID                 string `json:"id"`
	URI                string `json:"uri"`
	Account            string `json:"account"`
	Application        string `json:"application"`
	DevAccount         string `json:"dev_account"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	PolicyID           string `json:"policy_id"`
	OrderNumber        int64  `json:"order_number"`
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	UserSetID          string `json:"user_set_id"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	ResourceSetID      string `json:"resource_set_id"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ProcessSetID       string `json:"process_set_id"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	PartialMatch       bool   `json:"partial_match"`
}

type CTEPolicySignatureRulesJSON struct {
	ID               string `json:"id"`
	URI              string `json:"uri"`
	Account          string `json:"account"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	PolicyID         string `json:"policy_id"`
	SignatureSetID   string `json:"signature_set_id"`
	SignatureSetName string `json:"signature_set_name"`
}

// CTE Profile
type jsonCTEProfileCacheSettings struct {
	MaxFiles int64 `json:"max_files"`
	MaxSpace int64 `json:"max_space"`
}

type jsonCTEProfileDuplicateSettings struct {
	SuppressInterval  int64 `json:"suppress_interval"`
	SuppressThreshold int64 `json:"suppress_threshold"`
}

type jsonCTEProfileFileSettings struct {
	AllowPurge    bool   `json:"allow_purge"`
	FileThreshold string `json:"file_threshold"`
	MaxFileSize   int64  `json:"max_file_size"`
	MaxOldFiles   int64  `json:"max_old_files"`
}

type jsonCTEProfileManagementServiceLogger struct {
	Duplicates    string `json:"duplicates"`
	FileEnabled   bool   `json:"file_enabled"`
	SyslogEnabled bool   `json:"syslog_enabled"`
	Threshold     string `json:"threshold"`
	UploadEnabled bool   `json:"upload_enabled"`
}

type jsonCTEProfileQOSSchedule struct {
	EndTimeHour   int64  `json:"end_time_hour"`
	EndTimeMin    int64  `json:"end_time_min"`
	EndWeekday    string `json:"end_weekday"`
	StartTimeHour int64  `json:"start_time_hour"`
	StartTimeMin  int64  `json:"start_time_min"`
	StartWeekday  string `json:"start_weekday"`
}

type jsonCTEProfileServiceSetting struct {
	HostName string `json:"hostName"`
	Priority int64  `json:"priority"`
}

type jsonCTEProfileSyslogSettingServer struct {
	CACert        string `json:"caCertificate"`
	Certificate   string `json:"certificate"`
	MessageFormat string `json:"message_format"`
	Name          string `json:"name"`
	Port          int64  `json:"port"`
	PrivateKey    string `json:"privateKey"`
	Protocol      string `json:"protocol"`
}

type jsonCTEProfileSyslogSettings struct {
	Local     bool                                `json:"local"`
	Servers   []jsonCTEProfileSyslogSettingServer `json:"servers"`
	Threshold string                              `json:"syslog_threshold"`
}

type jsonCTEProfileUploadSettings struct {
	ConnectionTimeout    int64  `json:"connection_timeout"`
	DropIfBusy           bool   `json:"drop_if_busy"`
	JobCompletionTimeout int64  `json:"job_completion_timeout"`
	MaxInterval          int64  `json:"max_interval"`
	MaxMessages          int64  `json:"max_messages"`
	MinInterval          int64  `json:"min_interval"`
	Threshold            string `json:"upload_threshold"`
}

type jsonCTEProfileCreate struct {
	Name                    string                                `json:"name"`
	CacheSettings           jsonCTEProfileCacheSettings           `json:"cache_settings"`
	ConciseLogging          bool                                  `json:"concise_logging"`
	ConnectTimeout          int64                                 `json:"connect_timeout"`
	Description             string                                `json:"description"`
	DuplicateSettings       jsonCTEProfileDuplicateSettings       `json:"duplicate_settings"`
	FileSettings            jsonCTEProfileFileSettings            `json:"file_settings"`
	LDTQOSCapCPUAllocation  bool                                  `json:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent     int64                                 `json:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption       string                                `json:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate         int64                                 `json:"ldt_qos_rekey_rate"`
	LDTQOSSchedule          string                                `json:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate   int64                                 `json:"ldt_qos_status_check_rate"`
	ManagementServiceLogger jsonCTEProfileManagementServiceLogger `json:"management_service_logger"`
	MetadataScanInterval    int64                                 `json:"metadata_scan_interval"`
	MFAExemptUserSetID      string                                `json:"mfa_exempt_user_set_id"`
	OIDCConnectionID        string                                `json:"oidc_connection_id"`
	PolicyEvaluationLogger  jsonCTEProfileManagementServiceLogger `json:"policy_evaluation_logger"`
	QOSSchedules            []jsonCTEProfileQOSSchedule           `json:"qos_schedules"`
	RWPOperation            string                                `json:"rwp_operation"`
	RWPProcessSet           string                                `json:"rwp_process_set"`
	SecurityAdminLogger     jsonCTEProfileManagementServiceLogger `json:"security_admin_logger"`
	ServerResponseRate      int64                                 `json:"server_response_rate"`
	ServerSettings          []jsonCTEProfileServiceSetting        `json:"server_settings"`
	SyslogSettings          jsonCTEProfileSyslogSettings          `json:"syslog_settings"`
	SystemAdminLogger       jsonCTEProfileManagementServiceLogger `json:"system_admin_logger"`
	UploadSettings          jsonCTEProfileUploadSettings          `json:"upload_settings"`
}

type jsonCTEProfilesList struct {
	ID                     string `json:"id"`
	URI                    string `json:"uri"`
	Account                string `json:"account"`
	Application            string `json:"application"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
	Name                   string `json:"name"`
	Description            string `json:"description"`
	LDTQOSCapCPUAllocation bool   `json:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    int64  `json:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      string `json:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        int64  `json:"ldt_qos_rekey_rate"`
	ConciseLogging         bool   `json:"concise_logging"`
	ConnectTimeout         int64  `json:"connect_timeout"`
	LDTQOSSchedule         string `json:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  int64  `json:"ldt_qos_status_check_rate"`
	MetadataScanInterval   int64  `json:"metadata_scan_interval"`
	MFAExemptUserSetID     string `json:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   string `json:"mfa_exempt_user_set_name"`
	OIDCConnectionID       string `json:"oidc_connection_id"`
	OIDCConnectionName     string `json:"oidc_connection_name"`
	RWPOperation           string `json:"rwp_operation"`
	RWPProcessSet          string `json:"rwp_process_set"`
	ServerResponseRate     int64  `json:"server_response_rate"`
	// QOSSchedules            []jsonCTEProfileQOSSchedule           `json:"qos_schedules"`
	// ServerSettings          []jsonCTEProfileServiceSetting        `json:"server_settings"`
	// ManagementServiceLogger jsonCTEProfileManagementServiceLogger `json:"management_service_logger"`
	// PolicyEvaluationLogger  jsonCTEProfileManagementServiceLogger `json:"policy_evaluation_logger"`
	// SecurityAdminLogger     jsonCTEProfileManagementServiceLogger `json:"security_admin_logger"`
	// SystemAdminLogger       jsonCTEProfileManagementServiceLogger `json:"system_admin_logger"`
	// FileSettings            jsonCTEProfileFileSettings            `json:"file_settings"`
	// SyslogSettings          jsonCTEProfileSyslogSettings          `json:"syslog_settings"`
	// UploadSettings          jsonCTEProfileUploadSettings          `json:"upload_settings"`
	// DuplicateSettings       jsonCTEProfileDuplicateSettings       `json:"duplicate_settings"`
	// CacheSettings           jsonCTEProfileCacheSettings           `json:"cache_settings"`
}
