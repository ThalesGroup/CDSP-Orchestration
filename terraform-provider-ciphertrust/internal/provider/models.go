package provider

type UserLoginFlags struct {
	PreventUILogin bool `json:"prevent_ui_login"`
}

type User struct {
	UserID                 string         `json:"user_id"`
	Name                   string         `json:"full_name"`
	UserName               string         `json:"username"`
	Nickname               string         `json:"nickname"`
	Email                  string         `json:"email"`
	Password               string         `json:"password"`
	IsDomainUser           bool           `json:"is_domain_user"`
	LoginFlags             UserLoginFlags `json:"login_flags"`
	PasswordChangeRequired bool           `json:"password_change_required"`
}

type Key struct {
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
