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
