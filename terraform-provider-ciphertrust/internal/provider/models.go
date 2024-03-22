package provider

type User struct {
	UserID   string `tfsdk:"user_id"`
	Name     string `tfsdk:"name"`
	UserName string `tfsdk:"username"`
	Nickname string `tfsdk:"nickname"`
	Email    string `tfsdk:"email"`
}
