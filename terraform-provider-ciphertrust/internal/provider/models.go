package provider

type User struct {
	UserID   string `json:"user_id"`
	Name     string `json:"name"`
	UserName string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
