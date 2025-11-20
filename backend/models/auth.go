package models

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the JWT token response
type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // "-" means don't send password in JSON
}
