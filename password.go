package pwdserv

import "encoding/json"

// Password struct for password validation
type Password struct {
	JWTToken        string
	ApplicationID   string
	UserID          string
	OldPassword     string
	NewPassword     string
	ConfirmPassword string

	PasswordHistory []string
	NewPasswordHash string
}

// PasswordRules struct
type PasswordRules struct {
	CheckConfirm     bool
	CheckMinLength   bool
	MinLength        int
	CheckUserID      bool
	CheckUppercase   bool
	CheckLowercase   bool
	CheckNumeric     bool
	CheckSpecialChar bool
	SpecialChar      string
	CheckWhiteSpace  bool
	CheckHistory     bool
	MinHistory       int
	CheckBlackList   bool
	BlackList        []string
	CustomConfig     json.RawMessage
}
