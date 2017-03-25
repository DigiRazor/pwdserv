package pwdserv

import "encoding/json"

// Password struct for password validation.
type Password struct {
	// JWTToken can be used to store the token for the current session.
	JWTToken string
	// ApplicationID can be used to store a token for the current application.
	ApplicationID string
	// UserID is used to with the CheckUserID config switch.
	UserID string
	// OldPassword the current password for the user.
	OldPassword string
	// NewPassword the password to be validated.
	NewPassword string
	// ConfirmPassword is a confirmation of the new password to
	// ensure the user has typed in the password as expected.
	ConfirmPassword string

	// PasswordHistory is a slice containing the history of passwords
	// previously used by the user.
	PasswordHistory []string

	// NewPasswordHash is used to compare with PasswordHistory.
	NewPasswordHash string
}

// PasswordRules struct is the configuration options used
// to validate the password.
type PasswordRules struct {
	// CheckConfirm is the switch to validate with
	// the build-in ComfirmPassword validator.
	CheckConfirm bool

	// CheckMinLength is the switch to validate with
	// the build-in CheckLength validator.
	CheckMinLength bool

	// MinLength is the min no of characters that is allowed.
	MinLength int

	// CheckUserID is the switch to validate with
	// the build-in CheckUserID validator.
	CheckUserID bool

	// CheckUppercase is the switch to validate with
	// the build-in CheckUppercase validator.
	CheckUppercase bool

	// CheckLowercase is the switch to validate with
	// the build-in CheckLowercase validator.
	CheckLowercase bool

	// CheckNumeric is the switch to validate with
	// the build-in CheckNumeric validator.
	CheckNumeric bool

	// CheckSpecialChar is the switch to validate with
	// the build-in CheckSpecialChar validator.
	CheckSpecialChar bool

	// SpecialChar a string of special characters allowed.
	SpecialChar string

	// CheckWhiteSpace is the switch to validate with
	// the build-in CheckWhiteSpace validator.
	CheckWhiteSpace bool

	// CheckHistory is the switch to validate with
	// the build-in CheckHistory validator.
	CheckHistory bool

	// MinHistory the number of historical passwords to check.
	MinHistory int

	// CheckBlackList is the switch to validate with
	// the build-in CheckBlackList validator.
	CheckBlackList bool

	// BlackList a slice of words not allowed in passwords like: test, password ect
	BlackList []string

	// CustomConfig is a holder for custom configuration section
	CustomConfig json.RawMessage
}
