package pwdserv

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type validFunc struct {
	name       string
	validation Validation
}

func (n *validFunc) addFunc(name string, val Validation) {

	n.name = name
	n.validation = val
}

// ComfirmPassword validator checks the NewPassword against the ConfirmPassword.
func ComfirmPassword(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckConfirm == true {
		res := strings.TrimSpace(password.NewPassword) == strings.TrimSpace(password.ConfirmPassword)
		if res == false {
			return false, errors.New("Confirmation password does not match.")
		}
	}

	return true, nil
}

// CheckLength validator checks the NewPassword MinLength.
func CheckLength(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckMinLength == true {
		res := len(strings.TrimSpace(password.NewPassword)) >= config.MinLength

		if res == false {
			err := fmt.Sprintf("Passwords must be a minimum of %d characters.", config.MinLength)
			return false, errors.New(err)
		}
	}

	return true, nil
}

// CheckUserID validator checks the NewPassword against the UserID.
func CheckUserID(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckUserID == true {
		lowerUID := strings.ToLower(password.UserID)
		lowerPass := strings.ToLower(password.NewPassword)

		indx := strings.Index(lowerPass, lowerUID)

		if indx >= 0 {
			return false, errors.New("Password may not contain the UserID/ Username.")
		}
	}

	return true, nil
}

// CheckUppercase validator checks the NewPassword for upper-case characters.
func CheckUppercase(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckUppercase == true {
		res, _ := regexp.MatchString("(.*[A-Z])", password.NewPassword)

		if res == false {
			return false, errors.New("Password must contain at least 1 Capital letter.")
		}
	}

	return true, nil
}

// CheckLowercase validator checks the NewPassword for lower-case characters.
func CheckLowercase(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckLowercase == true {
		res, _ := regexp.MatchString("(.*[a-z])", password.NewPassword)

		if res == false {
			return false, errors.New("Password must contain at least 1 lower case character.")
		}
	}

	return true, nil
}

// CheckNumeric validator checks the NewPassword for numeric characters.
func CheckNumeric(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckNumeric == true {
		res, _ := regexp.MatchString("(.*[0-9])", password.NewPassword)

		if res == false {
			return false, errors.New("Password must contain at least 1 numeric character.")
		}
	}

	return true, nil
}

// CheckSpecialChar validator checks the NewPassword for special characters.
func CheckSpecialChar(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckSpecialChar == true {
		str := config.SpecialChar
		for _, r := range str {
			elem := string(r)
			indx := strings.Index(password.NewPassword, elem)
			if indx >= 0 {
				return true, nil
			}
		}
		err := fmt.Sprintf("Password must contain at least 1 of the following characters: '%s'.", config.SpecialChar)
		return false, errors.New(err)
	}

	return true, nil
}

// CheckWhiteSpace validator checks the NewPassword for white space.
func CheckWhiteSpace(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckWhiteSpace == true {
		res, _ := regexp.MatchString("(.*[\\s])", password.NewPassword)

		if res == true {
			return false, errors.New("Space is not allowed.")
		}
	}

	return true, nil
}

// CheckHistory validator checks the NewPasswordHash against the PasswordHistory
func CheckHistory(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckHistory == true {
		err := fmt.Sprintf("You are also not allowed to use any of your previous %d passwords.", config.MinHistory)
		if password.NewPassword == password.OldPassword {
			return false, errors.New(err)
		}

		if len(password.PasswordHistory) > 0 {
			// In his majesty's service, one must always choose the lesser of two weevils
			count := min(config.MinHistory-1, len(password.PasswordHistory))
			for i := 0; i < count; i++ {
				res := strings.TrimSpace(password.NewPasswordHash) == strings.TrimSpace(password.PasswordHistory[i])
				if res == true {
					return false, errors.New(err)
				}
			}
		}
	}

	return true, nil
}

// CheckBlackList validator checks the NewPassword against the BlackList
func CheckBlackList(password *Password, config *PasswordRules) (bool, error) {
	if config.CheckBlackList == true {

		if len(config.BlackList) > 0 {
			lowerPass := strings.ToLower(password.NewPassword)
			for i := 0; i < len(config.BlackList); i++ {
				n := strings.Count(lowerPass, config.BlackList[i])
				if n > 0 {
					err := fmt.Sprintf("Password contains black listed word '%s'.", config.BlackList[i])
					return false, errors.New(err)
				}
			}
		}
	}

	return true, nil
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
