package pwdserv

import (
	"encoding/json"
	"errors"
)

// Validation is a function that can be registered to validate
// passwords.
type Validation func(*Password, *PasswordRules) (bool, error)

// PasswordService service to validate user passwords
type PasswordService struct {
	vl     map[string]*validFunc
	config *PasswordRules
}

// New creates a new PasswordService
func New() *PasswordService {
	return &PasswordService{}
}

// SetConfig function
func (z *PasswordService) SetConfig(configData []byte, blackList []string) error {
	var cfg *PasswordRules

	z.Add("CCP", ComfirmPassword)
	z.Add("CL", CheckLength)
	z.Add("CUN", CheckUserID)
	z.Add("CUC", CheckUppercase)
	z.Add("CLC", CheckLowercase)
	z.Add("CNC", CheckNumeric)
	z.Add("CSC", CheckSpecialChar)
	z.Add("CWS", CheckWhiteSpace)
	z.Add("CH", CheckHistory)
	z.Add("CBL", CheckBlackList)

	err := json.Unmarshal(configData, &cfg)
	if err != nil {
		return err
	}

	cfg.BlackList = blackList

	z.config = cfg

	return nil
}

// Validate function
func (z *PasswordService) Validate(model *Password) error {

	if len(z.vl) == 0 {
		return errors.New("No validators loaded.")
	}

	for _, value := range z.vl {
		validation := value.validation
		isvalid, err := validation(model, z.config)
		if isvalid == false {
			return err
		}
	}

	return nil
}

// Add function
func (z *PasswordService) Add(name string, val Validation) {

	if z.vl == nil {
		z.vl = make(map[string]*validFunc)
	}

	v := z.vl[name]
	if v == nil {
		v = new(validFunc)
		z.vl[name] = v
	}

	v.addFunc(name, val)
}
