// Copyright 2017 DigiRazor (Pty) Ltd. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

// Package pwdserv provides an extendable service to validate user passwords when password changes.
//
// A basic example:
//
// package main
//
// import (
// 	"fmt"
//
// 	"github.com/DigiRazor/pwdserv"
// )
//
// var blackList = []string{
// 	"test",
// 	"password",
// }
//
// var cfgData = []byte(`{
// 			"CheckConfirm": true,
// 			"CheckMinLength": true,
// 			"MinLength": 8,
// 			"CheckUserID": true,
// 			"CheckUppercase": true,
// 			"CheckLowercase": true,
// 			"CheckNumeric": true,
// 			"CheckSpecialChar": true,
// 			"SpecialChar": "!@#$%*+/",
// 			"CheckWhiteSpace": true,
// 			"CheckHistory": true,
// 			"MinHistory": 3,
// 			"CheckBlackList": true
// 		}`)
//
// func main() {
//
// 	serv := pwdserv.New()
// 	err := serv.SetConfig(cfgData, blackList)
// 	if err != nil {
// 		fmt.Printf("Setup Error: %s\n", err)
// 	}
//
// 	pwd := pwdserv.Password{
// 		UserID:          "ABHW089",
// 		OldPassword:     "B1ge@rs*",
// 		NewPassword:     "yVHn6?R@",
// 		ConfirmPassword: "yVHn6?R@",
// 		PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
// 		NewPasswordHash: "yVHn6?R@",
// 	}
// 	err = serv.Validate(&pwd)
// 	if err != nil {
// 		fmt.Printf("Validate Error: %s\n", err)
// 	} else {
// 		fmt.Println("Success")
// 	}
// }

package pwdserv

import (
	"encoding/json"
	"errors"
)

// Validation is a function that can be registered to validate
// passwords.
type Validation func(*Password, *PasswordRules) (bool, error)

// PasswordService service to validate user password via
// configurable validator methods
type PasswordService struct {
	vl     map[string]*validFunc
	config *PasswordRules
}

// New creates a new initialized PasswordService
func New() *PasswordService {
	return &PasswordService{}
}

// SetConfig loads the build-in validators then parses the configuration data (JSON)
// and adds the blacklist to the configuration.
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

// Validate takes a Password structure to validate with the build-in/ custom validations,
// depending on the configuration setup.
//
// The returning error has the description of the validation that failed.
// If the password is valid the returning error will be nil.
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

// Add registers a new validator to be used in the validation of the new password.
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
