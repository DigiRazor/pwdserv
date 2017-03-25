# Go-PwdServ [![Build Status](https://travis-ci.org/DigiRazor/pwdserv.svg?branch=master)](https://travis-ci.org/DigiRazor/pwdserv)

Go-PwdServ is a lightweight password verification service for [Go](https://golang.org/).

This service supports the use of build-in validators, to validate a new password's complexity according to the rules enabled.

```
go get github.com/DigiRazor/pwdserv
```
## Features

### Basic Rules

**Confirm Password:** Basic check to make sure that the new password and confirm password matches.

**Minimum Length:** Basic check for minimum length of the password.

**User ID/ User-name:** Basic check to not allow the user id/ user name be in the password.

**Upper-case characters:** Basic check to confirm if the password contains an upper-case character.

**Lower-case characters:** Basic check to confirm if the password contains a lower-case character.

**Numeric characters:** Basic check to confirm if the password contains a numeric character.

**Special characters:** Basic check to confirm if the password contains any of the supplied special character(s).

**White space:** Basic check to not allow white space in the password.

**Historical passwords:** Basic check to compare the password to any of the supplied historical password.

**Black-list:** Basic check to not allow the password to be any of the supplied password(s) in the list.

## Usage

This is a quick introduction (Go-PwdServ, world; world, Go-PwdServ):

Basic example
```go
package main

import (
	"fmt"

	"github.com/DigiRazor/pwdserv"
)

var blackList = []string{
	"test",
	"password",
}

var cfgData = []byte(`{
			"CheckConfirm": true,
			"CheckMinLength": true,
			"MinLength": 8,
			"CheckUserID": true,
			"CheckUppercase": true,
			"CheckLowercase": true,
			"CheckNumeric": true,
			"CheckSpecialChar": true,
			"SpecialChar": "!@#$%*+/",
			"CheckWhiteSpace": true,
			"CheckHistory": true,
			"MinHistory": 3,
			"CheckBlackList": true
		}`)

func main() {

	serv := pwdserv.New()
	err := serv.SetConfig(cfgData, blackList)
	if err != nil {
		fmt.Printf("Setup Error: %s\n", err)
	}

	pwd := pwdserv.Password{
		UserID:          "ABHW089",
		OldPassword:     "B1ge@rs*",
		NewPassword:     "yVHn6?R@",
		ConfirmPassword: "yVHn6?R@",
		PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
		NewPasswordHash: "yVHn6?R@",
	}
	err = serv.Validate(&pwd)
	if err != nil {
		fmt.Printf("Validate Error: %s\n", err)
	} else {
		fmt.Println("Success")
	}
}
```

Custom Validations (With Logger)
```go
package main

import (
	"fmt"
	"time"

	"github.com/DigiRazor/pwdserv"
)

var blackList = []string{
	"test",
	"password",
}

var cfgData = []byte(`{
			"CheckConfirm": true,
			"CheckMinLength": true,
			"MinLength": 8,
			"CheckUserID": true,
			"CheckUppercase": true,
			"CheckLowercase": true,
			"CheckNumeric": true,
			"CheckSpecialChar": true,
			"SpecialChar": "!@#$%*+/",
			"CheckWhiteSpace": true,
			"CheckHistory": true,
			"MinHistory": 3,
			"CheckBlackList": true
		}`)

// Logger func
func Logger(inner pwdserv.Validation, name string) pwdserv.Validation {
	return func(password *pwdserv.Password, config *pwdserv.PasswordRules) (bool, error) {
		start := time.Now()

		r, e := inner(password, config)

		fmt.Printf(
			"%s\t%s\n",
			name,
			time.Since(start),
		)

		return r, e
	}
}

// CustomValidation1 function
func CustomValidation1(password *pwdserv.Password, config *pwdserv.PasswordRules) (bool, error) {
	// do custom validations
	fmt.Println("Custom Validation Check 1")
	return true, nil
}

// CustomValidation2 function
func CustomValidation2(password *pwdserv.Password, config *pwdserv.PasswordRules) (bool, error) {
	// do custom validations
	fmt.Println("Custom Validation Check 2")
	return true, nil
}

func main() {

	serv := pwdserv.New()
	err := serv.SetConfig(cfgData, blackList)
	if err != nil {
		fmt.Printf("Setup Error: %s\n", err)
	}

	pwd := pwdserv.Password{
		UserID:          "ABHW089",
		OldPassword:     "B1ge@rs*",
		NewPassword:     "yVHn6?R@",
		ConfirmPassword: "yVHn6?R@",
		PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
		NewPasswordHash: "yVHn6?R@",
	}

	serv.Add("Custom1", Logger(CustomValidation1, "Custom1"))
	serv.Add("Custom2", Logger(CustomValidation2, "Custom2"))

	err = serv.Validate(&pwd)
	if err != nil {
		fmt.Printf("Validate Error: %s\n", err)
	} else {
		fmt.Println("Success")
	}
}

```
## Change log

**Initial Version:** 
- Basic validations as per basic feature list
- Base unit tests
- Allowing for custom validation