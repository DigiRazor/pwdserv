package pwdserv_test

import (
	"errors"

	"github.com/DigiRazor/pwdserv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pwdserv", func() {
	Context("given you call New() function", func() {
		It("should create new instance", func() {
			serv := pwdserv.New()
			Expect(serv).ToNot(BeNil())
		})
	})

	Context("given you have an instance of the service", func() {
		var blackList []string

		It("should not return an error for valid config data when calling SetConfig()", func() {
			cfgData := []byte(`{
					"CheckConfirm": true,
					"CheckMinLength": true,
					"MinLength": 8,
					"CheckUserID": true,
					"CheckUppercase": true,
					"CheckLowercase": true,
					"CheckNumeric": true,
					"CheckSpecialChar": true,
					"SpecialChar": "!@#$%*/+",
					"CheckWhiteSpace": true,        
					"CheckHistory": true,
					"MinHistory": 12,
					"CheckBlackList": true
				}`)
			serv := pwdserv.New()
			err := serv.SetConfig(cfgData, blackList)

			Expect(err).ToNot(HaveOccurred())
		})

		It("should return an error for invalid config data when calling SetConfig().", func() {
			cfgData := []byte("")
			serv := pwdserv.New()
			err := serv.SetConfig(cfgData, blackList)

			Expect(err).To(HaveOccurred())
		})

		It("should return an error if SetConfig() wasn't called.", func() {

			serv := pwdserv.New()

			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn6?R@",
				ConfirmPassword: "yVHn6?R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn6?R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("given you have a configured service", func() {
		blackList := []string{
			"test",
			"password",
		}

		cfgData := []byte(`{
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
		serv := pwdserv.New()
		var _ = serv.SetConfig(cfgData, blackList)

		It("should return when calling Validate() with a valid password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn6?R@",
				ConfirmPassword: "yVHn6?R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn6?R@",
			}

			err := serv.Validate(&pwd)

			Expect(err).ToNot(HaveOccurred())
		})

		It("should return error when calling Validate() with an invalid Confirm password.", func() {

			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn6?R@",
				ConfirmPassword: "yVHn6?Ra",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn6?R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Confirmation password does not match.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with a short password.", func() {

			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVH6@",
				ConfirmPassword: "yVH6@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVH6@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Passwords must be a minimum of 8 characters.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with a UserID in password.", func() {

			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "Abhw089*",
				ConfirmPassword: "Abhw089*",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "Abhw089*",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password may not contain the UserID/ Username.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with no upper-case in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yvhn6?r@",
				ConfirmPassword: "yvhn6?r@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yvhn6?r@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password must contain at least 1 Capital letter.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with no lower-case in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "YVHN6?R@",
				ConfirmPassword: "YVHN6?R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "YVHN6?R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password must contain at least 1 lower case character.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with no numeric characters in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHna?R@",
				ConfirmPassword: "yVHna?R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHna?R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password must contain at least 1 numeric character.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with no special characters in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn63R2",
				ConfirmPassword: "yVHn63R2",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn63R2",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password must contain at least 1 of the following characters: '!@#$%*+/'.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() with a space in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn6 R@",
				ConfirmPassword: "yVHn6 R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn6 R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Space is not allowed.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() and the password has not changed.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "B1ge@rs*",
				ConfirmPassword: "B1ge@rs*",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "B1ge@rs*",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("You are also not allowed to use any of your previous 3 passwords.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() and the password is in history.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "3g9m@9W7",
				ConfirmPassword: "3g9m@9W7",
				PasswordHistory: []string{"$sG96r#X", "3g9m@9W7"},
				NewPasswordHash: "3g9m@9W7",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("You are also not allowed to use any of your previous 3 passwords.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

		It("should return error when calling Validate() and the password is in the black list.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "Test6?R@",
				ConfirmPassword: "Test6?R@",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "Test6?R@",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("Password contains black listed word 'test'.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})
	})

	Context("given you have a configured service with validators switched off", func() {
		blackList := []string{
			"test",
			"password",
		}

		cfgData := []byte(`{
			"CheckConfirm": true,
			"CheckMinLength": true,
			"MinLength": 8,
			"CheckUserID": true,
			"CheckUppercase": true,
			"CheckLowercase": true,
			"CheckNumeric": true,
			"CheckSpecialChar": false,
			"SpecialChar": "!@#$%*+/",
			"CheckWhiteSpace": true,
			"CheckHistory": true,
			"MinHistory": 3,
			"CheckBlackList": true
		}`)
		serv := pwdserv.New()
		var _ = serv.SetConfig(cfgData, blackList)

		It("should not return error when calling Validate() with no special characters in password.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "yVHn63R2",
				ConfirmPassword: "yVHn63R2",
				PasswordHistory: []string{"$sG96r#X", "3g9m&9W7"},
				NewPasswordHash: "yVHn63R2",
			}

			err := serv.Validate(&pwd)
			Expect(err).ToNot(HaveOccurred())

		})

		It("should return error when calling Validate() and the password is in history.", func() {
			pwd := pwdserv.Password{
				UserID:          "ABHW089",
				OldPassword:     "B1ge@rs*",
				NewPassword:     "3g9m@9W7",
				ConfirmPassword: "3g9m@9W7",
				PasswordHistory: []string{"$sG96r#X", "3g9m@9W7", "Mnj8NU%$", "&5=FLxGa"},
				NewPasswordHash: "3g9m@9W7",
			}

			err := serv.Validate(&pwd)
			Expect(err).To(HaveOccurred())

			errExpect := errors.New("You are also not allowed to use any of your previous 3 passwords.")
			Expect(err).To(BeEquivalentTo(errExpect))
		})

	})

})
