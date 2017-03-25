package pwdserv_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestPwdserv(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pwdserv Suite")
}
