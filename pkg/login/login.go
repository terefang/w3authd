package login

import (
	"log"
	"w3authproxy/pkg/pwdfile"
)

type LoginContext interface {
	Name() string
	HandleLogin(usr string, pwd string) (ok bool, roles []string, err error)
}

type SimpleLoginContext struct {
	name string
	user string
	pass string
}

func (s SimpleLoginContext) Name() string {
	return s.name
}

func (s SimpleLoginContext) HandleLogin(_usr string, _pwd string) (ok bool, roles []string, err error) {
	if _usr == s.user && pwdfile.ValidateCryptedCredentialSimple(_pwd, s.pass) {
		log.Printf("Password validated for user %s", _usr)
		return true, nil, nil
	}
	log.Printf("Password failed for user %s", _usr)
	return false, nil, nil
}

func NewSimpleLoginContext(n string, u string, p string) LoginContext {
	_slc := &SimpleLoginContext{}
	_slc.name = n
	_slc.user = u
	_slc.pass = p
	return _slc
}
