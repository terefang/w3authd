package pwdfile

import (
	"bufio"
	"os"
	"strings"

	"github.com/go-crypt/crypt"
	"github.com/terefang/gommons/pkg/xbytes"
	"github.com/terefang/gommons/pkg/xotp"
	tcrypt "github.com/tredoe/crypt"
	"github.com/tredoe/crypt/apr1_crypt"
	"github.com/tredoe/crypt/md5_crypt"
	"github.com/tredoe/crypt/sha512_crypt"
)

func ValidateCryptedCredential(_given string, _encrypted string) (bool, error) {
	if strings.HasPrefix(_encrypted, "{plain}") {
		return _given == _encrypted[7:], nil
	} else if strings.HasPrefix(_encrypted, "{OATH}") {
		// contains an url encoded in b64
		_str := xbytes.FromBase64([]byte(_encrypted[6:]))
		_otp, err := xotp.FromURL(string(_str))
		if err != nil {
			return false, err
		}
		_code, err := _otp.TOTPWithWindow(1)
		if err != nil {
			return false, err
		}
		for _, c := range _code {
			if c == _given {
				return true, nil
			}
		}
		return false, nil
	} else {
		_dec, _ := crypt.NewDefaultDecoder()
		_verifier, _verr := _dec.Decode(_encrypted)
		if _verr != nil {
			_verifier, _verr := tcrypt.NewFromHash(_encrypted)
			if _verr != nil {
				return false, _verr
			}
			_err := _verifier.Verify(_encrypted, []byte(_given))
			if _err != nil {
				return false, _err
			}
			return true, nil
		} else {
			return _verifier.MatchAdvanced(_given)
		}
	}
}

func ValidateCryptedCredentialSimple(pwd string, p string) bool {
	_b, _ := ValidateCryptedCredential(pwd, p)
	return _b
}

func CryptApr1Credential(_given string) (string, error) {
	_crypt := apr1_crypt.New()
	return _crypt.Generate([]byte(_given), make([]byte, 0))
}

func Crypt6Credential(_given string) (string, error) {
	_crypt := sha512_crypt.New()
	return _crypt.Generate([]byte(_given), make([]byte, 0))
}

func Crypt1Credential(_given string) (string, error) {
	_crypt := md5_crypt.New()
	return _crypt.Generate([]byte(_given), make([]byte, 0))
}

func TotpCredential(_given string) (string, error) {
	_otp, err := xotp.From([]byte(_given), xotp.DefaultDigits, xotp.DefaultAlgorithm)
	if err != nil {
		return "", err
	}
	return _otp.ToSimple(), nil
}

func TotpCredentialUrl(_given string) (string, error) {
	_otp, err := xotp.From([]byte(_given), xotp.DefaultDigits, xotp.DefaultAlgorithm)
	if err != nil {
		return "", err
	}
	return _otp.ToURL(), nil
}

type GenericFileLoginContext struct {
	name           string
	usercreds      map[string]string
	userroles      map[string]string
	IsAllowAnyUser bool
}

func (g GenericFileLoginContext) Name() string {
	return g.name
}

func (g GenericFileLoginContext) VerifyUserPass(usr string, pwd string) (ok bool, roles []string, err error) {
	_pwd, _ok := g.usercreds[usr]
	if (!_ok) && g.IsAllowAnyUser {
		_pwd, _ok = g.usercreds["*"]
	}
	if !_ok {
		return false, nil, nil
	}
	if _pwd == "x" {
		return false, nil, nil
	}
	if _pwd == "*" {
		return false, nil, nil
	}

	if _pwd == "" {
		// ignore valiadation
	} else if !ValidateCryptedCredentialSimple(pwd, _pwd) {
		return false, nil, nil
	}

	_ret := make([]string, 0)
	_ret = append(_ret, usr)
	_rol, _ok := g.userroles[usr]
	if !_ok {
		return true, _ret, nil
	}
	_ret = append(_ret, strings.Split(_rol, ",")...)
	return true, _ret, nil
}

func NewGenericFileLoginContext(n string) *GenericFileLoginContext {
	return &GenericFileLoginContext{name: n, usercreds: make(map[string]string), userroles: make(map[string]string)}
}

// ReadFromHtpasswd loads user credentials and roles from an htpasswd-style file.
//
// - Each non-empty, non-comment line must have the form "username:password".
// - Lines beginning with '/', '#', ';', ':', '%', '!', or '$' are treated as comments and ignored.
// - Reading stops when a line containing only "END" is encountered.
// - Entries whose username begins with '*' are ignored unless isAllowAnyUser is true.
// - Existing entries for the same username are overwritten by later entries in the file.
// - If the file cannot be opened or an error occurs while reading, the method returns without reporting an error.
func (g *GenericFileLoginContext) ReadFromHtpasswd(f string, isAllowAnyUser bool) {
	g.IsAllowAnyUser = isAllowAnyUser
	_fh, _ferr := os.OpenFile(f, os.O_RDONLY, 0)
	defer _fh.Close()
	if _ferr == nil {
		_bh := bufio.NewReaderSize(_fh, 8192)
		for _ferr == nil {
			_line, _isp, _err := _bh.ReadLine()
			_ferr = _err
			if _isp || _err != nil {
				return
			}
			_sline := strings.TrimSpace(string(_line))
			if len(_sline) == 0 {
				continue
			}
			if _sline == "END" {
				return
			}
			if _sline[0] == '/' {
				continue
			}
			if _sline[0] == '#' {
				continue
			}
			if _sline[0] == ';' {
				continue
			}
			if _sline[0] == ':' {
				continue
			}
			if _sline[0] == '%' {
				continue
			}
			if _sline[0] == '!' {
				continue
			}
			if _sline[0] == '$' {
				continue
			}
			// default any user
			if (_sline[0] == '*') && (!g.IsAllowAnyUser) {
				continue
			}
			_upr := strings.SplitN(_sline, ":", 3)
			g.usercreds[_upr[0]] = _upr[1]
			g.userroles[_upr[0]] = _upr[2]
			//log.Printf("created entry for %s", _upr[0])
		}
	}
}
