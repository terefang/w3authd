package pwdfile

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terefang/gommons/pkg/xcrypto"
)

type JwtLoginContext struct {
	name          string
	method        string
	allowCatchAll bool
	keys          map[string]string
}

func (a *JwtLoginContext) SetAllowCatchAll(all bool) {
	a.allowCatchAll = all
}

func (a *JwtLoginContext) SetMethod(m string) {
	a.method = m
}

func (a JwtLoginContext) VerifyToken(token string) (ok bool, roles []string, err error) {
	return VerifyToken(a.keys, token)
}

func FromBase64(b []byte) []byte {
	_bytes, _err := base64.StdEncoding.DecodeString(string(b))
	if _err != nil {
		return []byte("")
	}
	return _bytes
}

func ConvertRsaKey(pkey string) (any, error) {
	if strings.HasPrefix(pkey, "MI") {
		// is b64 encoded ?
		pkey = string(FromBase64([]byte(pkey)))
	}

	if strings.HasPrefix(pkey, "-----") {
		// PEM format
		_key, _err := jwt.ParseRSAPublicKeyFromPEM([]byte(pkey))
		if _err == nil {
			return _key, nil
		}
		// maybe it is a certificate, then extract public key
		_block, _ := pem.Decode([]byte(pkey))
		if _block != nil {
			if strings.Contains(_block.Type, "CERTIFICATE") {
				return x509.ParseCertificate(_block.Bytes)
			}
		}
	} else if pkey[0] == 0x30 && pkey[1] > 0x80 {
		// DER format
		_key, _err := x509.ParsePKCS1PublicKey([]byte(pkey))
		if _err == nil {
			return _key, nil
		}
		_key2, _err2 := x509.ParsePKIXPublicKey([]byte(pkey))
		if _err2 == nil {
			return _key2, nil
		}
		return nil, _err2
	}
	return nil, errors.New("key in unknown format")
}

func ConvertEcKey(pkey string) (any, error) {
	if strings.HasPrefix(pkey, "MI") {
		// is b64 encoded ?
		pkey = string(FromBase64([]byte(pkey)))
	}

	if strings.HasPrefix(pkey, "-----") {
		// PEM format
		_key, _err := jwt.ParseECPublicKeyFromPEM([]byte(pkey))
		if _err == nil {
			return _key, nil
		}
		_key2, _err2 := jwt.ParseEdPublicKeyFromPEM([]byte(pkey))
		if _err2 == nil {
			return _key2, nil
		}
		return nil, _err2
	} else if pkey[0] == 0x30 && pkey[1] > 0x80 {
		// DER format
		_key, _err := x509.ParsePKIXPublicKey([]byte(pkey))
		if _err == nil {
			return _key, nil
		}
		return nil, _err
	}
	return nil, errors.New("key in unknown format")
}

func ConvertSecretKeyToBytes(skey string) ([]byte, error) {
	if strings.HasPrefix(skey, "MI") {
		// is b64 encoded DER ?
		skey = string(FromBase64([]byte(skey)))
	}

	// key is a simple b64 byte dump or?
	if strings.HasPrefix(skey, "-----") {
		_bytes, _flag, _err := xcrypto.DecodeSecretFromPem([]byte(skey))
		if _err != nil {
			return nil, _err
		}
		if _flag {
			panic("encrypted secret key unsupported")
		}
		return _bytes, nil
	} else if skey[0] == 0x30 && skey[1] > 0x80 {
		// DER format
		_bytes, _type, _err := xcrypto.DecodeTypeFromDER([]byte(skey))
		if _err == nil {
			if _type == "SECRET KEY" {
				return _bytes, nil
			}
			return nil, errors.New("key in unknown format " + _type)
		}
		return nil, _err
	} else if strings.HasPrefix(skey, "b64:") {
		return FromBase64([]byte(skey[4:])), nil
	} else if strings.HasPrefix(skey, "raw:") {
		return []byte(skey[4:]), nil
	}
	return nil, errors.New("key in unknown format")
}

func (a JwtLoginContext) Name() string {
	return a.name
}

func (a JwtLoginContext) VerifyUserPass(usr string, pwd string) (ok bool, roles []string, err error) {
	if usr != a.method {
		return false, nil, nil
	}
	return a.VerifyToken(pwd)
}

func NewJwtLoginContext(n string) *JwtLoginContext {
	return &JwtLoginContext{name: n, keys: make(map[string]string)}
}

func (g *JwtLoginContext) ReadFromKeyFile(f string) {
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
			if _sline[0] == '*' && !g.allowCatchAll {
				continue
			}
			// issuer|algo1,...,algoN|b64keyblob
			_upr := strings.SplitN(_sline, "|", 3)
			if len(_upr) != 3 {
				continue
			}
			if strings.HasPrefix(_upr[2], "file:") {
				// all relative except "/..." and "~/..."
				_file := _upr[2][5:]
				if strings.HasPrefix(_file, "~/") {
					_home, _err := os.UserHomeDir()
					if _err != nil {
						panic(_err)
					}
					_file = filepath.Join(_home, _file[2:])
				} else if !strings.HasPrefix(_file, "/") {
					// is relative
					_parent := filepath.Dir(f)
					_file = filepath.Join(_parent, _file)
				}
				_bytes, _err := os.ReadFile(_file)
				if _err != nil {
					panic(_err)
				}
				_upr[2] = string(_bytes)
			}
			if _upr[1] != "" {
				_algos := strings.Split(_upr[1], ",")
				for _, _algo := range _algos {
					_identity := CanonicalizeIdentity(_upr[0], _algo)
					g.keys[_identity] = _upr[2]
				}
			} else {
				log.Printf("missing algo for %s", _upr[0])
			}
		}
	}
}

var jwaList = []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

func CanonicalizeIdentity(id string, algo string) string {
	// identity
	id = CanonicalizeString(strings.ToLower(id))
	// algo
	algo = CanonicalizeString(strings.ToUpper(algo))
	calgo := "INVALID"
	for _, k := range jwaList {
		if strings.Compare(algo, k) == 0 {
			calgo = k
			break
		}
	}
	return id + "#" + calgo
}

func CanonicalizeString(str string) string {
	str = strings.TrimSpace(str)
	r, _err := regexp.Compile("[^A-Za-z0-9\\-_]+")
	if _err == nil {
		str = r.ReplaceAllString(str, "_")
	}
	return str
}

func VerifyToken(_keys map[string]string, token string) (bool, []string, error) {
	_token, _err := jwt.Parse("x", func(token *jwt.Token) (any, error) {
		_alg := token.Method.Alg()
		_iss, _err := token.Claims.GetIssuer()
		if _err != nil {
			return nil, _err
		}
		// verify that we have key for issuer and algorithm
		_id := CanonicalizeIdentity(_iss, _alg)
		_key, _ok2 := _keys[_id]
		if !_ok2 {
			return nil, errors.New("key not found " + _id)
		}
		// parse key
		if strings.HasPrefix(_alg, "HS") {
			return ConvertSecretKeyToBytes(_key)
		} else if strings.HasPrefix(_alg, "RS") {
			return ConvertRsaKey(_key)
		} else if strings.HasPrefix(_alg, "PS") {
			return ConvertRsaKey(_key)
		} else if strings.HasPrefix(_alg, "ES") {
			return ConvertEcKey(_key)
		}
		return _key, nil
	})
	if _err != nil {
		return false, nil, _err
	}
	_roles := make([]string, 0)
	// put subject as username
	// since jwt is usually stark anonymous
	// this may be wrong
	_usr, _err := _token.Claims.GetSubject()
	if _err == nil {
		_roles = append(_roles, _usr)
	}

	// extract all claims exluding the well known
	_map, ok := _token.Claims.(jwt.MapClaims)
	if ok {
		_it := maps.Keys(_map)
		for k := range _it {
			switch k {
			case "exp":
			case "nbf":
			case "iat":
			case "aud":
			case "iss":
			case "sub":
			default:
				_r := fmt.Sprintf("%v=%v", k, _map[k])
				_roles = append(_roles, _r)
			}
		}
	}

	return true, _roles, nil
}
