package pwdfile

import (
    "bufio"
    "os"
    "strings"
)

type ApiKeyLoginContext struct {
    name      string
    userroles map[string]string
}

func (a ApiKeyLoginContext) VerifyToken(token string) (ok bool, roles []string, err error) {
    return a.VerifyUserPass(BEARER_AUTH_USER, token)
}

func (a ApiKeyLoginContext) Name() string {
    return a.name
}

func (a ApiKeyLoginContext) VerifyUserPass(usr string, pwd string) (ok bool, roles []string, err error) {
    if usr != BEARER_AUTH_USER {
        return false, nil, nil
    }

    _roles, _ok := a.userroles[pwd]
    if !_ok {
        return false, nil, nil
    }

    _ret := make([]string, 0)
    _ret = append(_ret, strings.Split(_roles, ",")...)

    return true, _ret, nil
}

func NewApiKeyLoginContext(n string) *ApiKeyLoginContext {
    return &ApiKeyLoginContext{name: n, userroles: make(map[string]string)}
}

// ReadFromHtpasswd loads api-keys and roles from an htpasswd-style file.
//
// - Each non-empty, non-comment line must have the form "apikey::role1,...,roleN".
// - Lines beginning with '/', '#', ';', ':', '%', '!', or '$' are treated as comments and ignored.
// - Reading stops when a line containing only "END" is encountered.
func (g *ApiKeyLoginContext) ReadFromHtpasswd(f string) {
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
            if _sline[0] == '*' {
                continue
            }
            _upr := strings.SplitN(_sline, ":", 3)
            if len(_upr) != 3 {
                continue
            }
            //g.usercreds[_upr[0]] = _upr[1]
            // we ignore the password field except
            // when it is used to disable an entry
            if _upr[1] == "!" {
                continue
            }
            g.userroles[_upr[0]] = _upr[2]
            //log.Printf("created entry for %s", _upr[0])
        }
    }
}
