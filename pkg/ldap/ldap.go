package ldap

import (
	"crypto/tls"
	"errors"
	"log"
	"net/url"
	"strings"
	"w3authproxy/pkg/login"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/hcl/v2/hclsimple"
)

type LdapConfig struct {
	LdapUri                []string `hcl:"ldap_uri"`
	LdapStartTls           bool     `hcl:"ldap_start_tls,optional"`
	BindUsername           string   `hcl:"ldap_bind_username,optional"`
	BindPassword           string   `hcl:"ldap_bind_password,optional"`
	UserTemplate           string   `hcl:"ldap_user_template,optional"`
	BaseDN                 string   `hcl:"ldap_base_dn"`
	UserBaseDN             string   `hcl:"ldap_user_base_dn,optional"`
	UserSearch             string   `hcl:"ldap_user_search,optional"`
	UserRoleAttribute      []string `hcl:"ldap_user_role_attribute,optional"`
	UserRoleAttributeType  string   `hcl:"ldap_user_role_attribute_type,optional"`
	GroupBaseDN            string   `hcl:"ldap_group_base_dn,optional"`
	GroupSearch            string   `hcl:"ldap_group_search,optional"`
	GroupRoleAttribute     []string `hcl:"ldap_group_role_attribute,optional"`
	GroupRoleAttributeType string   `hcl:"ldap_group_role_attribute_type,optional"`
	AllowRoles             []string `hcl:"ldap_allow_roles,optional"`
	// HeaderMap map[string]string `hcl:"headermap"`
	// headermap = {
	//		key  = value
	// }
}

type LdapLoginContext struct {
	name string
	Ldap LdapConfig
}

func (l LdapLoginContext) Name() string {
	return l.name
}

func (l LdapLoginContext) HandleLogin(usr string, pwd string) (bool, []string, error) {
	ok, roles, err := l.HandleLoginInternal(usr, pwd)

	if err == nil && ok {
		if l.Ldap.AllowRoles != nil {
			if roles != nil {
				for _, role := range l.Ldap.AllowRoles {
					for _, r := range roles {
						if strings.EqualFold(r, role) {
							return true, roles, nil
						}
					}
				}
			}
			return false, nil, errors.New("insufficient ldap role")
		}
	}

	return ok, roles, err
}

func (l LdapLoginContext) HandleLoginInternal(usr string, pwd string) (ok bool, roles []string, err error) {
	_l, _, err := l.CreateConnection()
	if err != nil {
		return false, nil, err
	}
	defer _l.Close()

	var _dn string = ""
	if l.Ldap.UserTemplate != "" {
		// _l.Unbind()
		_dn = strings.Replace(l.Ldap.UserTemplate, "{u}", usr, -1)
		err = _l.Bind(_dn, pwd)
		if err != nil {
			log.Printf("UserBind %s failed - %s", _dn, err.Error())
			return false, nil, err
		}
	}

	if _dn == "" {
		_dn, err = l.FindUserDn(_l, usr)
		if err != nil {
			return false, nil, err
		}
		err = _l.Bind(_dn, pwd)
		if err != nil {
			log.Printf("UserBind %s failed - %s", _dn, err.Error())
			return false, nil, err
		}
	}

	if (l.Ldap.GroupBaseDN != "" && l.Ldap.GroupSearch != "") || l.Ldap.UserRoleAttribute != nil {
		_gl, err := l.FindUserGroups(_l, usr, _dn)
		if err != nil {
			return true, nil, err
		}
		return true, _gl, nil
	}
	return true, nil, nil
}

func (l LdapLoginContext) CreateConnection() (*ldapv3.Conn, string, error) {
	for _, _uri := range l.Ldap.LdapUri {
		_parsed, err := url.Parse(_uri)
		if err != nil {
			log.Printf("Invalid url %s - %s", _uri, err.Error())
			continue
		}

		var _l *ldapv3.Conn = nil

		if _parsed.Scheme == "ldaps" {

			_l, err = ldapv3.DialURL(_uri, ldapv3.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))

			if err != nil {
				log.Printf("Connection to %s failed - %s", _uri, err.Error())
				continue
			}

		} else {

			_l, err = ldapv3.DialURL(_uri)

			if err != nil {
				log.Printf("Connection to %s failed - %s", _uri, err.Error())
				continue
			}

			if l.Ldap.LdapStartTls {
				// Reconnect with TLS
				err = _l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					log.Printf("StartTls to %s failed - %s", _uri, err.Error())
					_l.Close()
					continue
				}
			}
		}

		if l.Ldap.BindUsername != "" {
			// test admin bind if available
			err = _l.Bind(l.Ldap.BindUsername, l.Ldap.BindPassword)
			if err != nil {
				log.Printf("AdminBind to %s with %s failed - %s", _uri, l.Ldap.BindUsername, err.Error())
				_l.Close()
				continue
			}
		}
		return _l, _uri, nil
	}
	return nil, "", errors.New("no responding servers found")
}

func (l LdapLoginContext) TestConnection() bool {
	_l, _, err := l.CreateConnection()
	if err != nil {
		return false
	}
	defer _l.Close()
	return true
}

func (l LdapLoginContext) FindUserDn(_l *ldapv3.Conn, usr string) (string, error) {
	_attrs := make([]string, 0)
	_attrs = append(_attrs, "dn")
	_attrs = append(_attrs, l.Ldap.UserRoleAttribute...)
	_sf := strings.Replace(l.Ldap.UserSearch, "{u}", ldapv3.EscapeFilter(usr), -1)
	// Search for the given username
	searchRequest := ldapv3.NewSearchRequest(
		l.Ldap.UserBaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
		_sf,
		_attrs,
		nil,
	)

	sr, err := _l.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) != 1 {
		return "", errors.New("User " + usr + " does not exist or too many entries returned")
	}

	return sr.Entries[0].DN, nil
}

func (l LdapLoginContext) FindUserGroups(_l *ldapv3.Conn, _usr string, _dn string) ([]string, error) {

	_roles := make([]string, 0)

	if l.Ldap.UserRoleAttribute != nil {
		_attrs := make([]string, 0)
		_attrs = append(_attrs, "dn")
		_attrs = append(_attrs, l.Ldap.UserRoleAttribute...)
		searchRequest := ldapv3.NewSearchRequest(
			_dn,
			ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			_attrs,
			nil,
		)
		sr, err := _l.Search(searchRequest)
		if err != nil {
			return nil, err
		}

		if len(sr.Entries) > 0 {
			for _, attr := range l.Ldap.UserRoleAttribute {
				_vl := sr.Entries[0].GetEqualFoldAttributeValues(attr)
				for _, _vv := range _vl {
					if strings.EqualFold("dn", l.Ldap.UserRoleAttributeType) {
						_vdn, _err := ldapv3.ParseDN(_vv)
						if _err != nil {
							_roles = append(_roles, _vv)
						} else {
							_roles = append(_roles, _vdn.RDNs[0].Attributes[0].Value)
						}
					} else {
						_roles = append(_roles, _vv)
					}
				}
			}
		}
	}

	if l.Ldap.GroupBaseDN != "" && l.Ldap.GroupSearch != "" {
		_attrs := make([]string, 0)
		_attrs = append(_attrs, "dn")
		if l.Ldap.GroupRoleAttribute != nil {
			_attrs = append(_attrs, l.Ldap.GroupRoleAttribute...)
		}
		_sf := strings.Replace(l.Ldap.GroupSearch, "{u}", ldapv3.EscapeFilter(_usr), -1)
		_sf = strings.Replace(_sf, "{dn}", ldapv3.EscapeFilter(_dn), -1)
		// Search for the given username
		searchRequest := ldapv3.NewSearchRequest(
			l.Ldap.GroupBaseDN,
			ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
			_sf,
			_attrs,
			nil,
		)

		sr, err := _l.Search(searchRequest)
		if err != nil {
			return nil, err
		}

		for _, entry := range sr.Entries {
			if l.Ldap.GroupRoleAttribute == nil || len(l.Ldap.GroupRoleAttribute) == 0 {
				_roles = append(_roles, entry.DN)
				continue
			}
			for _, attr := range l.Ldap.GroupRoleAttribute {
				_vl := entry.GetEqualFoldAttributeValues(attr)
				for _, _vv := range _vl {
					if strings.EqualFold("dn", l.Ldap.GroupRoleAttributeType) {
						_vdn, _err := ldapv3.ParseDN(_vv)
						if _err != nil {
							_roles = append(_roles, _vv)
						} else {
							_roles = append(_roles, _vdn.RDNs[0].Attributes[0].Value)
						}
					} else {
						_roles = append(_roles, _vv)
					}
				}
			}
		}
	}

	return _roles, nil
}

func NewLdapLoginContext(n string, f string, t bool) (login.LoginContext, error) {
	_llc := &LdapLoginContext{name: n, Ldap: LdapConfig{}}
	_err := hclsimple.DecodeFile(f, nil, &_llc.Ldap)
	if _err != nil {
		return nil, _err
	}

	if _llc.Ldap.UserBaseDN == "" {
		_llc.Ldap.UserBaseDN = _llc.Ldap.BaseDN
	}

	// NO! -- empty group base disables
	// role extraction from groups
	//if _llc.Ldap.GroupBaseDN == "" {
	//	_llc.Ldap.GroupBaseDN = _llc.Ldap.BaseDN
	//}

	if t {
		_ok := _llc.TestConnection()
		if !_ok {
			log.Println("No active ldap servers available.")
			return nil, errors.New("no active ldap servers available")
		}
	}
	return _llc, nil
}
