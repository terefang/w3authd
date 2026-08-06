package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"w3authproxy"
	"w3authproxy/pkg/ldap"
	"w3authproxy/pkg/login"
	"w3authproxy/pkg/pwdfile"
	"w3authproxy/pkg/server"

	"github.com/terefang/gommons/pkg/subcmd"
)

func init() {
	subcmd.Register(&SvcCommand{})
}

type SvcCommand struct {
	hostAddr        string
	prefix          string
	sessionLifetime int
	localuser       string
	localpass       string
	allowAnyUser    bool
	htpasswd        string
	apikeyfile      string
	jwtkeyfile      string
	jwtmethod       string
	ldapcfg         string
	ldaptest        bool
	httpUserHeader  string
	httpRolesHeader string
	templateOverlay string
	redirect        bool
}

func (r *SvcCommand) Arguments(f *flag.FlagSet) {
	f.StringVar(&r.hostAddr, "hostAddr", ":5555", "listen address and port")
	f.StringVar(&r.prefix, "prefix", "/other", "path prefix")
	f.IntVar(&r.sessionLifetime, "sessionAge", 7200, "session lifetime")

	f.StringVar(&r.localuser, "localuser", "*", "local user")
	f.StringVar(&r.localpass, "localpass", "*", "local user password")

	f.BoolVar(&r.redirect, "redirect", false, "redirect with 3xx instead of deny with 4xx")
	f.BoolVar(&r.allowAnyUser, "allowAnyUser", true, "allow '*' to match any username (use with care)")
	f.StringVar(&r.htpasswd, "htpasswd", "/path/to/.htpasswd", "local user password file (.htpasswd style)")

	f.StringVar(&r.apikeyfile, "apikeys", "/path/to/.htpasswd", "api-keys file (.htpasswd style)")

	f.StringVar(&r.jwtkeyfile, "jwtkeys", "", "jwt-keys file, enables jwt authentication")
	f.StringVar(&r.jwtmethod, "jwtmethod", "", "jwt authentication (Bearer, JWT)")

	//f.StringVar(&r.ldapcfg,"ldapconfig", "/path/to/ldap.hcl", "ldap access config (.hcl style)")
	f.StringVar(&r.ldapcfg, "ldapconfig", "/u/fredo/GolandProjects/w3authproxy/test.ldap.hcl", "ldap access config (.hcl style)")
	f.BoolVar(&r.ldaptest, "ldaptest", false, "test ldap connectivity")

	f.StringVar(&r.httpUserHeader, "httpUserHeader", "X-Auth-Portal-User", "HTTP user header")
	f.StringVar(&r.httpRolesHeader, "httpRolesHeader", "X-Auth-Portal-Roles", "HTTP roles header")

	f.StringVar(&r.templateOverlay, "templateOverlay", "/path/to/templates", "use template directory overlay")
}

func (r SvcCommand) Info() (string, string) {
	return "server", `runs the server`
}

func (r *SvcCommand) Execute(args []string) int {
	fmt.Println(w3authproxy.VersionInfo)
	_hsc := server.NewHttpServerContext()
	//basic init
	_hsc.Init()
	//set config
	_hsc.SetPathPrefix(r.prefix)
	_hsc.SetSessionLifetime(r.sessionLifetime)
	_hsc.SetAuthUserHeader(r.httpUserHeader)
	_hsc.SetAuthRolesHeader(r.httpRolesHeader)
	// local user
	if (r.localuser)[0] != '*' {
		_ld := login.NewSimpleLoginContext("local", r.localuser, r.localpass)
		_hsc.AddLoginDomain(_ld)
	}
	// jwt
	if r.jwtkeyfile != "" {
		if r.jwtmethod != "" {
			_hsc.SetJwtMethod(r.jwtmethod)
		} else {
			_hsc.SetJwtMethod(pwdfile.BEARER_AUTH_USER)
		}
		log.Printf("Reading jwtkeys from %s", r.jwtkeyfile)
		_htp := pwdfile.NewJwtLoginContext("jwtkeys")
		_htp.ReadFromKeyFile(r.jwtkeyfile)
		_hsc.AddLoginDomain(_htp)
	}
	// apikeys
	_fi, _err := os.Stat(r.apikeyfile)
	if (_err == nil) && (_fi.Size() > 0) {
		log.Printf("Reading apikeys from %s", r.apikeyfile)
		_htp := pwdfile.NewApiKeyLoginContext("apikeys")
		_htp.ReadFromHtpasswd(r.apikeyfile)
		_hsc.AddLoginDomain(_htp)
	}
	// htpasswd
	_fi, _err = os.Stat(r.htpasswd)
	if (_err == nil) && (_fi.Size() > 0) {
		log.Printf("Reading users from %s", r.htpasswd)
		_htp := pwdfile.NewGenericFileLoginContext("htpasswd")
		_htp.ReadFromHtpasswd(r.htpasswd, r.allowAnyUser)
		_hsc.AddLoginDomain(_htp)
	}
	// ldap
	_fi, _err = os.Stat(r.ldapcfg)
	if (_err == nil) && (_fi.Size() > 0) {
		log.Printf("Adding ldap authenticator from %s", r.ldapcfg)
		_lp, _err := ldap.NewLdapLoginContext("ldap", r.ldapcfg, r.ldaptest)
		if _err != nil {
			panic(_err)
		}
		_hsc.AddLoginDomain(_lp)
	}
	// template dir
	_fi, _err = os.Stat(r.templateOverlay)
	if (_err == nil) && _fi.IsDir() {
		log.Printf("Adding templates from %s", r.templateOverlay)
		_hsc.SetTemplateOverlay(r.templateOverlay)
	}
	_hsc.SetDoRedirect(r.redirect)
	//set handlers
	_hsc.RegisterHandlers()
	//serve
	log.Printf("Starting services at %s", r.hostAddr)
	_hsc.RunAndServe(r.hostAddr)
	return 0
}
