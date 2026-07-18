package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"w3authproxy/pkg/ldap"
	"w3authproxy/pkg/login"
	"w3authproxy/pkg/pwdfile"
	"w3authproxy/pkg/server"

	"modernc.org/fileutil"
)

func main() {
	hostAddr := flag.String("hostAddr", ":5555", "listen address and port")
	prefix := flag.String("prefix", "/other", "path prefix")
	sessionLifetime := flag.Int("sessionAge", 7200, "session lifetime")

	doCrypt6 := flag.Bool("crypt", false, "crypt $6$ password")
	doApr1 := flag.Bool("apr1", false, "crypt $apr1$ password")

	localuser := flag.String("localuser", "*", "local user")
	localpass := flag.String("localpasss", "*", "local user password")

	allowAnyUser := flag.Bool("allowAnyUser", true, "allow '*' to match any username (use with care)")
	htpasswd := flag.String("htpasswd", "/path/to/.htpasswd", "local user password file (.htpasswd style)")

	//ldapcfg := flag.String("ldapconfig", "/path/to/ldap.hcl", "ldap access config (.hcl style)")
	ldapcfg := flag.String("ldapconfig", "/u/fredo/GolandProjects/w3authproxy/test.ldap.hcl", "ldap access config (.hcl style)")
	ldaptest := flag.Bool("ldaptest", false, "test ldap connectivity")

	httpUserHeader := flag.String("httpUserHeader", "X-Auth-Portal-User", "HTTP user header")
	httpRolesHeader := flag.String("httpRolesHeader", "X-Auth-Portal-Roles", "HTTP roles header")

	templateOverlay := flag.String("templateOverlay", "/path/to/templates", "use template directory overlay")
	dumpTemplates := flag.String("dumpTemplates", "", "dump embedded templates to directory")
	flag.Parse()

	if *doCrypt6 {
		fmt.Println(pwdfile.Crypt6Credential(flag.Arg(0)))
	} else if *doApr1 {
		fmt.Println(pwdfile.CryptApr1Credential(flag.Arg(0)))
	} else if *dumpTemplates != "" {
		_, _, _err := fileutil.CopyDir(server.StaticFiles, *dumpTemplates, ".", nil)
		if _err != nil {
			panic(_err)
		}
	} else {
		_hsc := server.NewHttpServerContext()
		//basic init
		_hsc.Init()
		//set config
		_hsc.SetPathPrefix(*prefix)
		_hsc.SetSessionLifetime(*sessionLifetime)
		_hsc.SetAuthUserHeader(*httpUserHeader)
		_hsc.SetAuthRolesHeader(*httpRolesHeader)
		// local user
		if (*localuser)[0] != '*' {
			_ld := login.NewSimpleLoginContext("local", *localuser, *localpass)
			_hsc.AddLoginDomain(_ld)
		}
		// htpasswd
		_fi, _err := os.Stat(*htpasswd)
		if (_err == nil) && (_fi.Size() > 0) {
			log.Printf("Reading users from %s", *htpasswd)
			_htp := pwdfile.NewGenericFileLoginContext("htpasswd")
			_htp.ReadFromHtpasswd(*htpasswd, *allowAnyUser)
			_hsc.AddLoginDomain(_htp)
		}
		// ldap
		_fi, _err = os.Stat(*ldapcfg)
		if (_err == nil) && (_fi.Size() > 0) {
			log.Printf("Adding ldap authenticator from %s", *ldapcfg)
			_lp, _err := ldap.NewLdapLoginContext("ldap", *ldapcfg, *ldaptest)
			if _err != nil {
				panic(_err)
			}
			_hsc.AddLoginDomain(_lp)
		}
		// template dir
		_fi, _err = os.Stat(*templateOverlay)
		if (_err == nil) && _fi.IsDir() {
			log.Printf("Adding templates from %s", *templateOverlay)
			_hsc.SetTemplateOverlay(*templateOverlay)
		}
		//set handlers
		_hsc.RegisterHandlers()
		//serve
		log.Printf("Starting services at %s", *hostAddr)
		_hsc.RunAndServe(*hostAddr)
	}
}
