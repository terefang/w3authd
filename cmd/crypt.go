package main

import (
	"flag"
	"fmt"
	"w3authproxy/pkg/pwdfile"

	"github.com/skip2/go-qrcode"
	"github.com/terefang/gommons/pkg/xcrypt"

	"github.com/terefang/gommons/pkg/subcmd"
	"github.com/terefang/gommons/pkg/xtui"
)

type CryptCommand struct {
	doCrypt6 bool
	doApr1   bool
	doPrompt bool
	password string
	doTotp   bool
	doQrcode bool
}

func (r *CryptCommand) Arguments(f *flag.FlagSet) {
	f.BoolVar(&r.doCrypt6, "crypt6", false, "crypt $6$ password")
	f.BoolVar(&r.doApr1, "apr1", false, "crypt $apr1$ password")
	f.BoolVar(&r.doTotp, "totp", false, "generate totp fob")
	f.BoolVar(&r.doQrcode, "qrcode", false, "print qrcode for fob")
	f.StringVar(&r.password, "password", "", "dont generate password but use the one given")
	f.BoolVar(&r.doPrompt, "prompt", false, "prompt for a given password, more secure")
}

func (r CryptCommand) Info() (string, string) {
	return "crypt", "crypt a password"
}

func (r CryptCommand) Execute(args []string) int {

	if r.doPrompt {
		_pass, _err := xtui.ReadSecretVerifyString("Enter Password: ", "Re-Enter Password: ")
		if _err != nil {
			panic(_err)
		}
		r.password = _pass
	}

	if r.password == "" {
		r.password = xcrypt.GeneratePasswordWithSym(xcrypt.PasswordSymbolSetExtensive, 32)
		fmt.Printf("%s\n", r.password)
	}

	if r.doTotp {
		r.password = xcrypt.GeneratePasswordWithKdfSymLevel(r.password, xcrypt.PasswordSymbolSetExtensive, 32, 10)
		fmt.Println(pwdfile.TotpCredential(r.password))
		if r.doQrcode {
			_uri, err := pwdfile.TotpCredentialUrl(r.password)
			if err != nil {
				panic(err)
			}
			_qr, err := qrcode.New(_uri, qrcode.Low)
			if err != nil {
				panic(err)
			}
			fmt.Println(_qr.ToString(false))
		}
	} else if r.doCrypt6 {
		fmt.Println(pwdfile.Crypt6Credential(r.password))
	} else if r.doApr1 {
		fmt.Println(pwdfile.CryptApr1Credential(r.password))
	} else {
		fmt.Println(pwdfile.Crypt1Credential(r.password))
	}
	return 0
}

func init() {
	subcmd.Register(&CryptCommand{})
}
