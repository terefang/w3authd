package main

import (
	"fmt"
	"w3authproxy"

	"github.com/terefang/gommons/pkg/subcmd"
)

type VersionCommand struct {
	subcmd.NoFlags
}

func (r VersionCommand) Info() (string, string) {
	return "version", "print version info"
}

func (r VersionCommand) Execute(args []string) int {
	fmt.Println(w3authproxy.VersionInfo)
	return 0
}

func init() {
	subcmd.Register(&VersionCommand{})
}
