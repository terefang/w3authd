package main

import (
	"fmt"
	"w3authproxy"

	"github.com/terefang/gommons/pkg/subcmd"
)

type ManualCommand struct {
	subcmd.NoFlags
}

func (r ManualCommand) Info() (string, string) {
	return "manual", "print manual"
}

func (r ManualCommand) Execute(args []string) int {
	fmt.Println(w3authproxy.ManualText)
	return 0
}

func init() {
	subcmd.Register(&ManualCommand{})
}
