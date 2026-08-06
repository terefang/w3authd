package main

import (
	"os"

	"github.com/terefang/gommons/pkg/subcmd"
)

func main() {
	exitcode := subcmd.Execute()
	os.Exit(exitcode)
}
