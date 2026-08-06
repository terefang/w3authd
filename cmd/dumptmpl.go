package main

import (
	"w3authproxy/pkg/server"

	"github.com/terefang/gommons/pkg/subcmd"
	"modernc.org/fileutil"
)

type DumpCommand struct {
	subcmd.NoFlags
}

func init() {
	subcmd.Register(&DumpCommand{})
}

func (r DumpCommand) Info() (string, string) {
	return "dump-templates", "export internal templates to given directory"
}

func (r DumpCommand) Execute(args []string) int {
	if len(args) == 1 {
		_, _, _err := fileutil.CopyDir(server.StaticFiles, args[0], ".", nil)
		if _err != nil {
			panic(_err)
		}
	}
	return 0
}
