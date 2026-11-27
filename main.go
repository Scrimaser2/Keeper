package main

import (
	"fmt"
	"os"

	"photovault/internal/cli"
	"photovault/internal/ui"
	"photovault/internal/vault"
)

func main() {
	service := vault.Service{}
	var err error
	if len(os.Args) == 1 || os.Args[1] == "type=gui" {
		err = ui.Run(service)
	} else {
		err = cli.Run(os.Args[1:], service)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
