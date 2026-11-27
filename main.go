package main

import (
	"fmt"
	"os"

	"photovault/internal/buildinfo"
	"photovault/internal/cli"
	"photovault/internal/ui"
	"photovault/internal/vault"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("Library %s\n", buildinfo.Version)
		return
	}
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
