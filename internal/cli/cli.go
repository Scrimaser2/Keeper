package cli

import (
	"errors"
	"fmt"
	"strings"

	"photovault/internal/vault"
)

type command struct {
	kind, input, output, key string
}

func Run(args []string, service vault.Service) error {
	cmd, err := parse(args)
	if err != nil {
		return err
	}
	switch cmd.kind {
	case "encrypt":
		_, err = service.Create(vault.CreateOptions{Source: cmd.input, Destination: cmd.output, Key: cmd.key})
	case "decrypt":
		err = service.Restore(vault.RestoreOptions{Collection: cmd.input, Destination: cmd.output, Key: cmd.key})
	}
	return err
}

func parse(args []string) (command, error) {
	var cmd command
	seen := make(map[string]bool)
	for _, argument := range args {
		key, value, ok := strings.Cut(argument, "=")
		if !ok {
			return cmd, fmt.Errorf("expected key=value argument, got %q", argument)
		}
		if seen[key] {
			return cmd, fmt.Errorf("duplicate parameter %q", key)
		}
		seen[key] = true
		switch key {
		case "type":
			cmd.kind = value
		case "in":
			cmd.input = value
		case "out":
			cmd.output = value
		case "key":
			cmd.key = value
		default:
			return cmd, fmt.Errorf("unknown parameter %q", key)
		}
	}
	if cmd.kind != "encrypt" && cmd.kind != "decrypt" {
		return cmd, errors.New("type must be encrypt or decrypt")
	}
	if cmd.input == "" || cmd.output == "" {
		return cmd, errors.New("in and out are required")
	}
	if !seen["key"] {
		return cmd, errors.New("key is required (an empty key is allowed, but is not recommended)")
	}
	return cmd, nil
}
