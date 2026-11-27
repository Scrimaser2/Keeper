package ui

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

type operationTemplate struct {
	compiled *template.Template
}

func loadSimulatedOperations() ([]*operationTemplate, error) {
	path, err := findOperationsFile()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read simulated operations from %s: %w", path, err)
	}
	var definitions []string
	if err := json.Unmarshal(data, &definitions); err != nil {
		return nil, fmt.Errorf("parse simulated operations from %s: %w", path, err)
	}
	if len(definitions) != 30 {
		return nil, fmt.Errorf("expected 30 simulated operations in %s, got %d", path, len(definitions))
	}

	functions := template.FuncMap{
		"num": func(minimum, maximum int) int {
			return minimum + rand.Intn(maximum-minimum+1)
		},
		"hex": func(width int) string {
			if width < 1 {
				width = 1
			}
			if width > 8 {
				width = 8
			}
			value := rand.Uint32()
			if width < 8 {
				value &= uint32(1<<(width*4)) - 1
			}
			return fmt.Sprintf("%0*X", width, value)
		},
		"pick": func(options ...string) string {
			if len(options) == 0 {
				return ""
			}
			return options[rand.Intn(len(options))]
		},
	}
	operations := make([]*operationTemplate, 0, len(definitions))
	for index, definition := range definitions {
		compiled, err := template.New(fmt.Sprintf("operation-%02d", index+1)).Funcs(functions).Parse(definition)
		if err != nil {
			return nil, fmt.Errorf("parse simulated operation %d: %w", index+1, err)
		}
		operations = append(operations, &operationTemplate{compiled: compiled})
	}
	return operations, nil
}

func findOperationsFile() (string, error) {
	candidates := make([]string, 0, 4)
	if executable, err := os.Executable(); err == nil {
		contents := filepath.Dir(filepath.Dir(executable))
		candidates = append(candidates, filepath.Join(contents, "Resources", "operations.json"))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(workingDirectory, "internal", "ui", "operations.json"),
			filepath.Join(workingDirectory, "operations.json"),
		)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("operations.json was not found beside the application or in the current project")
}

func simulatedOperation(operations []*operationTemplate, now time.Time) string {
	if len(operations) == 0 {
		return now.Format("15:04:05.000") + "  EVENT state=active"
	}
	selected := operations[rand.Intn(len(operations))]
	var line strings.Builder
	if err := selected.compiled.Execute(&line, map[string]string{"Time": now.Format("15:04:05.000")}); err != nil {
		return now.Format("15:04:05.000") + "  EVENT state=active"
	}
	return line.String()
}
