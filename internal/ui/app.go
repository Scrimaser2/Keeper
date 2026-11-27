package ui

import (
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"photovault/internal/media"
)

func Run(storage Storage) error {
	operations, err := loadSimulatedOperations()
	if err != nil {
		return err
	}
	application := app.NewWithID("com.library.viewer")
	application.Settings().SetTheme(theme.DarkTheme())
	window := application.NewWindow("Библиотека")
	window.Resize(fyne.NewSize(1040, 720))

	library := NewLibrary(window, storage, media.Viewer{})
	tabs := container.NewAppTabs(
		container.NewTabItem("Библиотека", library.Build()),
		container.NewTabItem("Метки", library.BuildTags()),
		container.NewTabItem("Создать", container.NewPadded(newCreateForm(window, storage))),
		container.NewTabItem("Восстановить", container.NewPadded(newRestoreForm(window, storage))),
	)
	console, consoleOutput, consoleScroll := startupConsole()
	var sequence []rune
	codeRunes := []rune(strings.ToUpper(accessCodeFromEnvironment()))
	var lastKey time.Time
	opened := false
	stopOutput := make(chan struct{})
	deadline := time.AfterFunc(20*time.Second, func() {
		fyne.Do(func() {
			if !opened {
				window.Close()
			}
		})
	})
	acceptRune := func(char rune) {
		if opened || len(codeRunes) == 0 {
			return
		}
		now := time.Now()
		if !lastKey.IsZero() && now.Sub(lastKey) >= 3*time.Second {
			sequence = nil
		}
		lastKey = now
		char = unicode.ToUpper(char)
		if len(sequence) < len(codeRunes) && char == codeRunes[len(sequence)] {
			sequence = append(sequence, char)
		} else if char == codeRunes[0] {
			sequence = []rune{char}
		} else {
			sequence = nil
		}
		if len(sequence) == len(codeRunes) {
			opened = true
			deadline.Stop()
			close(stopOutput)
			window.Canvas().SetOnTypedRune(nil)
			window.Canvas().SetOnTypedKey(nil)
			window.Canvas().Focus(nil)
			window.SetTitle("Библиотека")
			window.SetContent(tabs)
		}
	}
	input := widget.NewPasswordEntry()
	input.OnChanged = func(value string) {
		input.SetText("")
		for _, char := range value {
			acceptRune(char)
			if opened {
				break
			}
		}
	}
	input.Resize(fyne.NewSize(1, 1))
	input.Move(fyne.NewPos(0, 0))
	window.SetContent(container.NewStack(console, container.NewWithoutLayout(input)))
	window.Canvas().SetOnTypedRune(acceptRune)
	window.Canvas().Focus(input)
	go streamConsoleOutput(consoleOutput, consoleScroll, operations, stopOutput)
	window.ShowAndRun()
	return nil
}

func startupConsole() (fyne.CanvasObject, *widget.Label, *container.Scroll) {
	output := widget.NewLabel("")
	output.TextStyle = fyne.TextStyle{Monospace: true}
	output.Wrapping = fyne.TextWrapOff
	output.SetText("SESSION   LOCAL NODE\n-----------------------------------------------\n")
	scroll := container.NewVScroll(output)
	view := container.NewBorder(
		container.NewVBox(widget.NewLabelWithStyle("Session", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true, Bold: true}), widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), widget.NewLabelWithStyle("> █", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})),
		nil, nil, container.NewPadded(scroll),
	)
	return view, output, scroll
}

func accessCodeFromEnvironment() string {
	if value := strings.TrimSpace(os.Getenv("LIBRARY_ACCESS_CODE")); value != "" {
		return value
	}
	if runtime.GOOS == "darwin" {
		if output, err := exec.Command("/bin/launchctl", "getenv", "LIBRARY_ACCESS_CODE").Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}

func streamConsoleOutput(output *widget.Label, scroll *container.Scroll, operations []*operationTemplate, stop <-chan struct{}) {
	content := output.Text
	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(120+rand.Intn(530)) * time.Millisecond):
			line := simulatedOperation(operations, time.Now())
			fyne.Do(func() {
				rows := append(strings.Split(content, "\n"), line)
				if len(rows) > 48 {
					rows = rows[len(rows)-48:]
				}
				content = strings.Join(rows, "\n")
				output.SetText(content)
				if scroll != nil {
					scroll.ScrollToBottom()
				}
			})
		}
	}
}
