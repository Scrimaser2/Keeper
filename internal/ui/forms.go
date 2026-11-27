package ui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"photovault/internal/vault"
)

func newCreateForm(window fyne.Window, storage CreateStorage) fyne.CanvasObject {
	source, destination := "", ""
	key := widget.NewPasswordEntry()
	key.SetPlaceHolder("Ключ доступа")
	clearSource := widget.NewCheck("Удалить исходные файлы после добавления", nil)
	status := widget.NewLabel("")

	return container.NewVBox(
		widget.NewLabelWithStyle("Создать хранилище", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		folderField(window, "Папка с исходными файлами", &source, status),
		folderField(window, "Сохранить в", &destination, status),
		widget.NewLabel("Ключ доступа"), key, clearSource,
		widget.NewButtonWithIcon("Создать", theme.DocumentSaveIcon(), func() {
			if source == "" || destination == "" {
				status.SetText("Сначала выберите обе папки")
				return
			}
			status.SetText("Выполняется…")
			result, err := storage.Create(vault.CreateOptions{
				Source: source, Destination: destination, Key: key.Text, ClearSource: clearSource.Checked,
			})
			if err != nil {
				status.SetText("Не удалось создать хранилище: " + err.Error())
				return
			}
			status.SetText(createSummary(result, clearSource.Checked))
		}), status,
	)
}

func newRestoreForm(window fyne.Window, storage RestoreStorage) fyne.CanvasObject {
	collection, destination := "", ""
	key := widget.NewPasswordEntry()
	key.SetPlaceHolder("Ключ доступа")
	status := widget.NewLabel("")
	collectionLabel := widget.NewLabel("Не выбрано")
	chooseCollection := widget.NewButton("Выбрать файл", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				status.SetText("Не удалось выбрать файл: " + err.Error())
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			collection = reader.URI().Path()
			collectionLabel.SetText(reader.URI().Name())
		}, window)
	})

	return container.NewVBox(
		widget.NewLabelWithStyle("Восстановить хранилище", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Файл хранилища"), container.NewHBox(chooseCollection, collectionLabel),
		folderField(window, "Сохранить в", &destination, status),
		widget.NewLabel("Ключ доступа"), key,
		widget.NewButtonWithIcon("Восстановить", theme.FolderOpenIcon(), func() {
			if collection == "" || destination == "" {
				status.SetText("Сначала выберите файл и папку назначения")
				return
			}
			dialog.ShowConfirm("Восстановить файлы", "Файлы с такими именами в папке назначения будут заменены.", func(confirmed bool) {
				if !confirmed {
					return
				}
				status.SetText("Выполняется…")
				err := storage.Restore(vault.RestoreOptions{Collection: collection, Destination: destination, Key: key.Text})
				if err != nil {
					status.SetText("Не удалось восстановить хранилище: " + err.Error())
					return
				}
				status.SetText("Хранилище успешно восстановлено")
			}, window)
		}), status,
	)
}

func folderField(window fyne.Window, title string, selected *string, status *widget.Label) fyne.CanvasObject {
	value := widget.NewLabel("Не выбрано")
	pick := widget.NewButton("Выбрать папку", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				status.SetText("Не удалось выбрать папку: " + err.Error())
				return
			}
			if uri == nil {
				return
			}
			*selected = uri.Path()
			value.SetText(uri.Name())
		}, window)
	})
	return container.NewVBox(widget.NewLabel(title), container.NewHBox(pick, value))
}

func createSummary(result vault.CreateResult, cleared bool) string {
	message := "Хранилище успешно создано"
	if result.DuplicateFiles > 0 {
		message += fmt.Sprintf(". Пропущено дубликатов: %d", result.DuplicateFiles)
	}
	if result.SkippedSymlinks > 0 {
		message += fmt.Sprintf(". Пропущено символических ссылок: %d", result.SkippedSymlinks)
	}
	if result.SkippedHiddenFiles > 0 {
		message += fmt.Sprintf(". Пропущено скрытых файлов: %d", result.SkippedHiddenFiles)
	}
	if cleared {
		message += fmt.Sprintf(". Удалено исходных файлов: %d", result.ClearedFiles)
	}
	return message
}
