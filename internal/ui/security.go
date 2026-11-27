package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func newSecurityForm(window fyne.Window, storage SecurityStorage) fyne.CanvasObject {
	collection := ""
	pathLabel := widget.NewLabel("Не выбрано")
	currentPassword := widget.NewPasswordEntry()
	currentPassword.SetPlaceHolder("Текущий ключ доступа")
	newPassword := widget.NewPasswordEntry()
	newPassword.SetPlaceHolder("Новый ключ доступа")
	confirmPassword := widget.NewPasswordEntry()
	confirmPassword.SetPlaceHolder("Повторите новый ключ")
	status := widget.NewLabel("Операции проверки и ротации могут занять время на больших хранилищах")
	status.Wrapping = fyne.TextWrapWord

	choose := widget.NewButtonWithIcon("Выбрать хранилище", theme.FolderOpenIcon(), func() {
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
			pathLabel.SetText(reader.URI().Name())
		}, window)
	})

	run := func(message string, operation func(string) error, onSuccess func()) {
		if collection == "" {
			status.SetText("Сначала выберите файл хранилища")
			return
		}
		path := collection
		status.SetText(message)
		go func() {
			err := operation(path)
			fyne.Do(func() {
				if err != nil {
					status.SetText("Операция не выполнена: " + err.Error())
					return
				}
				if onSuccess != nil {
					onSuccess()
				}
				status.SetText("Операция успешно завершена")
			})
		}()
	}

	changePassword := widget.NewButton("Сменить пароль", func() {
		if newPassword.Text == "" || newPassword.Text != confirmPassword.Text {
			status.SetText("Введите новый пароль одинаково в обоих полях")
			return
		}
		password, replacement := currentPassword.Text, newPassword.Text
		run("Обновляю оболочку ключа…", func(path string) error {
			return storage.ChangePassword(path, password, replacement)
		}, func() {
			currentPassword.SetText(replacement)
			newPassword.SetText("")
			confirmPassword.SetText("")
		})
	})
	rotateKey := widget.NewButtonWithIcon("Выполнить полную ротацию DEK", theme.ViewRefreshIcon(), func() {
		password := currentPassword.Text
		dialog.ShowConfirm("Полная ротация ключа данных", "Все активные файлы будут расшифрованы и зашифрованы заново. Операция может занять много времени.", func(confirmed bool) {
			if confirmed {
				run("Перешифровываю данные новым DEK…", func(path string) error { return storage.RotateDataKey(path, password) }, nil)
			}
		}, window)
	})
	verify := widget.NewButton("Проверить целостность файлов", func() {
		password := currentPassword.Text
		run("Проверяю все активные файлы…", func(path string) error { return storage.Verify(path, password) }, nil)
	})
	compact := widget.NewButton("Уплотнить хранилище", func() {
		password := currentPassword.Text
		dialog.ShowConfirm("Уплотнить хранилище", "Будет создана компактная копия только с активными файлами.", func(confirmed bool) {
			if confirmed {
				run("Уплотняю хранилище…", func(path string) error { return storage.Compact(path, password) }, nil)
			}
		}, window)
	})
	status.TextStyle = fyne.TextStyle{Italic: true}
	return container.NewVBox(
		widget.NewLabelWithStyle("Безопасность и обслуживание", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(choose, pathLabel),
		widget.NewLabel("Текущий пароль"), currentPassword,
		widget.NewSeparator(),
		widget.NewLabel("Смена пароля перепаковывает DEK, не перешифровывая файлы."),
		widget.NewLabel("Полная ротация создаёт новый DEK и перешифровывает активные файлы."),
		newPassword, confirmPassword,
		changePassword, rotateKey,
		widget.NewSeparator(), verify, compact,
		status,
	)
}
