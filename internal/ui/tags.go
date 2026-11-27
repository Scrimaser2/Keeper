package ui

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"photovault/internal/vault"
)

const maxTagImageBytes = 256 << 10

type tagManager struct {
	owner  *Library
	list   *fyne.Container
	status *widget.Label
}

func newTagManager(owner *Library) *tagManager {
	return &tagManager{owner: owner, list: container.NewVBox(), status: widget.NewLabel("Откройте хранилище, чтобы управлять метками")}
}

func (manager *tagManager) build() fyne.CanvasObject {
	header := container.NewHBox(
		widget.NewLabelWithStyle("Метки", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewButtonWithIcon("Создать метку", theme.ContentAddIcon(), func() { manager.openEditor(nil) }),
	)
	return container.NewBorder(container.NewPadded(header), manager.status, nil, nil, container.NewPadded(container.NewVScroll(manager.list)))
}

func (manager *tagManager) refresh(tags []vault.Tag) {
	manager.list.Objects = nil
	if manager.owner.session == nil {
		manager.status.SetText("Откройте хранилище во вкладке «Библиотека»")
		manager.list.Add(widget.NewLabel("Метки появятся после открытия хранилища"))
		manager.list.Refresh()
		return
	}
	manager.status.SetText(fmt.Sprintf("Метки: %d", len(tags)))
	if len(tags) == 0 {
		manager.list.Add(widget.NewLabel("Пока нет меток. Создайте первую метку."))
	}
	for _, tag := range tags {
		manager.list.Add(manager.tagRow(tag))
	}
	manager.list.Refresh()
}

func (manager *tagManager) tagRow(tag vault.Tag) fyne.CanvasObject {
	swatch := canvas.NewRectangle(tagColor(tag.Color))
	swatchContainer := container.NewGridWrap(fyne.NewSize(34, 34), swatch)
	imageObject := tagImageObject(tag.Image)
	if imageObject == nil {
		imageObject = widget.NewLabel("")
	}
	icon := container.NewGridWrap(fyne.NewSize(34, 34), imageObject)
	name := widget.NewLabelWithStyle(tag.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	row := container.NewBorder(nil, widget.NewSeparator(), nil,
		container.NewHBox(widget.NewButton("Изменить", func() { copy := tag; manager.openEditor(&copy) }), widget.NewButton("Удалить", func() { manager.delete(tag) })),
		container.NewHBox(swatchContainer, icon, name))
	return container.NewPadded(row)
}

func (manager *tagManager) openEditor(existing *vault.Tag) {
	if manager.owner.session == nil {
		dialog.ShowInformation("Метки", "Сначала откройте хранилище во вкладке «Библиотека».", manager.owner.window)
		return
	}
	var initial vault.Tag
	if existing != nil {
		initial = *existing
		initial.Image = append([]byte(nil), existing.Image...)
	}
	name := widget.NewEntry()
	name.SetPlaceHolder("Например, Важное")
	name.SetText(initial.Name)
	colorEntry := widget.NewEntry()
	colorEntry.SetPlaceHolder("#RRGGBB")
	colorEntry.SetText(initial.Color)
	swatch := canvas.NewRectangle(tagColor(initial.Color))
	colorEntry.OnChanged = func(value string) { swatch.FillColor = tagColor(value); swatch.Refresh() }
	imageStatus := widget.NewLabel(imageStatusText(initial.Image))
	imageBytes := append([]byte(nil), initial.Image...)
	chooseImage := widget.NewButton("Выбрать изображение…", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, manager.owner.window)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			data, err := io.ReadAll(io.LimitReader(reader, maxTagImageBytes+1))
			if err != nil {
				dialog.ShowError(err, manager.owner.window)
				return
			}
			if len(data) > maxTagImageBytes {
				dialog.ShowError(fmt.Errorf("изображение должно быть не больше 256 КБ"), manager.owner.window)
				return
			}
			config, _, err := image.DecodeConfig(bytes.NewReader(data))
			if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 512 || config.Height > 512 {
				dialog.ShowInformation("Изображение метки", "Выберите изображение размером до 512 × 512 пикселей в формате PNG, JPEG или GIF.", manager.owner.window)
				return
			}
			imageBytes = data
			imageStatus.SetText(reader.URI().Name())
		}, manager.owner.window)
	})
	clearImage := widget.NewButton("Убрать изображение", func() { imageBytes = nil; imageStatus.SetText("Изображение не выбрано") })
	content := container.NewVBox(
		widget.NewLabel("Название"), name,
		widget.NewLabel("Цвет · шестнадцатеричный код"), container.NewHBox(container.NewGridWrap(fyne.NewSize(34, 34), swatch), colorEntry),
		widget.NewLabel("Изображение · до 512 × 512 пикселей и 256 КБ"), imageStatus,
		container.NewHBox(chooseImage, clearImage),
	)
	modal := dialog.NewCustom("Метка", "Отмена", content, manager.owner.window)
	content.Add(widget.NewButtonWithIcon("Сохранить", theme.DocumentSaveIcon(), func() {
		updated := vault.Tag{ID: initial.ID, Name: strings.TrimSpace(name.Text), Color: strings.TrimSpace(colorEntry.Text), Image: append([]byte(nil), imageBytes...)}
		if updated.Name == "" {
			dialog.ShowInformation("Метка", "Введите название метки.", manager.owner.window)
			return
		}
		saved, err := manager.owner.storage.SaveTag(manager.owner.collection, manager.owner.keyValue, updated)
		if err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		if err := manager.owner.reloadSession(); err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		manager.owner.render()
		manager.status.SetText("Метка сохранена: " + saved.Name)
		modal.Hide()
	}))
	modal.Resize(fyne.NewSize(480, 380))
	modal.Show()
}

func (manager *tagManager) delete(tag vault.Tag) {
	dialog.ShowConfirm("Удалить метку", "Удалить метку «"+tag.Name+"» и все её связи с элементами?", func(ok bool) {
		if !ok {
			return
		}
		if err := manager.owner.storage.DeleteTag(manager.owner.collection, manager.owner.keyValue, tag.ID); err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		if err := manager.owner.reloadSession(); err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		manager.owner.render()
		manager.status.SetText("Метка удалена")
	}, manager.owner.window)
}

func (manager *tagManager) assignToItem(name string) {
	if manager.owner.session == nil {
		return
	}
	tags := manager.owner.session.Tags()
	if len(tags) == 0 {
		dialog.ShowInformation("Добавить метку", "Сначала создайте метку во вкладке «Метки».", manager.owner.window)
		return
	}
	options := make([]string, len(tags))
	byName := make(map[string]vault.Tag, len(tags))
	for i, tag := range tags {
		options[i] = tag.Name
		byName[tag.Name] = tag
	}
	selectTag := widget.NewSelect(options, nil)
	selectTag.SetSelected(options[0])
	preview := manager.tagPreview(byName[selectTag.Selected])
	selectTag.OnChanged = func(value string) {
		preview.Objects = []fyne.CanvasObject{manager.tagPreviewObject(byName[value])}
		preview.Refresh()
	}
	content := container.NewVBox(widget.NewLabel("Выберите метку для «"+name+"»"), selectTag, preview)
	dialog.ShowCustomConfirm("Добавить метку", "Прикрепить", "Отмена", content, func(ok bool) {
		if !ok {
			return
		}
		tag := byName[selectTag.Selected]
		if _, err := manager.owner.storage.AssignTag(manager.owner.collection, manager.owner.keyValue, tag.ID, []string{name}); err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		if err := manager.owner.reloadSession(); err != nil {
			dialog.ShowError(err, manager.owner.window)
			return
		}
		manager.owner.render()
		manager.owner.status.SetText("Метка прикреплена: " + tag.Name)
	}, manager.owner.window)
}

func (manager *tagManager) tagPreview(tag vault.Tag) *fyne.Container {
	return container.NewMax(manager.tagPreviewObject(tag))
}

func (manager *tagManager) tagPreviewObject(tag vault.Tag) fyne.CanvasObject {
	background := canvas.NewRectangle(tagColor(tag.Color))
	if icon := tagImageObject(tag.Image); icon != nil {
		return container.NewMax(background, container.NewPadded(icon))
	}
	return container.NewMax(background)
}

func tagImageObject(data []byte) fyne.CanvasObject {
	if len(data) == 0 {
		return nil
	}
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	icon := canvas.NewImageFromImage(decoded)
	icon.FillMode = canvas.ImageFillContain
	return icon
}

func imageStatusText(data []byte) string {
	if len(data) == 0 {
		return "Изображение не выбрано"
	}
	return "Изображение выбрано"
}

func tagColor(value string) color.Color {
	value = strings.TrimPrefix(strings.TrimSpace(value), "#")
	parsed, err := strconv.ParseUint(value, 16, 24)
	if err != nil || len(value) != 6 {
		return color.RGBA{R: 92, G: 103, B: 118, A: 255}
	}
	return color.RGBA{R: uint8(parsed >> 16), G: uint8(parsed >> 8), B: uint8(parsed), A: 255}
}
