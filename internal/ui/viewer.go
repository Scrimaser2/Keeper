package ui

import (
	"fmt"
	"image"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type contextMenuCard struct {
	widget.BaseWidget
	content     fyne.CanvasObject
	onSecondary func(*fyne.PointEvent)
}

func newContextMenuCard(content fyne.CanvasObject, onSecondary func(*fyne.PointEvent)) *contextMenuCard {
	card := &contextMenuCard{content: content, onSecondary: onSecondary}
	card.ExtendBaseWidget(card)
	return card
}

func (card *contextMenuCard) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(card.content)
}

func (card *contextMenuCard) TappedSecondary(event *fyne.PointEvent) {
	card.onSecondary(event)
}

func showTextContent(parent fyne.Window, title, text string) {
	content := widget.NewMultiLineEntry()
	content.Wrapping = fyne.TextWrapWord
	content.SetText(text)
	content.Disable()
	dialogWindow := dialog.NewCustom(title, "Закрыть", container.NewScroll(content), parent)
	dialogWindow.Resize(fyne.NewSize(900, 680))
	dialogWindow.Show()
}

func showPhoto(parent fyne.Window, photos []libraryItem, current int, loadPhoto func(string) (image.Image, error), deleteItem func(string) error, onClosed func()) {
	if len(photos) == 0 || current < 0 || current >= len(photos) {
		return
	}
	viewer := fyne.CurrentApp().NewWindow(photos[current].name)
	prefetcher := newFullPhotoPrefetcher(loadPhoto)
	var viewerClosed atomic.Bool
	viewer.SetOnClosed(func() {
		viewerClosed.Store(true)
		done := prefetcher.close()
		if onClosed != nil {
			go func() {
				<-done
				onClosed()
			}()
		}
	})
	position := widget.NewLabel("")
	var showCurrent func()
	previous := widget.NewButton("Назад", func() {
		if current > 0 {
			current--
			showCurrent()
		}
	})
	next := widget.NewButton("Вперёд", func() {
		if current+1 < len(photos) {
			current++
			showCurrent()
		}
	})
	close := widget.NewButton("Закрыть просмотр", viewer.Close)
	remove := widget.NewButtonWithIcon("Удалить", theme.DeleteIcon(), func() {
		name := photos[current].name
		dialog.ShowConfirm("Удалить элемент", "Безвозвратно удалить его из хранилища?", func(confirmed bool) {
			if !confirmed {
				return
			}
			if err := deleteItem(name); err != nil {
				dialog.ShowError(err, viewer)
				return
			}
			viewer.Close()
		}, viewer)
	})
	showCurrent = func() {
		photo := photos[current]
		photoIndex := current
		viewer.SetTitle(photo.name)
		position.SetText(fmt.Sprintf("%d / %d", current+1, len(photos)))
		previous.Enable()
		next.Enable()
		if current == 0 {
			previous.Disable()
		}
		if current == len(photos)-1 {
			next.Disable()
		}
		controls := container.NewHBox(previous, position, next, layout.NewSpacer(), remove, close)
		viewer.SetContent(container.NewBorder(nil, controls, nil, nil, container.NewCenter(widget.NewLabel("Загружаю изображение…"))))
		prefetcher.request(photo.name, func(fullSize image.Image, err error) {
			fyne.Do(func() {
				if current != photoIndex || viewerClosed.Load() {
					return
				}
				if err != nil {
					viewer.SetContent(container.NewBorder(nil, controls, nil, nil, container.NewCenter(widget.NewLabel("Предпросмотр недоступен"))))
					dialog.ShowError(fmt.Errorf("не удалось открыть элемент: %w", err), viewer)
					return
				}
				preview := canvas.NewImageFromImage(fullSize)
				preview.FillMode = canvas.ImageFillContain
				viewer.SetContent(container.NewBorder(nil, controls, nil, nil, preview))
			})
		})
		prefetcher.setWindow(photos, current)
	}
	viewer.Canvas().SetOnTypedKey(func(event *fyne.KeyEvent) {
		switch event.Name {
		case fyne.KeyEscape:
			viewer.Close()
		case fyne.KeyLeft:
			if current > 0 {
				current--
				showCurrent()
			}
		case fyne.KeyRight:
			if current+1 < len(photos) {
				current++
				showCurrent()
			}
		}
	})
	showCurrent()
	viewer.SetFullScreen(true)
	viewer.Show()
}
