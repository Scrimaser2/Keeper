package ui

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	_ "golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"

	"photovault/internal/catalog"
	"photovault/internal/media"
	"photovault/internal/vault"
)

const (
	maxPreviewPixels   int64 = 24_000_000
	maxThumbnailPixels int64 = 24_000_000
)

type libraryItem struct {
	name      string
	size      int64
	hash      string
	extension string
	category  catalog.Category
	tags      []string
}

type Library struct {
	window           fyne.Window
	storage          LibraryStorage
	mediaViewer      media.Viewer
	collection       string
	keyValue         string
	session          *vault.Session
	items            []libraryItem
	visible          []libraryItem
	selected         map[string]bool
	category         string
	extension        string
	query            string
	accessCode       *widget.Entry
	status           *widget.Label
	selectedCount    *widget.Label
	categorySelect   *widget.Select
	extensionSelect  *widget.Select
	searchEntry      *widget.Entry
	fileLabel        *widget.Label
	gallery          *widget.GridWrap
	emptyState       *fyne.Container
	emptyLabel       *widget.Label
	form             *fyne.Container
	tagManager       *tagManager
	thumbs           *thumbnailCache
	thumbnailLoader  *thumbnailLoader
	lastVisible      int
	previewReported  map[string]bool
	previewLoaded    int
	previewFailed    int
	previewLastError string
}

func NewLibrary(window fyne.Window, storage LibraryStorage, mediaViewer media.Viewer) *Library {
	return &Library{
		window:      window,
		storage:     storage,
		mediaViewer: mediaViewer,
		selected:    make(map[string]bool),
		category:    "Все категории",
		extension:   "Все расширения",
		lastVisible: -1,
	}
}

func (l *Library) Build() fyne.CanvasObject {
	l.status = widget.NewLabel("Выберите файл хранилища")
	l.status.Wrapping = fyne.TextWrapWord
	l.selectedCount = widget.NewLabel("Выбрано: 0")
	l.accessCode = widget.NewPasswordEntry()
	l.accessCode.SetPlaceHolder("Ключ доступа")
	l.fileLabel = widget.NewLabel("Файл не выбран")
	l.searchEntry = widget.NewEntry()
	l.searchEntry.SetPlaceHolder("Поиск по имени или метке")
	l.searchEntry.OnChanged = func(value string) {
		l.query = strings.ToLower(strings.TrimSpace(value))
		l.render()
	}
	l.gallery = widget.NewGridWrap(func() int { return len(l.visible) }, l.createCard, l.updateCard)
	l.thumbs = newThumbnailCache(thumbnailCacheLimit)
	l.emptyLabel = widget.NewLabel("")
	l.emptyState = container.NewCenter(l.emptyLabel)
	l.showEmpty("Элементы появятся здесь")

	l.categorySelect = widget.NewSelect([]string{"Все категории", string(catalog.Visual), string(catalog.Video), string(catalog.Text), string(catalog.Document), string(catalog.Other)}, func(value string) {
		l.category = value
		l.render()
	})
	l.categorySelect.SetSelected("Все категории")
	l.extensionSelect = widget.NewSelect([]string{"Все расширения"}, func(value string) {
		l.extension = value
		l.render()
	})
	l.extensionSelect.SetSelected("Все расширения")
	l.categorySelect.Disable()
	l.extensionSelect.Disable()

	chooseFile := widget.NewButtonWithIcon("Выбрать файл", theme.FolderOpenIcon(), l.chooseCollection)
	openCollection := widget.NewButtonWithIcon("Открыть хранилище", theme.FolderOpenIcon(), l.openCollection)
	l.form = container.NewVBox(
		widget.NewLabelWithStyle("Библиотека", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Файл хранилища"),
		container.NewHBox(chooseFile, l.fileLabel),
		l.accessCode,
		openCollection,
		l.searchEntry,
		container.NewHBox(widget.NewLabel("Категория"), l.categorySelect, widget.NewLabel("Формат"), l.extensionSelect),
		widget.NewLabel("Двойной щелчок — открыть · правый щелчок — действия"),
		l.status,
		widget.NewSeparator(),
	)
	return container.NewBorder(container.NewPadded(l.form), widget.NewLabel("Личное хранилище"), nil, nil, container.NewStack(l.gallery, l.emptyState))
}

func (l *Library) BuildTags() fyne.CanvasObject {
	l.tagManager = newTagManager(l)
	return l.tagManager.build()
}

func (l *Library) chooseCollection() {
	l.lock()
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			l.status.SetText("Не удалось выбрать файл: " + err.Error())
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()
		l.collection = reader.URI().Path()
		l.fileLabel.SetText(reader.URI().Name())
		l.status.SetText("Выбран файл: " + reader.URI().Name())
	}, l.window)
}

func (l *Library) openCollection() {
	l.lock()
	if l.collection == "" {
		l.status.SetText("Сначала выберите файл хранилища")
		return
	}
	l.status.SetText("Загружаю список элементов…")
	l.keyValue = l.accessCode.Text
	session, err := l.storage.OpenSession(l.collection, l.keyValue)
	if err != nil {
		l.status.SetText("Не удалось открыть файл. Проверьте ключ доступа: " + err.Error())
		return
	}
	l.installSession(session)
	l.refreshExtensions()
	l.categorySelect.Enable()
	l.extensionSelect.Enable()
	if l.tagManager != nil {
		l.tagManager.refresh(session.Tags())
	}
	l.form.Refresh()
	l.render()
	l.status.SetText(fmt.Sprintf("Элементов: %d · кэш предпросмотра: 96 МБ", len(l.items)))
}

func (l *Library) installSession(session *vault.Session) {
	l.session = session
	entries := session.Items()
	l.items = make([]libraryItem, 0, len(entries))
	for _, entry := range entries {
		if catalog.IsHiddenPath(entry.Name) {
			continue
		}
		l.items = append(l.items, libraryItem{
			name:      entry.Name,
			size:      entry.Size,
			hash:      entry.Hash,
			extension: catalog.Extension(entry.Name),
			category:  catalog.CategoryFor(entry.Name),
			tags:      append([]string(nil), entry.Tags...),
		})
	}
	sort.Slice(l.items, func(i, j int) bool { return l.items[i].name < l.items[j].name })
	l.selected = make(map[string]bool)
	l.selectedCount.SetText("Выбрано: 0")
	l.thumbs = newThumbnailCache(thumbnailCacheLimit)
	l.thumbnailLoader = newThumbnailLoader(session, l.thumbs, loadThumbnail)
	l.previewReported = make(map[string]bool)
	l.previewLoaded = 0
	l.previewFailed = 0
	l.previewLastError = ""
}

func (l *Library) loadFullPhoto(name string) (image.Image, error) {
	if l.session == nil {
		return nil, fmt.Errorf("collection is closed")
	}
	return decodeSessionImage(l.session, name, fyne.NewSize(100000, 100000), maxPreviewPixels)
}

func loadThumbnail(session *vault.Session, item libraryItem) (image.Image, error) {
	return decodeSessionImage(session, item.name, fyne.NewSize(320, 240), maxThumbnailPixels)
}

func decodeSessionImage(session *vault.Session, name string, maxSize fyne.Size, maxPixels int64) (image.Image, error) {
	configReader, err := session.Open(name)
	if err != nil {
		return nil, err
	}
	config, _, decodeErr := image.DecodeConfig(configReader)
	closeErr := configReader.Close()
	if decodeErr != nil {
		if !isNativeImageCandidate(session, name) {
			return nil, decodeErr
		}
		return decodeWithNativeImageIO(session, name, maxSize, maxPixels)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > maxPixels {
		return nil, fmt.Errorf("image dimensions exceed the preview memory limit")
	}
	imageReader, err := session.Open(name)
	if err != nil {
		return nil, err
	}
	source, _, decodeErr := image.Decode(imageReader)
	closeErr = imageReader.Close()
	if decodeErr != nil {
		return nil, decodeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	scale := min(float64(maxSize.Width)/float64(config.Width), float64(maxSize.Height)/float64(config.Height), 1)
	w := max(1, int(float64(config.Width)*scale))
	h := max(1, int(float64(config.Height)*scale))
	thumbnail := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(thumbnail, thumbnail.Bounds(), source, source.Bounds(), draw.Over, nil)
	return thumbnail, nil
}

func isNativeImageCandidate(session *vault.Session, name string) bool {
	reader, err := session.Open(name)
	if err != nil {
		return false
	}
	var signature [12]byte
	_, readErr := io.ReadFull(reader, signature[:])
	_ = reader.Close()
	if readErr != nil {
		return false
	}
	if string(signature[:3]) == "\xff\xd8\xff" || string(signature[:4]) == "\x89PNG" ||
		string(signature[:4]) == "GIF8" || string(signature[:2]) == "BM" ||
		string(signature[:4]) == "II*\x00" || string(signature[:4]) == "MM\x00*" ||
		(string(signature[:4]) == "RIFF" && string(signature[8:12]) == "WEBP") {
		return true
	}
	if string(signature[4:8]) != "ftyp" {
		return false
	}
	brand := string(signature[8:12])
	switch brand {
	case "heic", "heix", "hevc", "hevx", "mif1", "msf1", "avif", "avis":
		return true
	default:
		return false
	}
}

func decodeWithNativeImageIO(session *vault.Session, name string, maxSize fyne.Size, maxPixels int64) (image.Image, error) {
	reader, err := session.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	maximumDimension := max(int(maxSize.Width), int(maxSize.Height))
	return media.DecodeImage(name, reader, maxPixels, maximumDimension)
}

func (l *Library) lock() {
	if l.thumbnailLoader != nil {
		l.thumbnailLoader.close()
		l.thumbnailLoader = nil
	}
	if l.session != nil {
		_ = l.session.Close()
		l.session = nil
	}
	if l.thumbs != nil {
		l.thumbs.clear()
	}
	l.items = nil
	l.visible = nil
	l.keyValue = ""
	l.selected = make(map[string]bool)
	if l.selectedCount != nil {
		l.selectedCount.SetText("Выбрано: 0")
	}
	if l.searchEntry != nil {
		l.searchEntry.SetText("")
		l.query = ""
	}
	if l.tagManager != nil {
		l.tagManager.refresh(nil)
	}
	if l.categorySelect != nil {
		l.categorySelect.Disable()
		l.category = "Все категории"
		l.categorySelect.SetSelected(l.category)
	}
	if l.extensionSelect != nil {
		l.extensionSelect.Disable()
		l.extension = "Все расширения"
		l.extensionSelect.Options = []string{l.extension}
		l.extensionSelect.SetSelected(l.extension)
	}
	if l.gallery != nil {
		l.showEmpty("Элементы появятся здесь")
	}
	if l.form != nil {
		l.form.Refresh()
	}
}

func (l *Library) refreshExtensions() {
	values := map[string]bool{"Все расширения": true}
	for _, item := range l.items {
		if item.extension == "" {
			values["Без формата"] = true
		} else {
			values[item.extension] = true
		}
	}
	options := make([]string, 0, len(values))
	for value := range values {
		options = append(options, value)
	}
	sort.Strings(options)
	allIndex := sort.SearchStrings(options, "Все расширения")
	if allIndex > 0 {
		options[0], options[allIndex] = options[allIndex], options[0]
	}
	l.extension = "Все расширения"
	l.extensionSelect.Options = options
	l.extensionSelect.SetSelected(l.extension)
}

func (l *Library) render() {
	l.visible = l.filteredItems()
	l.lastVisible = -1
	if len(l.visible) == 0 {
		message := "Хранилище пусто"
		if len(l.items) > 0 {
			message = "По заданным условиям ничего не найдено"
		}
		l.showEmpty(message)
		return
	}
	l.gallery.Show()
	l.emptyState.Hide()
	l.gallery.Refresh()
}

func (l *Library) filteredItems() []libraryItem {
	filtered := make([]libraryItem, 0, len(l.items))
	for _, item := range l.items {
		if l.category != "Все категории" && string(item.category) != l.category {
			continue
		}
		if l.query != "" {
			matches := strings.Contains(strings.ToLower(item.name), l.query)
			if !matches {
				for _, tag := range item.tags {
					if strings.Contains(strings.ToLower(tag), l.query) {
						matches = true
						break
					}
				}
			}
			if !matches {
				continue
			}
		}
		extension := item.extension
		if extension == "" {
			extension = "Без формата"
		}
		if l.extension != "Все расширения" && extension != l.extension {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func (l *Library) createCard() fyne.CanvasObject { return newLibraryCard(l) }

func (l *Library) updateCard(index widget.GridWrapItemID, object fyne.CanvasObject) {
	card := object.(*libraryCard)
	if index < 0 || index >= len(l.visible) {
		card.setEmpty()
		return
	}
	item := l.visible[index]
	card.setItem(item)
	if (item.category == catalog.Visual || item.category == catalog.Other) && l.thumbnailLoader != nil {
		name := item.name
		if item.category == catalog.Visual {
			card.setPreviewIfCached(l.thumbs)
		}
		l.thumbnailLoader.request(item, thumbnailHotPriority, func(preview image.Image, err error) {
			fyne.Do(func() {
				if l.session != nil {
					if item.category == catalog.Visual || err == nil {
						l.reportPreview(name, err)
					}
				}
				if l.session != nil && card.item.name == name {
					if err != nil {
						if item.category == catalog.Visual {
							card.setPreviewUnavailable()
						} else {
							card.setItem(item)
						}
					} else if item.category == catalog.Other {
						l.markDetectedImage(name)
					} else {
						card.setPreview(preview)
					}
				}
			})
		})
		l.prefetchAround(index)
	}
	l.lastVisible = index
}

func (l *Library) reportPreview(name string, err error) {
	if l.previewReported == nil {
		l.previewReported = make(map[string]bool)
	}
	if _, reported := l.previewReported[name]; reported {
		return
	}
	l.previewReported[name] = true
	if err != nil {
		l.previewFailed++
		l.previewLastError = fmt.Sprintf("%s: %v", filepath.Base(name), err)
	} else {
		l.previewLoaded++
	}
	status := fmt.Sprintf("Предпросмотр: готово %d · ошибок %d", l.previewLoaded, l.previewFailed)
	if l.previewLastError != "" {
		status += " · " + l.previewLastError
	}
	l.status.SetText(status)
}

func (l *Library) markDetectedImage(name string) {
	changed := false
	for i := range l.items {
		if l.items[i].name == name && l.items[i].category == catalog.Other {
			l.items[i].category = catalog.Visual
			changed = true
		}
	}
	for i := range l.visible {
		if l.visible[i].name == name && l.visible[i].category == catalog.Other {
			l.visible[i].category = catalog.Visual
			changed = true
		}
	}
	if changed {
		l.render()
	}
}

func (l *Library) prefetchAround(index int) {
	if l.thumbnailLoader == nil || len(l.visible) == 0 {
		return
	}
	step := 1
	if l.lastVisible >= 0 && index < l.lastVisible {
		step = -1
	}
	for distance := 1; distance <= 2; distance++ {
		near := index + distance*step
		if near >= 0 && near < len(l.visible) && l.visible[near].category == catalog.Visual {
			l.thumbnailLoader.request(l.visible[near], thumbnailWarmPriority, nil)
		}
		near = index - distance*step
		if near >= 0 && near < len(l.visible) && l.visible[near].category == catalog.Visual {
			l.thumbnailLoader.request(l.visible[near], thumbnailWarmPriority, nil)
		}
	}
	for distance := 3; distance <= 5; distance++ {
		near := index + distance*step
		if near >= 0 && near < len(l.visible) && l.visible[near].category == catalog.Visual {
			l.thumbnailLoader.request(l.visible[near], thumbnailPredictedPriority, nil)
		}
	}
}

func (l *Library) openPhoto(name string) {
	photos := make([]libraryItem, 0)
	for _, item := range l.visible {
		if item.category == catalog.Visual {
			photos = append(photos, item)
		}
	}
	if l.thumbnailLoader != nil {
		l.thumbnailLoader.pauseAndWait()
	}
	if l.thumbs != nil {
		l.thumbs.clear()
	}
	showPhoto(l.window, photos, indexOf(photos, name), l.loadFullPhoto, l.deleteItem, func() {
		if l.thumbnailLoader != nil {
			l.thumbnailLoader.resume()
		}
	})
}

func (l *Library) reloadSession() error {
	selection := make(map[string]bool, len(l.selected))
	for name, selected := range l.selected {
		selection[name] = selected
	}
	if l.thumbnailLoader != nil {
		l.thumbnailLoader.close()
	}
	if l.session != nil {
		_ = l.session.Close()
	}
	session, err := l.storage.OpenSession(l.collection, l.keyValue)
	if err != nil {
		return err
	}
	l.installSession(session)
	for name := range selection {
		for _, item := range l.items {
			if item.name == name {
				l.selected[name] = true
				break
			}
		}
	}
	l.selectedCount.SetText(fmt.Sprintf("Выбрано: %d", len(l.selected)))
	l.refreshExtensions()
	if l.tagManager != nil {
		l.tagManager.refresh(session.Tags())
	}
	return nil
}

func (l *Library) deleteItem(name string) error {
	if err := l.storage.Delete(l.collection, l.keyValue, name); err != nil {
		return err
	}
	delete(l.selected, name)
	if err := l.reloadSession(); err != nil {
		return err
	}
	l.selectedCount.SetText(fmt.Sprintf("Выбрано: %d", len(l.selected)))
	l.render()
	if len(l.items) == 0 {
		l.status.SetText("Элемент удалён. Хранилище пусто.")
	} else {
		l.status.SetText(fmt.Sprintf("Элемент удалён. Осталось: %d", len(l.items)))
	}
	return nil
}

func (l *Library) confirmDelete(name string) {
	if err := l.deleteItem(name); err != nil {
		dialog.ShowError(err, l.window)
	}
}

func (l *Library) openItem(item libraryItem) {
	if l.session == nil {
		return
	}
	switch item.category {
	case catalog.Text:
		if item.size > 8<<20 {
			dialog.ShowInformation("Просмотр текста", "Файл слишком большой для встроенного предпросмотра.", l.window)
			return
		}
		reader, err := l.session.Open(item.name)
		if err != nil {
			dialog.ShowError(err, l.window)
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
		closeErr := reader.Close()
		if readErr != nil {
			dialog.ShowError(readErr, l.window)
			return
		}
		if closeErr != nil {
			dialog.ShowError(closeErr, l.window)
			return
		}
		showTextContent(l.window, item.name, strings.ToValidUTF8(string(data), "�"))
	case catalog.Video:
		l.openNative(item, "video")
	case catalog.Document:
		switch item.extension {
		case ".pdf":
			l.openNative(item, "pdf")
		case ".rtf", ".doc":
			l.openNative(item, "richtext")
		default:
			l.openNative(item, "quicklook")
		}
	default:
		dialog.ShowInformation("Предпросмотр", "Этот формат нельзя открыть во встроенном окне.", l.window)
	}
}

func (l *Library) openNative(item libraryItem, kind string) {
	if l.session == nil {
		return
	}
	reader, err := l.session.Open(item.name)
	if err != nil {
		dialog.ShowError(err, l.window)
		return
	}
	l.status.SetText("Подготавливаю предпросмотр…")
	go func() {
		err := l.mediaViewer.Open(kind, item.name, reader)
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(err, l.window)
				return
			}
			l.status.SetText("Открыто во встроенном окне")
		})
	}()
}

func (l *Library) showEmpty(message string) {
	if l.gallery == nil || l.emptyLabel == nil || l.emptyState == nil {
		return
	}
	l.emptyLabel.SetText(message)
	l.gallery.Hide()
	l.emptyState.Show()
}

func indexOf(items []libraryItem, name string) int {
	for index, item := range items {
		if item.name == name {
			return index
		}
	}
	return 0
}

func hasTag(tags []string, target string) bool {
	for _, tag := range tags {
		if strings.EqualFold(tag, target) {
			return true
		}
	}
	return false
}

type libraryCard struct {
	widget.BaseWidget
	owner       *Library
	item        libraryItem
	updating    bool
	content     *fyne.Container
	previewBox  *fyne.Container
	placeholder *widget.Label
	nameLabel   *widget.Label
	tagsLabel   *widget.Label
	selectItem  *widget.Check
}

func newLibraryCard(owner *Library) *libraryCard {
	card := &libraryCard{owner: owner}
	card.placeholder = widget.NewLabel("ФАЙЛ")
	card.previewBox = container.NewMax(container.NewCenter(card.placeholder))
	card.nameLabel = widget.NewLabel("")
	card.nameLabel.Truncation = fyne.TextTruncateEllipsis
	card.tagsLabel = widget.NewLabel("")
	card.selectItem = widget.NewCheck("Выбрать", func(checked bool) {
		if card.updating || card.item.name == "" {
			return
		}
		if checked {
			card.owner.selected[card.item.name] = true
		} else {
			delete(card.owner.selected, card.item.name)
		}
		card.owner.selectedCount.SetText(fmt.Sprintf("Выбрано: %d", len(card.owner.selected)))
	})
	card.content = container.NewVBox(
		container.NewGridWrap(fyne.NewSize(188, 164), card.previewBox),
		card.nameLabel,
		card.tagsLabel,
		card.selectItem,
	)
	card.ExtendBaseWidget(card)
	return card
}

func (card *libraryCard) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(card.content)
}

func (card *libraryCard) TappedSecondary(event *fyne.PointEvent) {
	card.showContextMenu(event)
}

func (card *libraryCard) DoubleTapped(*fyne.PointEvent) {
	card.openItem()
}

func (card *libraryCard) openItem() {
	if card.item.name == "" {
		return
	}
	if card.item.category == catalog.Visual {
		card.owner.openPhoto(card.item.name)
		return
	}
	card.owner.openItem(card.item)
}

func (card *libraryCard) showContextMenu(event *fyne.PointEvent) {
	if card.item.name == "" {
		return
	}
	menu := fyne.NewMenu("",
		fyne.NewMenuItem("Добавить метку…", func() { card.owner.tagManager.assignToItem(card.item.name) }),
		fyne.NewMenuItem("Удалить элемент", func() {
			dialog.ShowConfirm("Удалить элемент", "Безвозвратно удалить его из хранилища?", func(confirmed bool) {
				if confirmed {
					card.owner.confirmDelete(card.item.name)
				}
			}, card.owner.window)
		}),
	)
	widget.ShowPopUpMenuAtPosition(menu, fyne.CurrentApp().Driver().CanvasForObject(card.owner.gallery), event.AbsolutePosition)
}

func (card *libraryCard) setEmpty() {
	card.updating = true
	card.item = libraryItem{}
	card.nameLabel.SetText("")
	card.tagsLabel.Hide()
	card.selectItem.SetChecked(false)
	card.setPreview(nil)
	card.updating = false
}

func (card *libraryCard) setItem(item libraryItem) {
	card.updating = true
	card.item = item
	card.nameLabel.SetText(filepath.Base(item.name))
	if len(item.tags) > 0 {
		card.tagsLabel.SetText(strings.Join(item.tags, " · "))
		card.tagsLabel.Show()
	} else {
		card.tagsLabel.SetText("")
		card.tagsLabel.Hide()
	}
	card.selectItem.SetChecked(card.owner.selected[item.name])
	card.updating = false
	if item.category != catalog.Visual {
		card.placeholder.SetText(strings.ToUpper(string(item.category)) + "\n" + item.extension)
		card.setPreview(nil)
	}
}

func (card *libraryCard) setPreviewIfCached(cache *thumbnailCache) {
	if preview, ok := cache.get(card.item.name); ok {
		card.setPreview(preview)
	} else {
		card.placeholder.SetText("Загрузка предпросмотра…")
		card.setPreview(nil)
	}
}

func (card *libraryCard) setPreviewUnavailable() {
	card.placeholder.SetText("Предпросмотр недоступен")
	card.setPreview(nil)
}

func (card *libraryCard) setPreview(preview image.Image) {
	if preview == nil {
		card.previewBox.Objects = []fyne.CanvasObject{container.NewCenter(card.placeholder)}
		card.previewBox.Refresh()
		card.Refresh()
		return
	}
	imagePreview := canvas.NewImageFromImage(preview)
	imagePreview.FillMode = canvas.ImageFillContain
	card.previewBox.Objects = []fyne.CanvasObject{imagePreview}
	card.previewBox.Refresh()
	card.Refresh()
}
