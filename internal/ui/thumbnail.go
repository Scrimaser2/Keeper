package ui

import (
	"container/list"
	"image"
	"sync"

	"photovault/internal/vault"
)

const (
	thumbnailCacheLimit        int64 = 96 << 20
	thumbnailWorkerCount             = 2
	thumbnailHotPriority             = 0
	thumbnailWarmPriority            = 1
	thumbnailPredictedPriority       = 2
)

type thumbnailEntry struct {
	name  string
	image image.Image
	bytes int64
}

type thumbnailCache struct {
	mu     sync.Mutex
	limit  int64
	used   int64
	items  map[string]*list.Element
	recent *list.List
}

func newThumbnailCache(limit int64) *thumbnailCache {
	return &thumbnailCache{limit: limit, items: make(map[string]*list.Element), recent: list.New()}
}

func (cache *thumbnailCache) get(name string) (image.Image, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	item, ok := cache.items[name]
	if !ok {
		return nil, false
	}
	cache.recent.MoveToFront(item)
	return item.Value.(thumbnailEntry).image, true
}

func (cache *thumbnailCache) add(name string, preview image.Image) {
	if preview == nil {
		return
	}
	weight := int64(preview.Bounds().Dx()) * int64(preview.Bounds().Dy()) * 4
	if weight <= 0 || weight > cache.limit {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if current, ok := cache.items[name]; ok {
		cache.used -= current.Value.(thumbnailEntry).bytes
		cache.recent.Remove(current)
		delete(cache.items, name)
	}
	for cache.used+weight > cache.limit {
		oldest := cache.recent.Back()
		if oldest == nil {
			break
		}
		item := oldest.Value.(thumbnailEntry)
		cache.used -= item.bytes
		delete(cache.items, item.name)
		cache.recent.Remove(oldest)
	}
	item := thumbnailEntry{name: name, image: preview, bytes: weight}
	cache.items[name] = cache.recent.PushFront(item)
	cache.used += weight
}

func (cache *thumbnailCache) clear() {
	cache.mu.Lock()
	cache.items = make(map[string]*list.Element)
	cache.recent.Init()
	cache.used = 0
	cache.mu.Unlock()
}

type thumbnailRequest struct {
	item      libraryItem
	priority  int
	callbacks []func(image.Image, error)
	queued    bool
}

type thumbnailLoader struct {
	session *vault.Session
	cache   *thumbnailCache
	load    func(*vault.Session, libraryItem) (image.Image, error)

	mu       sync.Mutex
	cond     *sync.Cond
	requests map[string]*thumbnailRequest
	queue    []*thumbnailRequest
	closed   bool
	paused   bool
	working  int
}

func newThumbnailLoader(session *vault.Session, cache *thumbnailCache, load func(*vault.Session, libraryItem) (image.Image, error)) *thumbnailLoader {
	loader := &thumbnailLoader{
		session:  session,
		cache:    cache,
		load:     load,
		requests: make(map[string]*thumbnailRequest),
	}
	loader.cond = sync.NewCond(&loader.mu)
	for i := 0; i < thumbnailWorkerCount; i++ {
		go loader.run()
	}
	return loader
}

func (loader *thumbnailLoader) request(item libraryItem, priority int, callback func(image.Image, error)) {
	if image, ok := loader.cache.get(item.name); ok {
		if callback != nil {
			callback(image, nil)
		}
		return
	}
	loader.mu.Lock()
	defer loader.mu.Unlock()
	if loader.closed {
		return
	}
	request, exists := loader.requests[item.name]
	if !exists {
		request = &thumbnailRequest{item: item, priority: priority, queued: true}
		loader.requests[item.name] = request
		loader.queue = append(loader.queue, request)
	} else if priority < request.priority {
		request.priority = priority
	}
	if callback != nil {
		request.callbacks = append(request.callbacks, callback)
	}
	loader.cond.Signal()
}

func (loader *thumbnailLoader) close() {
	loader.mu.Lock()
	loader.closed = true
	loader.queue = nil
	loader.cond.Broadcast()
	loader.mu.Unlock()
}

func (loader *thumbnailLoader) pauseAndWait() {
	loader.mu.Lock()
	loader.paused = true
	for loader.working > 0 {
		loader.cond.Wait()
	}
	loader.mu.Unlock()
}

func (loader *thumbnailLoader) resume() {
	loader.mu.Lock()
	loader.paused = false
	loader.cond.Broadcast()
	loader.mu.Unlock()
}

func (loader *thumbnailLoader) run() {
	for {
		loader.mu.Lock()
		for !loader.closed && (loader.paused || len(loader.queue) == 0) {
			loader.cond.Wait()
		}
		if loader.closed {
			loader.mu.Unlock()
			return
		}
		best := 0
		for i := 1; i < len(loader.queue); i++ {
			if loader.queue[i].priority < loader.queue[best].priority {
				best = i
			}
		}
		request := loader.queue[best]
		loader.queue = append(loader.queue[:best], loader.queue[best+1:]...)
		callbacks := append([]func(image.Image, error){}, request.callbacks...)
		request.callbacks = nil
		request.queued = false
		loader.working++
		loader.mu.Unlock()

		preview, err := loader.load(loader.session, request.item)
		if err == nil {
			loader.cache.add(request.item.name, preview)
		}
		loader.mu.Lock()
		current := loader.requests[request.item.name]
		if current == request {
			callbacks = append(callbacks, request.callbacks...)
			delete(loader.requests, request.item.name)
		}
		loader.mu.Unlock()
		for _, callback := range callbacks {
			callback(preview, err)
		}
		loader.mu.Lock()
		loader.working--
		loader.cond.Broadcast()
		loader.mu.Unlock()
	}
}
