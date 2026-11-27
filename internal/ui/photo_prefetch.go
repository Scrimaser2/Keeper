package ui

import (
	"image"
	"sync"
)

const fullPhotoCacheLimit int64 = 192 << 20

type fullPhotoEntry struct {
	image image.Image
	bytes int64
}

// fullPhotoPrefetcher keeps the current image and nearby full-size images in a
// bounded cache. One worker limits simultaneous full-resolution decodes.
type fullPhotoPrefetcher struct {
	load func(string) (image.Image, error)

	mu        sync.Mutex
	cond      *sync.Cond
	window    map[string]int
	cache     map[string]fullPhotoEntry
	callbacks map[string][]func(image.Image, error)
	queued    map[string]bool
	loading   map[string]bool
	queue     []string
	current   string
	used      int64
	closed    bool
	done      chan struct{}
}

func newFullPhotoPrefetcher(load func(string) (image.Image, error)) *fullPhotoPrefetcher {
	prefetcher := &fullPhotoPrefetcher{
		load:      load,
		window:    make(map[string]int),
		cache:     make(map[string]fullPhotoEntry),
		callbacks: make(map[string][]func(image.Image, error)),
		queued:    make(map[string]bool),
		loading:   make(map[string]bool),
		done:      make(chan struct{}),
	}
	prefetcher.cond = sync.NewCond(&prefetcher.mu)
	go prefetcher.run()
	return prefetcher
}

func (prefetcher *fullPhotoPrefetcher) request(name string, callback func(image.Image, error)) {
	prefetcher.mu.Lock()
	if prefetcher.closed {
		prefetcher.mu.Unlock()
		return
	}
	if entry, ok := prefetcher.cache[name]; ok {
		prefetcher.mu.Unlock()
		if callback != nil {
			callback(entry.image, nil)
		}
		return
	}
	if callback != nil {
		prefetcher.callbacks[name] = append(prefetcher.callbacks[name], callback)
	}
	if _, ok := prefetcher.window[name]; !ok {
		prefetcher.window[name] = 3
	}
	prefetcher.enqueueLocked(name)
	prefetcher.cond.Signal()
	prefetcher.mu.Unlock()
}

func (prefetcher *fullPhotoPrefetcher) setWindow(photos []libraryItem, current int) {
	prefetcher.mu.Lock()
	defer prefetcher.mu.Unlock()
	if prefetcher.closed || current < 0 || current >= len(photos) {
		return
	}
	start := max(0, current-2)
	end := min(len(photos), current+3)
	wanted := make(map[string]int, end-start)
	for index := start; index < end; index++ {
		wanted[photos[index].name] = absInt(index - current)
	}
	prefetcher.window = wanted
	prefetcher.current = photos[current].name
	for name, entry := range prefetcher.cache {
		if _, keep := wanted[name]; !keep {
			prefetcher.used -= entry.bytes
			delete(prefetcher.cache, name)
		}
	}
	for name := range prefetcher.callbacks {
		if _, keep := wanted[name]; !keep {
			delete(prefetcher.callbacks, name)
		}
	}
	prefetcher.queue = prefetcher.queue[:0]
	prefetcher.queued = make(map[string]bool)
	for name := range wanted {
		prefetcher.enqueueLocked(name)
	}
	prefetcher.cond.Signal()
}

func (prefetcher *fullPhotoPrefetcher) enqueueLocked(name string) {
	if prefetcher.queued[name] || prefetcher.loading[name] {
		return
	}
	if _, cached := prefetcher.cache[name]; cached {
		return
	}
	prefetcher.queue = append(prefetcher.queue, name)
	prefetcher.queued[name] = true
}

func (prefetcher *fullPhotoPrefetcher) close() <-chan struct{} {
	prefetcher.mu.Lock()
	if !prefetcher.closed {
		prefetcher.closed = true
		prefetcher.cache = nil
		prefetcher.callbacks = nil
		prefetcher.window = nil
		prefetcher.queue = nil
		prefetcher.used = 0
		if len(prefetcher.loading) == 0 {
			close(prefetcher.done)
			prefetcher.done = nil
		}
		prefetcher.cond.Broadcast()
	}
	done := prefetcher.done
	prefetcher.mu.Unlock()
	if done == nil {
		finished := make(chan struct{})
		close(finished)
		return finished
	}
	return done
}

func (prefetcher *fullPhotoPrefetcher) run() {
	for {
		prefetcher.mu.Lock()
		for !prefetcher.closed && len(prefetcher.queue) == 0 {
			prefetcher.cond.Wait()
		}
		if prefetcher.closed {
			prefetcher.mu.Unlock()
			return
		}
		best := 0
		for index := 1; index < len(prefetcher.queue); index++ {
			if prefetcher.window[prefetcher.queue[index]] < prefetcher.window[prefetcher.queue[best]] {
				best = index
			}
		}
		name := prefetcher.queue[best]
		prefetcher.queue = append(prefetcher.queue[:best], prefetcher.queue[best+1:]...)
		delete(prefetcher.queued, name)
		prefetcher.loading[name] = true
		prefetcher.mu.Unlock()

		loaded, err := prefetcher.load(name)
		weight := imageWeight(loaded)

		prefetcher.mu.Lock()
		delete(prefetcher.loading, name)
		if !prefetcher.closed && err == nil && weight > 0 && weight <= fullPhotoCacheLimit {
			if _, wanted := prefetcher.window[name]; wanted && prefetcher.makeRoomLocked(name, weight) {
				prefetcher.cache[name] = fullPhotoEntry{image: loaded, bytes: weight}
				prefetcher.used += weight
			}
		}
		callbacks := prefetcher.callbacks[name]
		delete(prefetcher.callbacks, name)
		if prefetcher.closed {
			callbacks = nil
			if len(prefetcher.loading) == 0 && prefetcher.done != nil {
				close(prefetcher.done)
				prefetcher.done = nil
			}
		}
		prefetcher.mu.Unlock()
		for _, callback := range callbacks {
			callback(loaded, err)
		}
	}
}

func (prefetcher *fullPhotoPrefetcher) makeRoomLocked(incoming string, weight int64) bool {
	for prefetcher.used+weight > fullPhotoCacheLimit {
		farthest := ""
		farthestDistance := -1
		for name := range prefetcher.cache {
			if name == prefetcher.current || name == incoming {
				continue
			}
			distance, wanted := prefetcher.window[name]
			if wanted && distance > farthestDistance {
				farthest, farthestDistance = name, distance
			}
		}
		incomingDistance, incomingWanted := prefetcher.window[incoming]
		if farthest == "" || !incomingWanted || farthestDistance <= incomingDistance {
			return false
		}
		prefetcher.used -= prefetcher.cache[farthest].bytes
		delete(prefetcher.cache, farthest)
	}
	return true
}

func imageWeight(preview image.Image) int64 {
	if preview == nil {
		return 0
	}
	bounds := preview.Bounds()
	return int64(bounds.Dx()) * int64(bounds.Dy()) * 4
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
