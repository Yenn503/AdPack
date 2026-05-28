package transport

import (
	"sync"

	"adpack/core"
)

var (
	registry   = make(map[string]core.Transport)
	registryMu sync.RWMutex
)

func Register(name string, t core.Transport) {
	registryMu.Lock()
	registry[name] = t
	registryMu.Unlock()
}

func Get(name string) (core.Transport, bool) {
	registryMu.RLock()
	t, ok := registry[name]
	registryMu.RUnlock()
	return t, ok
}

func List() []string {
	registryMu.RLock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	registryMu.RUnlock()
	return names
}

// ClearRegistry removes all registered transports (used for re-initialization).
func ClearRegistry() {
	registryMu.Lock()
	for k := range registry {
		delete(registry, k)
	}
	registryMu.Unlock()
}
