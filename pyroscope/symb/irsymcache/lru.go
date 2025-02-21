package irsymcache

import (
	"container/list"
	"fmt"
	"sync"
)

type entry[K comparable, V any] struct {
	key   K
	value V
}

type LRUCache[K comparable, V any] struct {
	mu       sync.Mutex
	maxSize  int
	size     int
	ll       *list.List
	cache    map[K]*list.Element
	putCount int

	evictCount int
	hitCount   int
	missCount  int

	sizeOf  func(key K, value V) int
	onEvict func(key K, value V)
}

func New[K comparable, V any](maxSize int, sizeof func(key K, value V) int) *LRUCache[K, V] {
	if maxSize <= 0 {
		panic("maxSize must be positive")
	}
	return &LRUCache[K, V]{
		maxSize: maxSize,
		ll:      list.New(),
		cache:   make(map[K]*list.Element),
		sizeOf:  sizeof,
	}
}

func (c *LRUCache[K, V]) SetOnEvict(fn func(key K, value V)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvict = fn
}

func (c *LRUCache[K, V]) Get(key K) (value V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, hit := c.cache[key]; hit {
		c.hitCount++
		c.ll.MoveToFront(element)
		return element.Value.(*entry[K, V]).value, true
	}
	c.missCount++
	return value, false
}

func (c *LRUCache[K, V]) Put(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.putCount++
	if _, exists := c.cache[key]; exists {
		return false
	}

	ent := &entry[K, V]{key: key, value: value}
	element := c.ll.PushFront(ent)
	c.cache[key] = element
	c.size += c.sizeOf(key, value)

	c.trimToSize()
	return true
}

func (c *LRUCache[K, V]) trimToSize() {
	for c.size > c.maxSize {
		element := c.ll.Back()
		if element == nil {
			break
		}
		ent := element.Value.(*entry[K, V])
		delete(c.cache, ent.key)
		c.ll.Remove(element)
		c.size -= c.sizeOf(ent.key, ent.value)
		c.evictCount++

		if c.onEvict != nil {
			c.onEvict(ent.key, ent.value)
		}
	}
}

func (c *LRUCache[K, V]) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}

func (c *LRUCache[K, V]) MaxSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxSize
}

func (c *LRUCache[K, V]) Stats() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	accesses := c.hitCount + c.missCount
	hitRate := 0
	if accesses > 0 {
		hitRate = c.hitCount * 100 / accesses
	}
	return fmt.Sprintf("LRUCache[maxSize=%d,hits=%d,misses=%d,hitRate=%d%%]",
		c.maxSize, c.hitCount, c.missCount, hitRate)
}
