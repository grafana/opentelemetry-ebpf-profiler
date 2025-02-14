package irsymcache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func defaultSizeOf[K comparable, V any](key K, value V) int {
	return 1
}

func TestLRUCache_PutAndGet(t *testing.T) {
	tests := []struct {
		name     string
		maxSize  int
		ops      func(*LRUCache[string, int])
		wantSize int
		checks   map[string]int // key -> expected value
	}{
		{
			name:    "basic put and get",
			maxSize: 3,
			ops: func(c *LRUCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3)
			},
			wantSize: 3,
			checks: map[string]int{
				"a": 1,
				"b": 2,
				"c": 3,
			},
		},
		{
			name:    "eviction on overflow",
			maxSize: 2,
			ops: func(c *LRUCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3) // should evict "a"
			},
			wantSize: 2,
			checks: map[string]int{
				"b": 2,
				"c": 3,
			},
		},
		{
			name:    "get updates access order",
			maxSize: 2,
			ops: func(c *LRUCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Get("a")    // moves "a" to front
				c.Put("c", 3) // should evict "b", not "a"
			},
			wantSize: 2,
			checks: map[string]int{
				"a": 1,
				"c": 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := New[string, int](tt.maxSize, defaultSizeOf[string, int])
			tt.ops(cache)

			if got := cache.Size(); got != tt.wantSize {
				t.Errorf("Size() = %v, want %v", got, tt.wantSize)
			}

			// Check all expected key-value pairs
			for k, want := range tt.checks {
				if got, ok := cache.Get(k); !ok {
					t.Errorf("Get(%v) = missing, want %v", k, want)
				} else if got != want {
					t.Errorf("Get(%v) = %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestLRUCache_Stats(t *testing.T) {
	cache := New[string, int](2, defaultSizeOf[string, int])

	// Test hits
	cache.Put("a", 1)
	cache.Put("b", 2)

	if _, ok := cache.Get("a"); !ok {
		t.Error("Get(a) should hit")
	}
	if _, ok := cache.Get("b"); !ok {
		t.Error("Get(b) should hit")
	}
	if _, ok := cache.Get("a"); !ok {
		t.Error("Get(a) should hit")
	}

	// Test misses
	if _, ok := cache.Get("c"); ok {
		t.Error("Get(c) should miss")
	}

	if cache.hitCount != 3 {
		t.Errorf("hitCount = %v, want 3", cache.hitCount)
	}
	if cache.missCount != 1 {
		t.Errorf("missCount = %v, want 1", cache.missCount)
	}
}

func TestLRUCache_CustomSize(t *testing.T) {
	type CustomCache struct {
		*LRUCache[string, string]
	}

	newCustomCache := func(maxSize int) *CustomCache {
		c := &CustomCache{
			LRUCache: New[string, string](maxSize, defaultSizeOf[string, string]),
		}
		return c
	}

	cache := newCustomCache(5)
	cache.LRUCache.sizeOf = func(key string, value string) int {
		return len(value)
	}

	tests := []struct {
		op      string
		key     string
		value   string
		wantLen int
	}{
		{"put", "a", "1", 1},     // size = 1
		{"put", "b", "22", 2},    // size = 3
		{"put", "c", "333", 3},   // size = 6, should evict "a" (size becomes 5)
		{"check", "a", "", 0},    // "a" should be evicted
		{"check", "b", "22", 2},  // "b" should exist
		{"check", "c", "333", 3}, // "c" should exist
	}

	for _, tt := range tests {
		switch tt.op {
		case "put":
			cache.Put(tt.key, tt.value)
		case "check":
			if got, ok := cache.Get(tt.key); ok != (tt.wantLen > 0) {
				t.Errorf("Get(%v) existence = %v, want %v", tt.key, ok, tt.wantLen > 0)
			} else if ok && got != tt.value {
				t.Errorf("Get(%v) = %v, want %v", tt.key, got, tt.value)
			}
		}
	}
}

func TestLRUCache_evict(t *testing.T) {
	cache := New[string, int](1024, func(key string, value int) int {
		return value
	})
	cache.Put("f1", 512)
	cache.Put("f2", 512)
	cache.Get("f1")
	cache.Put("f3", 512)

	assert.Equal(t, 1024, cache.Size())
	assert.Equal(t, 1, cache.evictCount)

	_, ok := cache.Get("f2")
	assert.False(t, ok)
	_, ok = cache.Get("f1")
	assert.True(t, ok)
	_, ok = cache.Get("f3")
	assert.True(t, ok)

}
