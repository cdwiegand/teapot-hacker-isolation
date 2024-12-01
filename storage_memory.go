package teapot_hacker_isolation

import (
	"os"
	"time"
)

type MemoryStorage struct {
	cache map[string]MemoryStorageItem
}

type MemoryStorageItem struct {
	count   int
	expires int64
}

func NewMemoryStorage() *MemoryStorage {
	ret := MemoryStorage{
		cache: make(map[string]MemoryStorageItem),
	}
	return &ret
}

func (r *MemoryStorage) GetIpViolations(ip string) (int, error) {
	for h, v := range r.cache {
		if h == ip && v.expires >= time.Now().Unix() {
			return v.count, nil
		}
	}
	// TODO FIXME: kick off thread to GC old entries??
	return 0, nil
}

func (r *MemoryStorage) IncrIpViolations(ip string, jailTime time.Duration) (int, error) {
	now := time.Now().Unix()
	newExpires := now + int64(jailTime.Seconds())
	for h, v := range r.cache {
		if h == ip && v.expires >= now {
			os.Stderr.WriteString("matched!\n")
			v.count = v.count + 1
			v.expires = newExpires
			r.cache[ip] = v // set back into memory cache
			return v.count, nil
		}
	}
	r.cache[ip] = MemoryStorageItem{
		count:   1,
		expires: newExpires,
	}
	return 1, nil
}
