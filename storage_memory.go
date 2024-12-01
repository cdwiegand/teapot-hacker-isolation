package teapot_hacker_isolation

import (
	"os"
	"time"
)

type MemoryStorage struct {
	cache map[string]StorageItem
}

func NewMemoryStorage() *MemoryStorage {
	ret := MemoryStorage{
		cache: make(map[string]StorageItem),
	}
	return &ret
}

func (r *MemoryStorage) GetIpViolations(ip string) StorageItem {
	for h, v := range r.cache {
		if h == ip && v.expires >= time.Now().Unix() {
			return v
		}
	}
	// TODO FIXME: kick off thread to GC old entries??
	return StorageItem{}
}

func (r *MemoryStorage) IncrIpViolations(ip string, jailTime time.Duration) StorageItem {
	now := time.Now().Unix()
	newExpires := now + int64(jailTime.Seconds())
	for h, v := range r.cache {
		if h == ip && v.expires >= now {
			os.Stderr.WriteString("matched!\n")
			v.count = v.count + 1
			v.expires = newExpires
			r.cache[ip] = v // set back into memory cache
			return v
		}
	}
	ret := StorageItem{
		count:   1,
		expires: newExpires,
	}
	r.cache[ip] = ret
	return ret
}
