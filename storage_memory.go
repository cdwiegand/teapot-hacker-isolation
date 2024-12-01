package teapot_hacker_isolation

import "time"

type MemoryStorage struct {
	cache map[string]MemoryStorageItem
}

type MemoryStorageItem struct {
	count   int
	expires int64
}

func NewMemoryStorage() (*MemoryStorage, error) {
	ret := MemoryStorage{
		cache: make(map[string]MemoryStorageItem),
	}
	return &ret, nil
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
	for h, v := range r.cache {
		if h == ip {
			if v.expires < time.Now().Unix() {
				v.count = 1
			} else {
				v.count = v.count + 1
			}
			r.cache[h] = v // set back into memory cache
			v.expires = time.Now().Unix() + int64(jailTime.Seconds())
			return v.count, nil
		}
	}
	r.cache[ip] = MemoryStorageItem{
		count:   1,
		expires: time.Now().Unix() + int64(jailTime.Seconds()),
	}
	return 1, nil
}
