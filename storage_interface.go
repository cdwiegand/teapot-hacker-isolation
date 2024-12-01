package teapot_hacker_isolation

import "time"

type IStorage interface {
	GetIpViolations(ip string) StorageItem
	IncrIpViolations(ip string, jailTime time.Duration) StorageItem
}

type StorageItem struct {
	count   int
	expires int64
}
