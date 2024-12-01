package teapot_hacker_isolation

import "time"

type IStorage interface {
	GetIpViolations(ip string) (int, error)
	IncrIpViolations(ip string, jailTime time.Duration) (int, error)
}
