package teapot_hacker_isolation

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	MinInstances              int                 `json:"minInstances"`
	MinutesInJail             int                 `json:"minutesInJail"`
	ReturnCurrentStatusHeader string              `json:"returnCurrentStatusHeader"`
	ReturnCurrentCountHeader  string              `json:"returnCurrentCountHeader"`
	StorageSystem             string              `json:"storageSystem"`
	RedisStorageConfig        *RedisStorageConfig `json:"redis"`
	LoggingPrefix             string              `json:"loggingPrefix"`
	TriggerOnHeaders          []string            `json:"triggerOnHeaders"`
	TriggerOnStatusCodes      []int               `json:"triggerOnStatusCodes"`
	ReturnStatusCodeOnBlock   int                 `json:"blockedStatusCode"`
}

// CreateConfig creates the DEFAULT plugin configuration - no access to config yet!
func CreateConfig() *Config {
	return &Config{
		MinInstances:              2,
		MinutesInJail:             2,
		ReturnCurrentStatusHeader: "",
		ReturnCurrentCountHeader:  "",
		StorageSystem:             "memory",
		RedisStorageConfig:        NewRedisStorageConfig(),
		LoggingPrefix:             "TeapotIsolation: ",
		TriggerOnHeaders:          []string{"X-Hacker-Detected"},
		TriggerOnStatusCodes:      []int{418},
		ReturnStatusCodeOnBlock:   418,
	}
}

type TeapotHackerIsolationPlugin struct {
	Config  *Config
	Logger  *log.Logger
	Storage IStorage
	name    string
	next    http.Handler
}

// for debugging and to get back a strongly typed plugin implementation
func NewTeapotHackerIsolationPlugin(ctx context.Context, next http.Handler, config *Config, name string) (*TeapotHackerIsolationPlugin, error) {
	if config == nil {
		return nil, fmt.Errorf("config can not be nil")
	}

	logger := log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)

	plugin := &TeapotHackerIsolationPlugin{
		Config: config,
		Logger: logger,
		next:   next,
		name:   name,
	}

	//var storage IStorage
	var err error
	storageType := strings.ToLower(config.StorageSystem)
	switch storageType {
	case "memory":
		plugin.Storage = NewMemoryStorage()
	case "redis":
		redis, err := NewRedisStorage(config.RedisStorageConfig)
		if err == nil && redis != nil {
			plugin.Storage = redis
		}
	default:
		panic(fmt.Sprintf("Storage type %s unknown", config.StorageSystem))
	}

	return plugin, err
}

// for Traefik plugin integration
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return NewTeapotHackerIsolationPlugin(ctx, next, config, name)
}

func (t *TeapotHackerIsolationPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ip = req.RemoteAddr // this shouldn't happen??
	}
	found, err := t.Storage.GetIpViolations(ip)
	if err != nil {
		t.Logger.Printf("Failed to get IP from storage: %s\n", err.Error())
	} else if found >= t.Config.MinInstances {
		// means we were able to get it :(
		t.Logger.Printf("IP %s is blocked\n", ip)
		if t.Config.ReturnCurrentStatusHeader != "" {
			rw.Header().Set(t.Config.ReturnCurrentStatusHeader, "BLOCKED")
		}
		if t.Config.ReturnCurrentCountHeader != "" {
			rw.Header().Set(t.Config.ReturnCurrentCountHeader, fmt.Sprintf("%d", found))
		}
		rw.WriteHeader(t.Config.ReturnStatusCodeOnBlock)
		// no body for you!
		return
	}

	rw2 := httptest.NewRecorder()
	t.next.ServeHTTP(rw2, req)

	badDetected := t.DetectIfHacker(rw2.Result())
	if badDetected {
		jailTime := time.Duration(t.Config.MinutesInJail) * time.Minute
		found, err = t.Storage.IncrIpViolations(ip, jailTime)
		if err != nil {
			t.Logger.Printf("Unable to log bad IP to redis: %s\n", err.Error())
		}
		if t.Config.ReturnCurrentCountHeader != "" {
			rw.Header().Set(t.Config.ReturnCurrentCountHeader, fmt.Sprintf("%d", found))
		}
		if found >= t.Config.MinInstances {
			t.Logger.Printf("IP %s is now blocked\n", ip)
			if t.Config.ReturnCurrentStatusHeader != "" {
				rw.Header().Set(t.Config.ReturnCurrentStatusHeader, "BLOCKED")
			}
			rw.WriteHeader(t.Config.ReturnStatusCodeOnBlock)
			return
		}
	}

	// ok to pass through content
	for h, vs := range rw2.Result().Header {
		for _, v := range vs {
			rw.Header().Add(h, v)
		}
	}
	if t.Config.ReturnCurrentStatusHeader != "" {
		rw.Header().Set(t.Config.ReturnCurrentStatusHeader, "OK")
	}
	if t.Config.ReturnCurrentCountHeader != "" {
		rw.Header().Set(t.Config.ReturnCurrentCountHeader, fmt.Sprintf("%d", found))
	}
	rw.WriteHeader(rw2.Result().StatusCode)
	if rw2.Body.Len() > 0 {
		rw.Write(rw2.Body.Bytes())
	}
}

func (t *TeapotHackerIsolationPlugin) DetectIfHacker(rw2 *http.Response) bool {
	blocked := false
	for _, v := range t.Config.TriggerOnStatusCodes {
		if rw2.StatusCode == v {
			return true
		}
	}
	if !blocked {
		// check headers
		for name := range rw2.Header {
			for _, detect := range t.Config.TriggerOnHeaders {
				if strings.EqualFold(name, detect) {
					return true
				}
			}
		}
	}
	return false
}
