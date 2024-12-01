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
	MinInstances               int      `json:"minInstances"`
	ExpirySeconds              int      `json:"expirySeconds"`
	ReturnCurrentExpiresHeader string   `json:"returnCurrentExpiresHeader"`
	ReturnCurrentStatusHeader  string   `json:"returnCurrentStatusHeader"`
	ReturnCurrentCountHeader   string   `json:"returnCurrentCountHeader"`
	StorageSystem              string   `json:"storageSystem"`
	RedisHost                  string   `json:"redisHost"`
	RedisPort                  int      `json:"redisPort"`
	LoggingPrefix              string   `json:"loggingPrefix"`
	TriggerOnHeaders           []string `json:"triggerOnHeaders"`
	TriggerOnStatusCodes       []int    `json:"triggerOnStatusCodes"`
	ReturnStatusCodeOnBlock    int      `json:"blockedStatusCode"`
	ReturnBodyOnBlock          string   `json:"blockedBody"`
	ReturnHeadersOnBlock       []string `json:"blockedHeaders"`
}

// CreateConfig creates the DEFAULT plugin configuration - no access to config yet!
func CreateConfig() *Config {
	return &Config{
		MinInstances:               2,
		ExpirySeconds:              2,
		ReturnCurrentExpiresHeader: "",
		ReturnCurrentStatusHeader:  "",
		ReturnCurrentCountHeader:   "",
		StorageSystem:              "Memory",
		LoggingPrefix:              "TeapotIsolation: ",
		TriggerOnHeaders:           []string{"X-Hacker-Detected"},
		TriggerOnStatusCodes:       []int{418, 405},
		ReturnStatusCodeOnBlock:    418,
		ReturnBodyOnBlock:          "This is a coffee shop!",
		ReturnHeadersOnBlock:       []string{"Content-Type: tea/earl-grey"},
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

	logger := log.New(os.Stderr, config.LoggingPrefix, log.LstdFlags|log.Lshortfile)

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
		redis, err := NewRedisStorage(config)
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

func (t *TeapotHackerIsolationPlugin) AppendStatusHeaders(rw http.ResponseWriter, found StorageItem, blocked bool) {
	if blocked {
		if t.Config.ReturnCurrentStatusHeader != "" {
			rw.Header().Set(t.Config.ReturnCurrentStatusHeader, "BLOCKED")
		}
		if t.Config.ReturnCurrentExpiresHeader != "" {
			expiresAt := time.Unix(found.expires, 0)
			rw.Header().Set(t.Config.ReturnCurrentExpiresHeader, expiresAt.String())
		}
	} else {
		if t.Config.ReturnCurrentStatusHeader != "" {
			rw.Header().Set(t.Config.ReturnCurrentStatusHeader, "OK")
		}
	}
	if t.Config.ReturnCurrentCountHeader != "" {
		rw.Header().Set(t.Config.ReturnCurrentCountHeader, fmt.Sprintf("%d", found.count))
	}
}
func (t *TeapotHackerIsolationPlugin) ReturnHackerResponse(rw http.ResponseWriter, found StorageItem) {
	t.AppendStatusHeaders(rw, found, true)
	for _, v := range t.Config.ReturnHeadersOnBlock {
		if strings.Contains(v, ":") {
			parts := strings.SplitN(v, ":", 2)
			rw.Header().Set(parts[0], parts[1])
		}
	}
	rw.WriteHeader(t.Config.ReturnStatusCodeOnBlock)
	if t.Config.ReturnBodyOnBlock != "" {
		rw.Write([]byte(t.Config.ReturnBodyOnBlock))
	}
}

func (t *TeapotHackerIsolationPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	jailTime := time.Duration(t.Config.ExpirySeconds) * time.Minute

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ip = req.RemoteAddr // this shouldn't happen??
	}
	found := t.Storage.GetIpViolations(ip)
	if err != nil {
		t.Logger.Printf("Failed to get IP from storage: %s\n", err.Error())
	} else if found.count >= t.Config.MinInstances {
		found = t.Storage.IncrIpViolations(ip, jailTime) // increment their badness
		expiresAt := time.Unix(found.expires, 0)
		t.Logger.Printf("IP %s is blocked until %s\n", ip, expiresAt.String())
		t.ReturnHackerResponse(rw, found)
		return // DO NOT CONTINUE
	}

	rw2 := httptest.NewRecorder()
	t.next.ServeHTTP(rw2, req)

	badDetected := t.DetectIfHacker(rw2.Result())
	if badDetected {
		found = t.Storage.IncrIpViolations(ip, jailTime)
		if err != nil {
			t.Logger.Printf("Unable to log bad IP to storage: %s\n", err.Error())
		}
		if found.count >= t.Config.MinInstances {
			expiresAt := time.Unix(found.expires, 0)
			t.Logger.Printf("IP %s is now blocked until %s\n", ip, expiresAt.String())
			t.ReturnHackerResponse(rw, found)
			return // DO NOT CONTINUE
		}
	}

	// ok to pass through content
	for h, vs := range rw2.Result().Header {
		for _, v := range vs {
			rw.Header().Add(h, v)
		}
	}
	t.AppendStatusHeaders(rw, found, false)
	// now write status code, after which we can only write body, no more headers!
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
