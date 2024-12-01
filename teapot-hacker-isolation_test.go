package teapot_hacker_isolation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// New created a new plugin, with a config that's been set (possibly) by the admin
func TestNew(t *testing.T) {
	ctx := context.Background()
	config := CreateConfig()
	newPlugin, err := New(ctx, nil, config, "testing")
	if err != nil {
		t.FailNow()
	}
	if newPlugin == nil {
		t.FailNow()
	}
}

func CreateTestConfig() *Config {
	config := CreateConfig()
	config.ReturnCurrentStatusHeader = "X-Debug-Teapot"
	config.ReturnCurrentCountHeader = "X-Count-Teapots"
	config.TriggerOnHeaders = []string{"X-Teapot-Detected"}
	config.MinInstances = 2
	config.MinutesInJail = 2
	return config
}

func CreateTestPlugin(config *Config, ctx context.Context) (*TeapotHackerIsolationPlugin, error) {
	return NewTeapotHackerIsolationPlugin(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "teapot-header") {
			rw.Header().Add(config.TriggerOnHeaders[0], "1")
		}
		if strings.Contains(req.URL.Path, "418") {
			rw.WriteHeader(418)
		} else {
			rw.WriteHeader(200)
		}
	}), config, "testing")
}

func TestServeHTTP(t *testing.T) {
	ctx := context.Background()
	config := CreateTestConfig()
	newPlugin, err := CreateTestPlugin(config, ctx)
	if err != nil {
		t.FailNow()
	}

	req418, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/418-please", nil)
	req418.RemoteAddr = "testip"
	reqHeader, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/teapot-header-please", nil)
	reqHeader.RemoteAddr = "testip"
	reqInnocent, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/innocent", nil)
	reqInnocent.RemoteAddr = "testip"

	var recorder *httptest.ResponseRecorder
	var response *http.Response

	recorder = httptest.NewRecorder()
	// should not be blocked yet
	newPlugin.ServeHTTP(recorder, reqInnocent)
	response = recorder.Result()
	if response.StatusCode != 200 {
		t.Errorf("Got non-200 result, I should get 200 here, I got %d instead", response.StatusCode)
		return
	}
	if response.Header[config.ReturnCurrentCountHeader] == nil {
		t.Error("Didn't get count header like I expected")
		return
	}
	if response.Header[config.ReturnCurrentCountHeader][0] != "0" {
		t.Errorf("Didn't get count == I expected 0, got %s", response.Header[config.ReturnCurrentCountHeader][0])
		return
	}

	recorder = httptest.NewRecorder()
	newPlugin.ServeHTTP(recorder, req418)
	response = recorder.Result()
	if response.StatusCode != 418 {
		t.Errorf("Got non-418 result, I requested one though, I got %d instead", response.StatusCode)
		return
	}
	if response.Header[config.ReturnCurrentCountHeader] == nil {
		t.Error("Didn't get count header like I expected")
		return
	}
	if response.Header[config.ReturnCurrentCountHeader][0] != "1" {
		t.Errorf("Didn't get count == I expected 1, got %s", response.Header[config.ReturnCurrentCountHeader][0])
		return
	}

	recorder = httptest.NewRecorder()
	// but should not be blocked yet
	newPlugin.ServeHTTP(recorder, reqInnocent)
	response = recorder.Result()
	if response.StatusCode != 200 {
		t.Errorf("Got non-200 result, I should get 200 here, I got %d instead", response.StatusCode)
		return
	}
	if response.Header[config.ReturnCurrentCountHeader] == nil {
		t.Error("Didn't get count header like I expected")
		return
	}
	if response.Header[config.ReturnCurrentCountHeader][0] != "1" {
		t.Errorf("Didn't get count == I expected 1, got %s", response.Header[config.ReturnCurrentCountHeader][0])
		return
	}

	recorder = httptest.NewRecorder()
	// now try to trigger by header
	newPlugin.ServeHTTP(recorder, reqHeader)
	response = recorder.Result()
	if response.StatusCode != 418 {
		t.Errorf("Got non-418 result, I requested one though, I got %d instead", response.StatusCode)
		return
	}
	if response.Header[config.ReturnCurrentCountHeader] == nil {
		t.Error("Didn't get count header like I expected")
		return
	}
	if response.Header[config.ReturnCurrentCountHeader][0] != "2" {
		t.Errorf("Didn't get count == I expected 1, got %s", response.Header[config.ReturnCurrentCountHeader][0])
		return
	}

	recorder = httptest.NewRecorder()
	// should be blocked now
	newPlugin.ServeHTTP(recorder, reqInnocent)
	response = recorder.Result()
	if response.StatusCode != 418 {
		t.Errorf("Got non-418 result, I should be blocked by now, I got %d instead", response.StatusCode)
		return
	}
	if response.Header[config.ReturnCurrentCountHeader] == nil {
		t.Error("Didn't get count header like I expected")
		return
	}
	if response.Header[config.ReturnCurrentCountHeader][0] != "2" {
		t.Errorf("Didn't get count == I expected 1, got %s", response.Header[config.ReturnCurrentCountHeader][0])
		return
	}
}

func TestDetectIfHacker(t *testing.T) {
	ctx := context.Background()
	config := CreateTestConfig()
	newPlugin, err := CreateTestPlugin(config, ctx)
	if err != nil {
		t.FailNow()
	}

	resp := &http.Response{
		StatusCode: 418,
	}
	if !newPlugin.DetectIfHacker(resp) {
		t.FailNow()
	}

	resp = &http.Response{
		StatusCode: 200,
	}
	resp.Header = make(http.Header)
	resp.Header[config.TriggerOnHeaders[0]] = []string{"1"}
	if !newPlugin.DetectIfHacker(resp) {
		t.FailNow()
	}

	resp = &http.Response{
		StatusCode: 200,
	}
	if newPlugin.DetectIfHacker(resp) {
		t.FailNow()
	}
}
