package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGetRoutingPressureReturnsStrictPrivacySafeSchema(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, coreauth.NewManager(nil, &coreauth.LeastPressureSelector{}, nil))
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/routing-pressure", nil)
	h.GetRoutingPressure(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &body); errDecode != nil {
		t.Fatal(errDecode)
	}
	wantKeys := []string{"active_leases", "active_seats", "eligible_routes", "routing_events_dropped", "routing_events_rejected", "schema_version", "seats", "selector", "telemetry_instance"}
	gotKeys := make([]string, 0, len(body))
	for key := range body {
		gotKeys = append(gotKeys, key)
	}
	if !reflect.DeepEqual(sortedStrings(gotKeys), wantKeys) {
		t.Fatalf("response keys=%#v, want %#v", sortedStrings(gotKeys), wantKeys)
	}
	for _, sentinel := range []string{"auth_id", "account", "email", "token", "path", "model", "provider", "metadata"} {
		if strings.Contains(strings.ToLower(recorder.Body.String()), sentinel) {
			t.Fatalf("response contains forbidden %q field: %s", sentinel, recorder.Body.String())
		}
	}
}

func TestRoutingPressureRouteRequiresManagementAuthentication(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "pressure-management-key")
	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, coreauth.NewManager(nil, &coreauth.LeastPressureSelector{}, nil))
	router := gin.New()
	router.GET("/v0/management/routing-pressure", h.Middleware(), h.GetRoutingPressure)

	unauthorized := httptest.NewRecorder()
	unauthorizedRequest := httptest.NewRequest(http.MethodGet, "/v0/management/routing-pressure", nil)
	unauthorizedRequest.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(unauthorized, unauthorizedRequest)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	authorized := httptest.NewRecorder()
	authorizedRequest := httptest.NewRequest(http.MethodGet, "/v0/management/routing-pressure", nil)
	authorizedRequest.RemoteAddr = "127.0.0.1:1234"
	authorizedRequest.Header.Set("Authorization", "Bearer pressure-management-key")
	router.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}

func sortedStrings(values []string) []string {
	sort.Strings(values)
	return values
}
