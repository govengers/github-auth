package githuboauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

const testContextKey = "test-context-key"
const testIsAuthenticatedKey = "test-is-authenticated-key"

func TestAPIKeyValidation_ValidKey_XAPIKey(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key-123"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("X-API-Key", "test-key-123")

	handled := handler(c)
	if !handled {
		t.Fatal("expected handler to return true for valid key")
	}
	if w.Code == http.StatusUnauthorized {
		t.Error("expected non-401 status for valid key")
	}
	val, exists := c.Get(testContextKey)
	if !exists || val != true {
		t.Error("expected context key to be set to true")
	}
}

func TestAPIKeyValidation_ValidKey_BearerAuth(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key-456"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("Authorization", "Bearer test-key-456")

	handled := handler(c)
	if !handled {
		t.Fatal("expected handler to return true for valid bearer key")
	}
	val, exists := c.Get(testContextKey)
	if !exists || val != true {
		t.Error("expected context key to be set to true for bearer auth")
	}
}

func TestAPIKeyValidation_InvalidKey_Returns401(t *testing.T) {
	handler := getApiKeyFunction([]string{"correct-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("X-API-Key", "wrong-key")

	handled := handler(c)
	if !handled {
		t.Fatal("expected handler to return true for invalid key")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyValidation_InvalidKey_NoErrorLeak(t *testing.T) {
	handler := getApiKeyFunction([]string{"correct-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("X-API-Key", "wrong-key")

	handler(c)

	// F-H: Verify response body does not contain "invalid API key"
	body := w.Body.String()
	var resp map[string]any
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if msg, ok := resp["message"].(string); ok {
		if msg == "invalid API key" {
			t.Error("response leaks 'invalid API key' error message")
		}
	}
}

func TestAPIKeyValidation_NoKey_PassesThrough(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)

	handled := handler(c)
	if handled {
		t.Error("expected handler to return false when no key provided")
	}
}

func TestAPIKeyValidation_EmptyBearer(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("Authorization", "Bearer ")

	handled := handler(c)
	if handled {
		t.Error("expected handler to return false for empty bearer value")
	}
}

func TestAPIKeyValidation_BearerWithoutSpace(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
	c.Request.Header.Set("Authorization", "Bearertest-key")

	handled := handler(c)
	if handled {
		t.Error("expected handler to return false for malformed bearer prefix")
	}
}

func TestAPIKeyValidation_MultipleKeys(t *testing.T) {
	handler := getApiKeyFunction([]string{"key-one", "key-two", "key-three"}, testContextKey, testIsAuthenticatedKey, nil)

	for _, key := range []string{"key-one", "key-two", "key-three"} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("X-API-Key", key)

		handled := handler(c)
		if !handled {
			t.Errorf("expected handler to accept key %q", key)
		}
		val, exists := c.Get(testContextKey)
		if !exists || val != true {
			t.Errorf("expected context key set for %q", key)
		}
	}
}

func TestAPIKeyValidation_WhitespaceTrimmingKey(t *testing.T) {
	handler := getApiKeyFunction([]string{"test-key"}, testContextKey, testIsAuthenticatedKey, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-API-Key", "  test-key  ")

	handled := handler(c)
	if !handled {
		t.Error("expected handler to trim whitespace and accept key")
	}
}

func TestGetApiKeyAuthMiddleware_NoKey_Returns401(t *testing.T) {
	mw := GetApiKeyAuthMiddleware([]string{"valid-key"})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	mw(c)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
