package githuboauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// F-02: generateContextKey creates a cryptographically random string to use as
// a Gin context key. Since the key is generated at runtime and never exposed,
// external middleware cannot guess it to spoof API key authentication.
func generateContextKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("githuboauth: failed to generate random context key: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// F-I: Pre-hash API keys so constant-time comparison uses fixed-length
// inputs, preventing key length leakage via timing differences.
func hashAPIKey(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte(key))
}

// getApiKeyFunction returns a function that checks for API key authentication.
// It returns true if the request was handled (either valid key or invalid key with 401),
// and false if no API key was provided (allowing the next auth method to run).
// Keys not in allowedApiKeys are offered to resolve (optional), which reports
// whether it handled the request; otherwise the request is rejected with 401.
// F-02: The contextKey parameter is a random string generated at Init() time,
// preventing external middleware from spoofing API key authentication.
func getApiKeyFunction(allowedApiKeys []string, contextKey string, isAuthenticatedContextKey string, resolve func(*gin.Context, string) bool) func(*gin.Context) bool {
	// Pre-hash all valid keys at initialization time
	hashedKeys := make([][sha256.Size]byte, len(allowedApiKeys))
	for i, key := range allowedApiKeys {
		hashedKeys[i] = hashAPIKey(key)
	}

	return func(c *gin.Context) bool {
		// F-06: Check X-API-Key header first (raw key value)
		apiKeyHeaderValue := c.GetHeader("X-API-Key")

		// F-06: If no X-API-Key, check Authorization header with proper "Bearer " prefix (with space)
		if apiKeyHeaderValue == "" {
			auth := c.GetHeader("Authorization")
			if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
				apiKeyHeaderValue = after
			}
		}

		apiKeyHeaderValue = strings.TrimSpace(apiKeyHeaderValue)
		if apiKeyHeaderValue != "" {
			inputHash := hashAPIKey(apiKeyHeaderValue)
			for _, validHash := range hashedKeys {
				// F-I: Both sides are now sha256 digests (32 bytes), so
				// ConstantTimeCompare never leaks the original key length.
				if subtle.ConstantTimeCompare(inputHash[:], validHash[:]) == 1 {
					c.Set(contextKey, true)
					c.Set(isAuthenticatedContextKey, true)
					c.Next()
					return true
				}
			}
			if resolve != nil && resolve(c, apiKeyHeaderValue) {
				return true
			}
			// F-H: Use AbortWithStatusJSON instead of AbortWithError to avoid
			// leaking error details in the response body.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
				"code":    "unauthorized",
			})
			return true
		}
		return false
	}
}

// GetApiKeyAuthMiddleware returns a Gin middleware that requires a valid API key.
// Requests without a key or with an invalid key receive 401.
// API keys are pre-hashed once at initialization, not per-request.
func GetApiKeyAuthMiddleware(allowedApiKeys []string) gin.HandlerFunc {
	contextKey := generateContextKey()
	isAuthenticatedKey := generateContextKey()
	handler := getApiKeyFunction(allowedApiKeys, contextKey, isAuthenticatedKey, nil)
	return func(c *gin.Context) {
		handled := handler(c)
		if !handled {
			c.AbortWithStatus(401)
		}
	}
}
