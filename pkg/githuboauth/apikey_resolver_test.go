package githuboauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func resolverTestRouter(t *testing.T, resolve func(context.Context, string) *ResolvedAPIKey) (*gin.Engine, *Handle) {
	t.Helper()
	mock := newMockGitHubServer()
	t.Cleanup(mock.close)
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = []string{"static-key"}
	cfg.APIKeyResolver = resolve
	engine, handle, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	engine.GET("/whoami", func(c *gin.Context) {
		sess, ok := handle.GetSessionStore().GetSession(c)
		if !ok || sess.UserInformation == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no session"})
			return
		}
		access, _ := sess.GetData("access")
		c.JSON(http.StatusOK, gin.H{"login": sess.UserInformation.Profile.Login, "isAdmin": handle.IsAdmin(c), "access": access})
	})
	return engine, handle
}

func userWithTeams(login string, teams ...string) *ResolvedAPIKey {
	list := make([]Team, 0, len(teams))
	for _, slug := range teams {
		list = append(list, Team{Slug: slug, Organization: Organization{Login: "myorg"}})
	}
	return &ResolvedAPIKey{Login: login, Teams: &list}
}

func getWithKey(engine *gin.Engine, path, key string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-API-Key", key)
	engine.ServeHTTP(w, req)
	return w
}

func TestAPIKeyResolver(t *testing.T) {
	keys := map[string]*ResolvedAPIKey{
		"dev-key":      userWithTeams("dev", "developers"),
		"admin-key":    userWithTeams("boss", "developers", "admins"),
		"outsider-key": userWithTeams("outsider", "marketing"),
		"vouched-key":  {Login: "api-key:ci", Data: map[string]any{"access": "read_only"}},
	}
	engine, _ := resolverTestRouter(t, func(_ context.Context, key string) *ResolvedAPIKey {
		return keys[key]
	})

	tests := []struct {
		name, path, key string
		wantStatus      int
		wantBody        string
	}{
		{"resolved key authenticates as owner", "/whoami", "dev-key", http.StatusOK, `"login":"dev"`},
		{"resolved key is not admin", "/whoami", "dev-key", http.StatusOK, `"isAdmin":false`},
		{"resolved admin key is admin", "/whoami", "admin-key", http.StatusOK, `"isAdmin":true`},
		{"resolved non-admin key is blocked by admin middleware", "/admin/dashboard", "dev-key", http.StatusForbidden, ""},
		{"resolved admin key passes admin middleware", "/admin/dashboard", "admin-key", http.StatusOK, ""},
		{"static key still works", "/protected", "static-key", http.StatusOK, ""},
		{"owner without allowed team is forbidden", "/protected", "outsider-key", http.StatusForbidden, ""},
		{"unknown key is unauthorized", "/protected", "nope", http.StatusUnauthorized, ""},
		{"vouched key without teams skips team check", "/whoami", "vouched-key", http.StatusOK, `"login":"api-key:ci"`},
		{"vouched key carries data into the session", "/whoami", "vouched-key", http.StatusOK, `"access":"read_only"`},
		{"vouched key is never admin", "/admin/dashboard", "vouched-key", http.StatusForbidden, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := getWithKey(engine, tt.path, tt.key)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Fatalf("body %s does not contain %s", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestAPIKeyResolver_WithoutStaticKeys(t *testing.T) {
	mock := newMockGitHubServer()
	defer mock.close()
	cfg := mock.testConfig()
	cfg.AllowedAPIKeys = nil
	cfg.APIKeyResolver = func(_ context.Context, key string) *ResolvedAPIKey {
		if key == "only-key" {
			return userWithTeams("dev", "developers")
		}
		return nil
	}
	engine, _, err := setupTestRouter(cfg)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if w := getWithKey(engine, "/protected", "only-key"); w.Code != http.StatusOK {
		t.Fatalf("resolved key: status %d", w.Code)
	}
	if w := getWithKey(engine, "/protected", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key: status %d", w.Code)
	}
}
