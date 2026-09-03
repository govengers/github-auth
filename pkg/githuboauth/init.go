package githuboauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// Config holds all configuration needed to initialize GitHub OAuth.
type Config struct {
	// OAuth2 settings
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	AuthURL       string // e.g. https://github.com/login/oauth/authorize
	TokenURL      string // e.g. https://github.com/login/oauth/access_token
	DeviceAuthURL string // optional

	// GitHub API base URL. Defaults to https://api.github.com.
	// Must use HTTPS. Set this to your GitHub Enterprise API URL for GHE support,
	// e.g. https://github.example.com/api/v3
	GitHubAPIBaseURL string

	// Team-based authorization.
	// Teams are specified in "org/team-slug" format (case-insensitive).
	AllowedTeams []string // at least one required
	AdminTeams   []string // optional

	// Relevant teams for context enrichment (optional).
	// When configured, the middleware sets matching team slugs on the Gin context
	// for downstream handlers to perform fine-grained authorization.
	// Teams are specified in "org/team-slug" format (case-insensitive).
	RelevantTeams []string

	// API key authentication (optional fallback).
	// Requests with a valid API key bypass OAuth.
	AllowedAPIKeys []string

	// APIKeyResolver resolves a presented API key that is not in AllowedAPIKeys
	// to the principal behind it (optional). Return nil for unknown or revoked keys.
	// See ResolvedAPIKey for how the result maps onto the request's auth state.
	// Unlike AllowedAPIKeys, resolved keys never bypass GetAdminMiddleware.
	APIKeyResolver func(ctx context.Context, key string) *ResolvedAPIKey

	// Session cookie encryption keys.
	// SecretKey must be 64 bytes (for HMAC-SHA512 signing).
	// EncryptionKey must be 32 bytes (for AES-256 encryption).
	SessionSecretKey     []byte
	SessionEncryptionKey []byte

	// Session cookie settings.
	CookieName   string // defaults to "session_id"
	CookieDomain string // defaults to "localhost"

	// F-N: SessionMaxAge as pointer to distinguish "not set" (nil -> default 7 days)
	// from explicitly zero (0 -> session cookie, expires on browser close).
	SessionMaxAge *int // seconds, nil defaults to 604800 (7 days)

	// F-05: CookieSecure defaults to true (safe-by-default).
	// Set CookieInsecure to true ONLY for local development without HTTPS.
	CookieInsecure bool

	// Public base URL of the application (optional), e.g. https://app.example.com.
	// When set, login redirects use absolute URLs. Required behind forward-auth
	// proxies (e.g. Traefik forwardAuth): the proxy resolves relative Location
	// headers against its own upstream address instead of the public host.
	BaseURL string

	// Route paths (optional, defaults shown).
	LoginPath        string // defaults to /auth/login
	CallbackPath     string // defaults to /auth/callback
	UserInfoPath     string // defaults to /auth/userinfo
	LogoutPath       string // defaults to /auth/logout
	RefreshTeamsPath string // defaults to /auth/refresh-teams
}

// ResolvedAPIKey is the principal behind an application-issued API key.
type ResolvedAPIKey struct {
	// Login becomes the session's Profile.Login (attribution), e.g. "api-key:ci".
	Login string
	// Teams drive the allowed-team check, admin status and relevant teams exactly
	// like an OAuth session. nil skips the team check and never grants admin:
	// the application vouches for the key itself.
	Teams *[]Team
	// Data is copied into the session's Data map for the application's own use,
	// e.g. an access level. Read it back via GetSession(c).GetData(key).
	Data map[string]any
}

// Handle provides access to the initialized OAuth system.
type Handle struct {
	handler      *oauthHandler
	sessionStore *SessionStore
	connector    *GitHubConnector
	// Context keys for reading auth state set by middleware
	isAuthenticatedContextKey string
	isAdminContextKey         string
	relevantTeamsContextKey   string
}

// IsUserAdmin checks if the given teams include any admin team.
func (h *Handle) IsUserAdmin(teams *[]Team) bool {
	return h.handler.isUserAdmin(teams)
}

// GetAllowedTeams returns the configured allowed teams (normalized to lowercase).
func (h *Handle) GetAllowedTeams() []string {
	return h.handler.config.allowedTeams
}

// GetAdminTeams returns the configured admin teams (normalized to lowercase).
func (h *Handle) GetAdminTeams() []string {
	return h.handler.config.adminTeams
}

// GetRelevantTeamConfig returns the configured relevant teams (normalized to lowercase).
func (h *Handle) GetRelevantTeamConfig() []string {
	return h.handler.config.relevantTeams
}

// IsAuthenticated returns true if the current request was authenticated
// by the OAuth middleware (via session or API key).
func (h *Handle) IsAuthenticated(c *gin.Context) bool {
	v, exists := c.Get(h.isAuthenticatedContextKey)
	if !exists {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// IsAdmin returns true if the authenticated user is a member of any admin team.
// For API key authenticated requests this returns false (no user context).
func (h *Handle) IsAdmin(c *gin.Context) bool {
	v, exists := c.Get(h.isAdminContextKey)
	if !exists {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// GetRelevantTeams returns the subset of configured RelevantTeams that the
// authenticated user is a member of. Returns nil for API key authenticated
// requests or when no RelevantTeams are configured.
func (h *Handle) GetRelevantTeams(c *gin.Context) []string {
	v, exists := c.Get(h.relevantTeamsContextKey)
	if !exists {
		return nil
	}
	teams, ok := v.([]string)
	if !ok {
		return nil
	}
	return teams
}

// GetSessionStore returns the session store.
func (h *Handle) GetSessionStore() *SessionStore {
	return h.sessionStore
}

// GetGitHubConnector returns the GitHub connector for making additional API calls.
func (h *Handle) GetGitHubConnector() *GitHubConnector {
	return h.connector
}

// GetAdminMiddleware returns a Gin middleware that restricts access to admin users.
// Requests that were authenticated via a validated API key bypass the admin check.
// OAuth users must be members of an admin team.
func (h *Handle) GetAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// F-02: Use random context key from handler config instead of guessable constant
		if authenticated, exists := c.Get(h.handler.config.apiKeyContextKey); exists && authenticated == true {
			log.Trace().Msg("admin middleware: request authenticated via valid API key, bypassing admin check")
			c.Next()
			return
		}

		sess, ok := h.sessionStore.GetSession(c)
		if !ok {
			log.Debug().Msg("admin middleware: no session found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
				"code":    "unauthorized",
			})
			return
		}

		if sess.UserInformation == nil {
			log.Debug().Msg("admin middleware: no user information in session")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
				"code":    "unauthorized",
			})
			return
		}

		if !h.handler.isUserAdmin(sess.UserInformation.Teams) {
			log.Debug().Msg("admin middleware: user is not an admin")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "admin access required",
				"code":    "forbidden",
			})
			return
		}

		log.Trace().Msg("admin middleware: user is admin, allowing access")
		c.Next()
	}
}

// GetMiddleware returns the middleware chain for manual route registration.
// Use this when you need to apply the OAuth middleware to specific routes
// rather than globally via Init().
func (h *Handle) GetMiddleware() gin.HandlersChain {
	return h.handler.getHandlersChain(h.sessionStore)
}

// New creates a Handle without registering middleware on any engine.
// Use GetMiddleware() to obtain the middleware chain for manual registration.
func New(cfg *Config) (*Handle, error) {
	return newHandle(cfg)
}

// Init registers all OAuth routes and middleware on the provided gin.Engine.
// It returns a Handle for querying auth state (admin checks, session access, etc.).
func Init(engine *gin.Engine, cfg *Config) (*Handle, error) {
	h, err := newHandle(cfg)
	if err != nil {
		return nil, err
	}
	engine.Use(h.GetMiddleware()...)
	return h, nil
}

func newHandle(cfg *Config) (*Handle, error) {
	// Validate required fields
	if cfg.ClientID == "" {
		return nil, errors.New("ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("ClientSecret is required")
	}
	if cfg.RedirectURI == "" {
		return nil, errors.New("RedirectURI is required")
	}
	if cfg.AuthURL == "" {
		return nil, errors.New("AuthURL is required")
	}
	if cfg.TokenURL == "" {
		return nil, errors.New("TokenURL is required")
	}

	// F-17: Warn if scopes don't include read:org (needed for team fetching)
	if len(cfg.Scopes) == 0 {
		log.Warn().Msg("no OAuth scopes configured; read:org is typically required for team-based authorization")
	}

	// F-05: CookieSecure defaults to true; CookieInsecure is the explicit opt-out
	cookieSecure := !cfg.CookieInsecure
	if cfg.CookieInsecure {
		log.Warn().Msg("CookieInsecure is true: session cookies will be sent over plain HTTP. This is insecure for production use.")
	}

	// F-07: Normalize team lists to lowercase for case-insensitive comparison
	for i, t := range cfg.AllowedTeams {
		cfg.AllowedTeams[i] = strings.ToLower(t)
	}
	for i, t := range cfg.AdminTeams {
		cfg.AdminTeams[i] = strings.ToLower(t)
	}
	for i, t := range cfg.RelevantTeams {
		cfg.RelevantTeams[i] = strings.ToLower(t)
	}

	// Apply defaults
	if cfg.GitHubAPIBaseURL == "" {
		cfg.GitHubAPIBaseURL = "https://api.github.com"
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session_id"
	}
	if cfg.CookieDomain == "" {
		cfg.CookieDomain = "localhost"
	}
	// F-N: Distinguish nil (use default) from explicit 0 (session cookie)
	sessionMaxAge := 604800 // 7 days default
	if cfg.SessionMaxAge != nil {
		sessionMaxAge = *cfg.SessionMaxAge
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/auth/login"
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = "/auth/callback"
	}
	if cfg.UserInfoPath == "" {
		cfg.UserInfoPath = "/auth/userinfo"
	}
	if cfg.LogoutPath == "" {
		cfg.LogoutPath = "/auth/logout"
	}
	if cfg.RefreshTeamsPath == "" {
		cfg.RefreshTeamsPath = "/auth/refresh-teams"
	}
	if cfg.BaseURL != "" {
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
		if u, err := url.Parse(cfg.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errors.New("BaseURL must be an absolute URL, e.g. https://app.example.com")
		}
	}

	log.Info().Msg("initializing GitHub OAuth middleware")

	oauthConfig := &oauth2.Config{
		RedirectURL:  cfg.RedirectURI,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:       cfg.AuthURL,
			TokenURL:      cfg.TokenURL,
			DeviceAuthURL: cfg.DeviceAuthURL,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}

	sessionStore, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     cfg.SessionSecretKey,
		EncryptionKey: cfg.SessionEncryptionKey,
		OAuthConfig:   oauthConfig,
		CookieName:    cfg.CookieName,
		CookieDomain:  cfg.CookieDomain,
		CookieSecure:  cookieSecure,
		MaxAge:        sessionMaxAge,
	})
	if err != nil {
		return nil, err
	}

	// F-07: Configure best-effort token revocation on logout.
	// Uses GitHub's DELETE /applications/{client_id}/token endpoint with Basic auth.
	apiBaseURL := cfg.GitHubAPIBaseURL
	clientID := cfg.ClientID
	clientSecret := cfg.ClientSecret
	sessionStore.onLogout = func(token *oauth2.Token) {
		if token == nil || token.AccessToken == "" {
			return
		}
		revokeURL, err := url.JoinPath(apiBaseURL, "applications", clientID, "token")
		if err != nil {
			log.Error().Err(err).Msg("failed to construct token revocation URL")
			return
		}
		body, _ := json.Marshal(map[string]string{"access_token": token.AccessToken})
		req, err := http.NewRequest(http.MethodDelete, revokeURL, bytes.NewReader(body))
		if err != nil {
			log.Error().Err(err).Msg("failed to create token revocation request")
			return
		}
		req.SetBasicAuth(clientID, clientSecret)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Error().Err(err).Msg("failed to revoke OAuth token")
			return
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			log.Debug().Msg("successfully revoked GitHub OAuth token")
		} else {
			log.Warn().Int("status", resp.StatusCode).Msg("unexpected status from token revocation")
		}
	}

	// F-03: NewGitHubConnector now validates the URL and returns an error
	connector, err := NewGitHubConnector(&GitHubConnectorConfig{
		ApiBaseURL: cfg.GitHubAPIBaseURL,
	})
	if err != nil {
		return nil, err
	}

	// F-02: Generate random context key for API key authentication
	apiKeyContextKey := generateContextKey()
	isAuthenticatedContextKey := generateContextKey()
	isAdminContextKey := generateContextKey()
	relevantTeamsContextKey := generateContextKey()

	handler, err := newOAuthHandler(&oauthHandlerConfig{
		oauthConfig:               oauthConfig,
		gitHubConnector:           connector,
		allowedTeams:              cfg.AllowedTeams,
		adminTeams:                cfg.AdminTeams,
		relevantTeams:             cfg.RelevantTeams,
		cookieSecure:              cookieSecure,
		baseURL:                   cfg.BaseURL,
		loginPath:                 cfg.LoginPath,
		callbackPath:              cfg.CallbackPath,
		userInfoPath:              cfg.UserInfoPath,
		logoutPath:                cfg.LogoutPath,
		refreshTeamsPath:          cfg.RefreshTeamsPath,
		apiKeyContextKey:          apiKeyContextKey,
		isAuthenticatedContextKey: isAuthenticatedContextKey,
		isAdminContextKey:         isAdminContextKey,
		relevantTeamsContextKey:   relevantTeamsContextKey,
	})
	if err != nil {
		return nil, err
	}

	if len(cfg.AllowedAPIKeys) > 0 || cfg.APIKeyResolver != nil {
		sessionStore.apiKeySessionContextKey = generateContextKey()
		handler.config.apiKeyHandler = getApiKeyFunction(
			cfg.AllowedAPIKeys, apiKeyContextKey, isAuthenticatedContextKey,
			handler.getAPIKeyResolverFunc(sessionStore, cfg.APIKeyResolver),
		)
	}

	return &Handle{
		handler:                   handler,
		sessionStore:              sessionStore,
		connector:                 connector,
		isAuthenticatedContextKey: isAuthenticatedContextKey,
		isAdminContextKey:         isAdminContextKey,
		relevantTeamsContextKey:   relevantTeamsContextKey,
	}, nil
}
