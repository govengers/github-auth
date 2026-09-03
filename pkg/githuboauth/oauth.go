package githuboauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type oauthHandlerConfig struct {
	oauthConfig      *oauth2.Config
	gitHubConnector  *GitHubConnector
	allowedTeams     []string
	adminTeams       []string
	relevantTeams    []string
	apiKeyHandler    func(*gin.Context) bool
	cookieSecure     bool
	baseURL          string
	loginPath        string
	callbackPath     string
	userInfoPath     string
	logoutPath       string
	refreshTeamsPath string
	// F-02: Random context key for API key authentication, generated per Init()
	apiKeyContextKey          string
	isAuthenticatedContextKey string
	isAdminContextKey         string
	relevantTeamsContextKey   string
}

type oauthHandler struct {
	config *oauthHandlerConfig
	// F-08: Short-lived negative cache for sessions denied team access.
	// Prevents double GitHub API call amplification for unauthorized users.
	deniedSessionCache *expirable.LRU[string, struct{}]
}

const (
	deniedCacheSize = 1000
	deniedCacheTTL  = 30 * time.Second
)

func newOAuthHandler(config *oauthHandlerConfig) (*oauthHandler, error) {
	if len(config.allowedTeams) == 0 {
		return nil, errors.New("no allowed teams configured; specify at least one team in the form of '<org-name>/<team-slug>'")
	}

	return &oauthHandler{
		config:             config,
		deniedSessionCache: expirable.NewLRU[string, struct{}](deniedCacheSize, nil, deniedCacheTTL),
	}, nil
}

// absoluteURL prefixes path with the configured public base URL, if set.
// Behind a forward-auth proxy redirects must be absolute: the proxy resolves
// relative Location headers against its own upstream address.
func (h *oauthHandler) absoluteURL(path string) string {
	return h.config.baseURL + path
}

func (h *oauthHandler) getHandlersChain(s *SessionStore) gin.HandlersChain {
	return gin.HandlersChain{
		h.getCallbackHandler(s),
		h.getLoginHandler(s),
		h.getLogoutHandler(s),
		h.getUserInfoHandler(s),
		h.getRefreshTeamsHandler(s),
		h.getAuthHandler(s),
	}
}

func (h *oauthHandler) hasAllowedTeam(teams *[]Team) bool {
	teamSlugs := GetTeamSlugs(teams)
	for _, allowedTeam := range h.config.allowedTeams {
		if slices.Contains(teamSlugs, allowedTeam) {
			return true
		}
	}
	return false
}

// getAPIKeyResolverFunc adapts Config.APIKeyResolver for getApiKeyFunction.
// A resolved key authenticates the request as the resolved principal: GetSession
// yields a session for it, and its teams (if any) go through the same checks as
// an OAuth session.
func (h *oauthHandler) getAPIKeyResolverFunc(s *SessionStore, resolve func(context.Context, string) *ResolvedAPIKey) func(*gin.Context, string) bool {
	if resolve == nil {
		return nil
	}
	return func(c *gin.Context, key string) bool {
		resolved := resolve(c.Request.Context(), key)
		if resolved == nil || resolved.Login == "" {
			return false
		}
		if resolved.Teams != nil && !h.hasAllowedTeam(resolved.Teams) {
			log.Debug().Str("login", resolved.Login).Msg("api key principal is not member of any allowed team")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "access denied",
				"code":    "forbidden",
			})
			return true
		}
		data := map[string]any{}
		for k, v := range resolved.Data {
			data[k] = v
		}
		c.Set(s.apiKeySessionContextKey, &Session{
			UserInformation: &UserInformation{
				Profile: &UserProfile{Login: resolved.Login},
				Teams:   resolved.Teams,
			},
			Data:  data,
			store: s,
		})
		c.Set(h.config.isAuthenticatedContextKey, true)
		c.Set(h.config.isAdminContextKey, h.isUserAdmin(resolved.Teams))
		c.Set(h.config.relevantTeamsContextKey, h.getRelevantTeams(resolved.Teams))
		log.Trace().Str("login", resolved.Login).Msg("request authenticated via resolved api key")
		c.Next()
		return true
	}
}

func (h *oauthHandler) isUserAdmin(teams *[]Team) bool {
	if teams == nil || len(h.config.adminTeams) == 0 {
		return false
	}
	teamSlugs := GetTeamSlugs(teams)
	for _, adminTeam := range h.config.adminTeams {
		if slices.Contains(teamSlugs, adminTeam) {
			return true
		}
	}
	return false
}

func (h *oauthHandler) getRelevantTeams(teams *[]Team) []string {
	if teams == nil || len(h.config.relevantTeams) == 0 {
		return nil
	}
	teamSlugs := GetTeamSlugs(teams)
	var relevant []string
	for _, rt := range h.config.relevantTeams {
		if slices.Contains(teamSlugs, rt) {
			relevant = append(relevant, rt)
		}
	}
	return relevant
}

func (h *oauthHandler) getLoginHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path != h.config.loginPath {
			c.Next()
			return
		}

		log.Debug().Msg("executing oauth login handler")

		oauthState, err := generateStateOauthCookie(c.Writer, h.config.cookieSecure)
		if err != nil {
			log.Error().Err(err).Msg("failed to generate oauth state")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// F-E: Generate PKCE verifier
		verifier := oauth2.GenerateVerifier()

		// F-11: Store verifier server-side; only put opaque ID in cookie
		pkceID, err := s.StorePKCEVerifier(verifier)
		if err != nil {
			log.Error().Err(err).Msg("failed to store PKCE verifier")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		setPKCECookie(c.Writer, pkceID, h.config.cookieSecure)

		oidcProviderRedirectUrl := h.config.oauthConfig.AuthCodeURL(oauthState, oauth2.S256ChallengeOption(verifier))
		c.Redirect(http.StatusTemporaryRedirect, oidcProviderRedirectUrl)
		c.Abort()
	}
}

func (h *oauthHandler) getCallbackHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path != h.config.callbackPath {
			c.Next()
			return
		}

		log.Debug().Msg("executing oauth callback handler")

		err := validateOAuthState(c)
		if err != nil {
			return
		}

		// F-12: Clear the oauthstate cookie after successful validation
		clearOAuthStateCookie(c.Writer, h.config.cookieSecure)

		// F-11: Retrieve PKCE verifier from server-side store via opaque cookie ID
		pkceCookieID, err := c.Cookie("pkce_verifier")
		if err != nil || pkceCookieID == "" {
			log.Warn().Msg("missing PKCE verifier cookie")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		clearPKCECookie(c.Writer, h.config.cookieSecure)

		pkceVerifier, ok := s.GetPKCEVerifier(pkceCookieID)
		if !ok {
			log.Warn().Msg("PKCE verifier not found or expired")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		s.ClearPKCEVerifier(pkceCookieID)

		log.Debug().Msg("oauth state is valid")
		log.Debug().Msg("exchanging token exchange")
		oauthToken, err := doTokenExchange(h.config.oauthConfig, c, pkceVerifier, s.baseTransport)
		if err != nil {
			return
		}

		log.Debug().Msg("token exchange successful")

		session, err := s.CreateSession(c)
		if err != nil {
			log.Error().Err(err).Msg("failed to create session")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		session.OAuthToken = oauthToken

		userInformation, err := getUserInformation(h.config.gitHubConnector, c, session.GetHttpClient(c.Request.Context()))
		if err != nil {
			return
		}

		log.Debug().Msg("saving session with user information")
		session.UserInformation = userInformation

		// F-15: Handle save error instead of silently discarding
		if err := s.Save(c, session); err != nil {
			log.Error().Err(err).Msg("failed to save session after login")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Set("session", session)

		log.Debug().Msg("redirecting to /")
		c.Redirect(http.StatusTemporaryRedirect, h.absoluteURL("/"))
		c.Abort()
	}
}

func (h *oauthHandler) getAuthHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.config.apiKeyHandler != nil {
			handled := h.config.apiKeyHandler(c)
			if handled {
				log.Trace().Msg("api key handler passed request")
				return
			}
		}

		sess, ok := s.GetSession(c)
		if !ok {
			// F-11: Return 401 JSON for API/XHR requests instead of redirect
			if isAPIRequest(c) {
				log.Debug().Msg("no session found in auth handler for API request, returning 401")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"message": "authentication required",
					"code":    "unauthorized",
				})
				return
			}
			log.Debug().Msg("no session found in auth handler. redirecting to login")
			c.Redirect(http.StatusTemporaryRedirect, h.absoluteURL(h.config.loginPath))
			c.Abort()
			return
		}

		if !sess.HasUserInfo() {
			log.Debug().Msg("user info not in cache, fetching from GitHub")
			userInformation, err := getUserInformation(h.config.gitHubConnector, c, sess.GetHttpClient(c.Request.Context()))
			if err != nil {
				return
			}
			sess.SetUserInfo(userInformation)
		}

		checkForAllowedTeam := func() bool {
			return h.hasAllowedTeam(sess.UserInformation.Teams)
		}

		setAuthContext := func() {
			c.Set(h.config.isAuthenticatedContextKey, true)
			c.Set(h.config.isAdminContextKey, h.isUserAdmin(sess.UserInformation.Teams))
			c.Set(h.config.relevantTeamsContextKey, h.getRelevantTeams(sess.UserInformation.Teams))
		}

		if checkForAllowedTeam() {
			// F-08: Clear negative cache entry if user is now authorized
			if sess.sessionID != "" {
				h.deniedSessionCache.Remove(sess.sessionID)
			}
			setAuthContext()
			c.Next()
			return
		}

		// F-08: Check negative cache before re-querying GitHub API
		if sess.sessionID != "" {
			if _, denied := h.deniedSessionCache.Get(sess.sessionID); denied {
				log.Debug().Msg("session in denied cache, skipping re-query")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"message": "access denied",
					"code":    "forbidden",
				})
				return
			}
		}

		log.Warn().Msg("user is not member of any of the allowed teams. re-querying user information")
		userInformation, err := getUserInformation(h.config.gitHubConnector, c, sess.GetHttpClient(c.Request.Context()))
		if err != nil {
			return
		}
		sess.SetUserInfo(userInformation)

		log.Trace().Msg("re-checking if user is member of allowed teams")
		if checkForAllowedTeam() {
			log.Trace().Msg("user is member of allowed teams. pass")
			setAuthContext()
			c.Next()
			return
		}

		// F-08: Cache the denial to prevent re-querying for 30 seconds
		if sess.sessionID != "" {
			h.deniedSessionCache.Add(sess.sessionID, struct{}{})
		}

		log.Warn().Strs("allowedTeams", h.config.allowedTeams).Msg("user not in any allowed team")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"message": "access denied",
			"code":    "forbidden",
		})
	}
}

func (h *oauthHandler) getUserInfoHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path != h.config.userInfoPath {
			c.Next()
			return
		}

		log.Trace().Msg("executing oauth userinfo handler")

		sess, ok := s.GetSession(c)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if !sess.HasUserInfo() {
			log.Debug().Msg("user info not in cache, fetching from GitHub")
			userInformation, err := getUserInformation(h.config.gitHubConnector, c, sess.GetHttpClient(c.Request.Context()))
			if err != nil {
				return
			}
			sess.SetUserInfo(userInformation)
		}

		// F-13: Do not expose allowedTeams/adminTeams in the response
		// F-J: Only return necessary profile fields to avoid PII leakage
		c.JSON(http.StatusOK, gin.H{
			"sub":         sess.UserInformation.Profile.Login,
			"userProfile": safeUserProfile(sess.UserInformation.Profile),
			"teams":       sess.UserInformation.Teams,
			"isAdmin":     h.isUserAdmin(sess.UserInformation.Teams),
		})
		c.Abort()
	}
}

func (h *oauthHandler) getRefreshTeamsHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path != h.config.refreshTeamsPath || c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		log.Debug().Msg("executing oauth refresh-teams handler")

		sess, ok := s.GetSession(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		userInformation, err := getUserInformation(h.config.gitHubConnector, c, sess.GetHttpClient(c.Request.Context()))
		if err != nil {
			log.Error().Err(err).Msg("failed to refresh teams from GitHub")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh teams"})
			return
		}

		sess.SetUserInfo(userInformation)

		// F-08: Clear negative cache on team refresh so authorization is re-evaluated
		if sess.sessionID != "" {
			h.deniedSessionCache.Remove(sess.sessionID)
		}

		// F-13: Do not expose allowedTeams/adminTeams in the response
		c.JSON(http.StatusOK, gin.H{
			"teams":   userInformation.Teams,
			"isAdmin": h.isUserAdmin(userInformation.Teams),
		})
		c.Abort()
	}
}

// F-18: Logout endpoint to destroy sessions
func (h *oauthHandler) getLogoutHandler(s *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path != h.config.logoutPath || c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		log.Debug().Msg("executing oauth logout handler")

		// F-06: Validate Origin header for CSRF protection.
		// If Origin is present and doesn't match the request host, reject.
		// SameSite=Lax already mitigates most cross-site attacks, but this
		// adds defense-in-depth for older browsers and same-site attackers.
		if origin := c.GetHeader("Origin"); origin != "" {
			originURL, err := url.Parse(origin)
			if err != nil || originURL.Host != c.Request.Host {
				log.Warn().Str("origin", origin).Str("host", c.Request.Host).Msg("logout CSRF: origin mismatch")
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		if err := s.DestroySession(c); err != nil {
			log.Error().Err(err).Msg("failed to destroy session")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if isAPIRequest(c) {
			c.JSON(http.StatusOK, gin.H{"message": "logged out"})
		} else {
			c.Redirect(http.StatusTemporaryRedirect, h.absoluteURL(h.config.loginPath))
		}
		c.Abort()
	}
}

// --- utility functions ---

func generateStateOauthCookie(w http.ResponseWriter, secure bool) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  time.Now().Add(20 * time.Minute),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	return state, nil
}

// F-12: Clear the oauthstate cookie after consumption
func clearOAuthStateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthstate",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

// F-11: Cookie now stores an opaque ID referencing server-side PKCE verifier
func setPKCECookie(w http.ResponseWriter, pkceID string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    pkceID,
		Expires:  time.Now().Add(20 * time.Minute),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func clearPKCECookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func validateOAuthState(c *gin.Context) error {
	oauthState, err := c.Cookie("oauthstate")
	if err != nil {
		log.Warn().Err(err).Msg("failed to get oauth state from cookie")
		c.AbortWithStatus(http.StatusUnauthorized)
		return err
	}
	// F-01: Use constant-time comparison to prevent timing oracle attacks
	if subtle.ConstantTimeCompare([]byte(c.Request.FormValue("state")), []byte(oauthState)) != 1 {
		log.Warn().Msg("invalid oauth state")
		c.AbortWithStatus(http.StatusUnauthorized)
		return errors.New("invalid oauth state")
	}
	return nil
}

// F-15: Accept optional base transport for token exchange (avoids global transport mutation in tests)
func doTokenExchange(oauthConfig *oauth2.Config, c *gin.Context, pkceVerifier string, baseTransport http.RoundTripper) (*oauth2.Token, error) {
	code := c.Request.FormValue("code")
	ctx := c.Request.Context()
	// F-15: If a custom base transport is provided, inject it via context
	// so the oauth2 library uses it instead of http.DefaultTransport
	if baseTransport != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: baseTransport,
			Timeout:   30 * time.Second,
		})
	}
	// F-E: Include PKCE verifier in token exchange
	oauthToken, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		log.Error().Err(err).Msg("failed to exchange code")
		c.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	return oauthToken, nil
}

func getUserInformation(connector *GitHubConnector, c *gin.Context, client *http.Client) (*UserInformation, error) {
	log.Trace().Msg("getting user information")
	userInformation, err := connector.GetUserInformation(c.Request.Context(), client)
	if err != nil {
		log.Error().Err(err).Msg("failed to get user information")
		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, err
	}
	return userInformation, nil
}

// F-J: Return only the profile fields the frontend needs, filtering out PII
// (email, bio, location, 2FA status, disk usage, private repo counts, etc.)
func safeUserProfile(p *UserProfile) gin.H {
	if p == nil {
		return gin.H{}
	}
	return gin.H{
		"login":     p.Login,
		"id":        p.ID,
		"avatarUrl": p.AvatarURL,
		"name":      p.Name,
		"htmlUrl":   p.HTMLURL,
	}
}

// F-11: Detect API/XHR requests that should get JSON errors instead of redirects
func isAPIRequest(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	if strings.HasPrefix(c.Request.URL.Path, "/api/") {
		return true
	}
	return false
}
