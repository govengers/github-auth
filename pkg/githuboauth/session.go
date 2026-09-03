package githuboauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// F-14: Use sync.Once instead of init() to avoid global side effects on import
var registerGobOnce sync.Once

func ensureGobRegistered() {
	registerGobOnce.Do(func() {
		gob.Register(&oauth2.Token{})
	})
}

var (
	ErrSessionNotFound   = errors.New("session not found")
	ErrInvalidSession    = errors.New("invalid session data")
	ErrUserInfoNotCached = errors.New("user information not in cache")
)

const (
	userInfoCacheSize = 1000
	userInfoCacheTTL  = time.Minute
	pkceCacheSize     = 1000
	pkceCacheTTL      = 20 * time.Minute
)

type SessionStore struct {
	cookieStore   *sessions.CookieStore
	oauthConfig   *oauth2.Config
	cookieName    string
	userInfoCache *expirable.LRU[string, *UserInformation]
	// F-11: Server-side PKCE verifier storage (keyed by random cookie ID)
	pkceStore *expirable.LRU[string, string]
	// F-07: Optional token revocation callback, called asynchronously on logout
	onLogout func(*oauth2.Token)
	// F-15: Optional base transport for HTTP clients (used in tests to avoid
	// mutating http.DefaultTransport globally)
	baseTransport http.RoundTripper
	// Gin context key under which a session for a request authenticated via
	// Config.APIKeyResolver is stored (random per Init, see F-02).
	apiKeySessionContextKey string
}

// Session represents an authenticated user session.
// F-10: The mu field protects Data from concurrent access.
type Session struct {
	OAuthToken      *oauth2.Token
	UserInformation *UserInformation
	mu              sync.RWMutex
	Data            map[string]any
	store           *SessionStore
	// F-09: sessionID is a stable identifier stored in the cookie,
	// independent of the access token (which changes on refresh).
	sessionID string
}

type SessionStoreOptions struct {
	SecretKey     []byte
	EncryptionKey []byte
	OAuthConfig   *oauth2.Config
	CookieName    string
	CookieDomain  string
	CookieSecure  bool
	MaxAge        int
}

func NewSessionStore(options *SessionStoreOptions) (*SessionStore, error) {
	// F-14: Register gob types lazily instead of via init()
	ensureGobRegistered()

	if len(options.SecretKey) != 64 {
		return nil, errors.New("session secret key must be 64 bytes (for HMAC-SHA512)")
	}
	if len(options.EncryptionKey) != 32 {
		return nil, errors.New("session encryption key must be 32 bytes (for AES-256)")
	}

	store := sessions.NewCookieStore(options.SecretKey, options.EncryptionKey)

	store.Options = &sessions.Options{
		Path:     "/",
		Domain:   options.CookieDomain,
		MaxAge:   options.MaxAge,
		Secure:   options.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return &SessionStore{
		cookieStore:   store,
		oauthConfig:   options.OAuthConfig,
		cookieName:    options.CookieName,
		userInfoCache: expirable.NewLRU[string, *UserInformation](userInfoCacheSize, nil, userInfoCacheTTL),
		pkceStore:     expirable.NewLRU[string, string](pkceCacheSize, nil, pkceCacheTTL),
	}, nil
}

func (s *SessionStore) GetSession(c *gin.Context) (*Session, bool) {
	if s.apiKeySessionContextKey != "" {
		if v, ok := c.Get(s.apiKeySessionContextKey); ok {
			if sess, ok := v.(*Session); ok {
				return sess, true
			}
		}
	}
	gorillaSession, err := s.cookieStore.Get(c.Request, s.cookieName)
	if err != nil {
		log.Debug().Err(err).Msg("failed to get session from cookie store")
		return nil, false
	}

	if gorillaSession.IsNew {
		log.Debug().Msg("session is new, no existing session found")
		return nil, false
	}

	return s.sessionFromGorillaSession(gorillaSession)
}

func (s *SessionStore) CreateSession(c *gin.Context) (*Session, error) {
	log.Trace().Msg("creating new session")

	// F-09: Generate a stable session ID for cache keying
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	return &Session{
		Data:      make(map[string]any),
		store:     s,
		sessionID: sessionID,
	}, nil
}

func (s *SessionStore) Save(c *gin.Context, session *Session) error {
	gorillaSession, _ := s.cookieStore.Get(c.Request, s.cookieName)

	if session.OAuthToken != nil {
		gorillaSession.Values["oauth_token"] = session.OAuthToken
	}

	// F-09: Store the stable session ID in the cookie
	if session.sessionID != "" {
		gorillaSession.Values["session_id"] = session.sessionID

		if session.UserInformation != nil {
			s.userInfoCache.Add(session.sessionID, session.UserInformation)
		}
	}

	if err := gorillaSession.Save(c.Request, c.Writer); err != nil {
		log.Error().Err(err).Msg("failed to save session")
		return err
	}

	return nil
}

func (s *SessionStore) DestroySession(c *gin.Context) error {
	gorillaSession, _ := s.cookieStore.Get(c.Request, s.cookieName)

	// F-07: Revoke OAuth token (best-effort, fire-and-forget)
	if s.onLogout != nil {
		if token, ok := gorillaSession.Values["oauth_token"]; ok && token != nil {
			if t, ok := token.(*oauth2.Token); ok {
				go s.onLogout(t)
			}
		}
	}

	// F-09: Remove from cache by session ID
	if sid, ok := gorillaSession.Values["session_id"]; ok && sid != nil {
		if sessionID, ok := sid.(string); ok {
			s.userInfoCache.Remove(sessionID)
		}
	}

	gorillaSession.Options.MaxAge = -1

	return gorillaSession.Save(c.Request, c.Writer)
}

// F-11: StorePKCEVerifier stores a PKCE verifier server-side and returns a
// random opaque ID to be stored in the browser cookie. The verifier itself
// never leaves the server.
func (s *SessionStore) StorePKCEVerifier(verifier string) (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", err
	}
	s.pkceStore.Add(id, verifier)
	return id, nil
}

// F-11: GetPKCEVerifier retrieves a stored PKCE verifier by its opaque ID.
func (s *SessionStore) GetPKCEVerifier(id string) (string, bool) {
	return s.pkceStore.Get(id)
}

// F-11: ClearPKCEVerifier removes a PKCE verifier after use.
func (s *SessionStore) ClearPKCEVerifier(id string) {
	s.pkceStore.Remove(id)
}

func (s *SessionStore) sessionFromGorillaSession(gorillaSession *sessions.Session) (*Session, bool) {
	session := &Session{
		store: s,
		Data:  make(map[string]any),
	}

	if token, ok := gorillaSession.Values["oauth_token"]; ok && token != nil {
		if t, ok := token.(*oauth2.Token); ok {
			session.OAuthToken = t
		}
	}

	// F-09: Restore session ID from cookie
	if sid, ok := gorillaSession.Values["session_id"]; ok && sid != nil {
		if sessionID, ok := sid.(string); ok {
			session.sessionID = sessionID

			if userInfo, ok := s.userInfoCache.Get(sessionID); ok {
				session.UserInformation = userInfo
			}
		}
	}

	if session.OAuthToken == nil {
		return nil, false
	}

	return session, true
}

// GetSessionID returns the stable session identifier.
func (s *Session) GetSessionID() string {
	return s.sessionID
}

// HasUserInfo returns true if user information is available (cached).
func (s *Session) HasUserInfo() bool {
	return s.UserInformation != nil
}

// SetUserInfo caches user information for this session.
func (s *Session) SetUserInfo(userInfo *UserInformation) {
	s.UserInformation = userInfo
	if s.store != nil && s.sessionID != "" {
		s.store.userInfoCache.Add(s.sessionID, userInfo)
	}
}

// F-10: GetData safely reads a value from the session data map.
func (s *Session) GetData(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.Data[key]
	return val, ok
}

// F-10: SetData safely writes a value to the session data map.
func (s *Session) SetData(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Data[key] = value
}

// GetHttpClient returns an HTTP client that uses the session's OAuth token
// with automatic token refresh. The provided context is used for token refresh
// operations and should be the request context.
func (s *Session) GetHttpClient(ctx context.Context) *http.Client {
	if s.OAuthToken == nil || s.store == nil || s.store.oauthConfig == nil {
		return &http.Client{Timeout: 30 * time.Second}
	}

	tokenSource := s.store.oauthConfig.TokenSource(ctx, s.OAuthToken)

	transport := &oauth2.Transport{
		Source: tokenSource,
	}
	// F-15: Use injected base transport if available (e.g. in tests)
	if s.store.baseTransport != nil {
		transport.Base = s.store.baseTransport
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// GetToken returns the current OAuth token, potentially refreshing it.
// The provided context is used for token refresh operations.
func (s *Session) GetToken(ctx context.Context) (*oauth2.Token, error) {
	if s.OAuthToken == nil {
		return nil, errors.New("no oauth token in session")
	}

	if s.store == nil || s.store.oauthConfig == nil {
		return s.OAuthToken, nil
	}

	tokenSource := s.store.oauthConfig.TokenSource(ctx, s.OAuthToken)
	return tokenSource.Token()
}

// GenerateSessionSecretKey generates a 64-byte key for HMAC-SHA512 signing.
// Returns the raw key bytes ready to be passed to Config.SessionSecretKey.
func GenerateSessionSecretKey() ([]byte, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateSessionEncryptionKey generates a 32-byte key for AES-256 encryption.
// Returns the raw key bytes ready to be passed to Config.SessionEncryptionKey.
func GenerateSessionEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// F-B: EncodeKeyToBase64 encodes raw key bytes to a base64 string for storage
// in configuration files or environment variables.
func EncodeKeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// F-B: DecodeKeyFromBase64 decodes a base64-encoded string back to raw key bytes.
// Use this when loading keys from configuration files or environment variables.
func DecodeKeyFromBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// F-09: Generate a cryptographically random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
