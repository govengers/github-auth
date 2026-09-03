# githuboauth

A Go library for GitHub OAuth2 authentication with team-based authorization, built on [Gin](https://github.com/gin-gonic/gin).

## Install

```bash
go get github.com/mxcd/github-fwd-auth/pkg/githuboauth
```

## Features

- GitHub OAuth2 with PKCE (S256)
- Team-based access control (`org/team-slug` format, case-insensitive)
- Admin team authorization
- API key fallback authentication (timing-safe, pre-hashed)
- Encrypted session cookies (HMAC-SHA512 + AES-256)
- User info caching with LRU eviction
- Token refresh and revocation on logout
- GitHub Enterprise support

## Quick Start

### Option A: Auto-register routes and middleware

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/mxcd/github-fwd-auth/pkg/githuboauth"
)

func main() {
    router := gin.Default()

    handle, err := githuboauth.Init(router, &githuboauth.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURI:  "https://example.com/auth/callback",
        Scopes:       []string{"user:email", "read:org"},
        AuthURL:      "https://github.com/login/oauth/authorize",
        TokenURL:     "https://github.com/login/oauth/access_token",
        AllowedTeams: []string{"my-org/my-team"},

        SessionSecretKey:     secretKey,     // 64 bytes
        SessionEncryptionKey: encryptionKey, // 32 bytes
        CookieDomain:         "example.com",
    })
    if err != nil {
        panic(err)
    }

    // All routes on this engine now require authentication.
    // OAuth routes (/auth/login, /auth/callback, etc.) are registered automatically.

    router.GET("/dashboard", func(c *gin.Context) {
        sess, _ := handle.GetSessionStore().GetSession(c)
        c.JSON(200, gin.H{"user": sess.UserInformation.Profile.Login})
    })

    router.Run(":8080")
}
```

### Option B: Manual middleware registration

```go
handle, err := githuboauth.New(&githuboauth.Config{
    // ... same config as above
})

router := gin.Default()

// Apply to specific route groups
protected := router.Group("/app")
protected.Use(handle.GetMiddleware()...)
protected.GET("/profile", profileHandler)
```

## Generating Session Keys

Session cookies are signed with HMAC-SHA512 (64-byte key) and encrypted with AES-256 (32-byte key). Generate and store these keys securely:

```go
secretKey, _ := githuboauth.GenerateSessionSecretKey()       // 64 bytes
encryptionKey, _ := githuboauth.GenerateSessionEncryptionKey() // 32 bytes

// Encode for storage in config files or environment variables
fmt.Println(githuboauth.EncodeKeyToBase64(secretKey))
fmt.Println(githuboauth.EncodeKeyToBase64(encryptionKey))
```

To load keys from base64-encoded config values:

```go
secretKey, err := githuboauth.DecodeKeyFromBase64(os.Getenv("SESSION_SECRET_KEY"))
encryptionKey, err := githuboauth.DecodeKeyFromBase64(os.Getenv("SESSION_ENCRYPTION_KEY"))
```

## Configuration Reference

### Required

| Field | Type | Description |
|-------|------|-------------|
| `ClientID` | `string` | GitHub OAuth App client ID |
| `ClientSecret` | `string` | GitHub OAuth App client secret |
| `RedirectURI` | `string` | OAuth callback URL (must match GitHub app config) |
| `AuthURL` | `string` | OAuth authorize endpoint (e.g. `https://github.com/login/oauth/authorize`) |
| `TokenURL` | `string` | OAuth token endpoint (e.g. `https://github.com/login/oauth/access_token`) |
| `AllowedTeams` | `[]string` | Teams allowed access in `org/team-slug` format |
| `SessionSecretKey` | `[]byte` | 64-byte HMAC-SHA512 signing key |
| `SessionEncryptionKey` | `[]byte` | 32-byte AES-256 encryption key |

### Optional

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Scopes` | `[]string` | `[]` | OAuth scopes (include `read:org` for team-based auth) |
| `DeviceAuthURL` | `string` | `""` | Device authorization endpoint |
| `GitHubAPIBaseURL` | `string` | `https://api.github.com` | GitHub API URL (set for GHE, must be HTTPS) |
| `AdminTeams` | `[]string` | `[]` | Teams with admin privileges |
| `RelevantTeams` | `[]string` | `[]` | Teams to expose on Gin context for downstream authorization |
| `AllowedAPIKeys` | `[]string` | `[]` | API keys for non-OAuth authentication |
| `CookieName` | `string` | `session_id` | Session cookie name |
| `CookieDomain` | `string` | `localhost` | Cookie domain |
| `SessionMaxAge` | `*int` | `nil` (7 days) | Cookie max age in seconds (`nil` = 7 days, `0` = session cookie) |
| `CookieInsecure` | `bool` | `false` | Set `true` only for local dev without HTTPS |
| `BaseURL` | `string` | `""` | Public base URL for absolute login redirects — required behind forward-auth proxies (e.g. Traefik forwardAuth) |
| `LoginPath` | `string` | `/auth/login` | Login route path |
| `CallbackPath` | `string` | `/auth/callback` | OAuth callback route path |
| `UserInfoPath` | `string` | `/auth/userinfo` | User info route path |
| `LogoutPath` | `string` | `/auth/logout` | Logout route path |
| `RefreshTeamsPath` | `string` | `/auth/refresh-teams` | Team refresh route path |

## Registered Routes

When using `Init()` or applying `GetMiddleware()`, the following routes are registered:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/login` | Initiates OAuth flow (redirects to GitHub) |
| `GET` | `/auth/callback` | Handles OAuth callback, creates session |
| `GET` | `/auth/userinfo` | Returns authenticated user profile as JSON |
| `POST` | `/auth/logout` | Destroys session and revokes OAuth token |
| `POST` | `/auth/refresh-teams` | Re-fetches team membership from GitHub |

## Admin Middleware

Protect admin-only routes using `GetAdminMiddleware()`. Users must belong to a team listed in `AdminTeams`. API key-authenticated requests bypass the admin check.

```go
admin := router.Group("/admin")
admin.Use(handle.GetAdminMiddleware())
admin.GET("/settings", adminSettingsHandler)
```

Responses:
- `401` if no valid session
- `403` if authenticated but not in an admin team
- Proceeds if user is an admin or request is API key-authenticated

## Auth Context

After successful authentication the middleware sets `isAuthenticated`, `isAdmin`, and the matching `RelevantTeams` on the Gin context. Read them via the `Handle` methods:

```go
handle, _ := githuboauth.Init(router, &githuboauth.Config{
    // ...
    RelevantTeams: []string{"myorg/backend", "myorg/frontend", "myorg/devops"},
})

router.GET("/api/resource", func(c *gin.Context) {
    // true for both OAuth sessions and valid API keys
    if !handle.IsAuthenticated(c) {
        return
    }

    // true when the user belongs to any configured AdminTeams
    // (always false for API key requests)
    if handle.IsAdmin(c) {
        // admin-only logic
    }

    // subset of RelevantTeams the user is a member of
    // e.g. ["myorg/backend", "myorg/devops"]
    teams := handle.GetRelevantTeams(c)
    for _, t := range teams {
        // fine-grained authorization per team
    }
})
```

| Method | Returns | Description |
|--------|---------|-------------|
| `handle.IsAuthenticated(c)` | `bool` | `true` if the request passed auth (OAuth session or API key) |
| `handle.IsAdmin(c)` | `bool` | `true` if the user is in any `AdminTeams` team |
| `handle.GetRelevantTeams(c)` | `[]string` | Configured `RelevantTeams` the user belongs to |

### Reading configured teams

The `Handle` also exposes getters for the team lists that were passed in via `Config` (all normalized to lowercase):

| Method | Returns | Description |
|--------|---------|-------------|
| `handle.GetAllowedTeams()` | `[]string` | Configured `AllowedTeams` |
| `handle.GetAdminTeams()` | `[]string` | Configured `AdminTeams` |
| `handle.GetRelevantTeamConfig()` | `[]string` | Configured `RelevantTeams` |

## Working with Sessions

```go
// Get current session
sess, ok := handle.GetSessionStore().GetSession(c)
if !ok {
    // No authenticated session
    return
}

// Access user profile
login := sess.UserInformation.Profile.Login
name := sess.UserInformation.Profile.Name
teams := sess.UserInformation.Teams

// Check admin status
isAdmin := handle.IsUserAdmin(teams)

// Get team slugs as []string
slugs := githuboauth.GetTeamSlugs(teams)
// e.g. ["my-org/team-a", "my-org/team-b"]

// Store/retrieve custom session data (thread-safe)
sess.SetData("preference", "dark-mode")
val, ok := sess.GetData("preference")

// Get an OAuth-aware HTTP client (auto-refreshes tokens)
client := sess.GetHttpClient(c.Request.Context())

// Get the current OAuth token
token, err := sess.GetToken(c.Request.Context())
```

## Making GitHub API Calls

Use the built-in connector for additional GitHub API calls:

```go
connector := handle.GetGitHubConnector()

// Use the session's OAuth client
client := sess.GetHttpClient(c.Request.Context())

profile, err := connector.GetUserProfile(c.Request.Context(), client)
teams, err := connector.GetUserTeams(c.Request.Context(), client)
info, err := connector.GetUserInformation(c.Request.Context(), client)
```

## API Key Authentication

When `AllowedAPIKeys` is configured, requests can authenticate via API key instead of OAuth. Keys are checked in the following headers (in order):

1. `X-API-Key: <key>`
2. `Authorization: Bearer <key>`

API key-authenticated requests bypass OAuth session checks entirely.

### Application-issued API keys

`APIKeyResolver` lets the application issue its own keys (stored hashed in a database, managed in its own UI). It is consulted for any presented key that is not in `AllowedAPIKeys`:

```go
cfg.APIKeyResolver = func(ctx context.Context, key string) *githuboauth.ResolvedAPIKey {
    k, ok := myKeys.Lookup(ctx, key) // return nil for unknown or revoked keys
    if !ok {
        return nil
    }
    return &githuboauth.ResolvedAPIKey{
        Login: "api-key:" + k.Name,                     // attribution, Profile.Login of the session
        Teams: nil,                                     // nil: no team check, never admin
        Data:  map[string]any{"access": k.Access},      // available via GetSession(c).GetData("access")
    }
}
```

A resolved request is authenticated as that principal: `GetSessionStore().GetSession(c)` returns a session carrying `Profile.Login` and `Data`, so handlers need no special casing (`OAuthToken` is nil, which distinguishes it from a browser session). If `Teams` is set they go through the allowed-team check (403 when none matches) and decide `IsAdmin` / `GetAdminMiddleware` like an OAuth session; with `Teams == nil` the application vouches for the key and it is never admin. Unknown keys get 401.

### Standalone API key middleware

For routes that only accept API keys (no OAuth fallback):

```go
middleware := githuboauth.GetApiKeyAuthMiddleware([]string{"key1", "key2"})
router.Use(middleware)
```

## Auth Flow Behavior

The middleware adapts its response based on the request type:

- **Browser requests** (`Accept: text/html`): redirects to `/auth/login`
- **API requests** (`Accept: application/json`, `X-Requested-With: XMLHttpRequest`, or paths starting with `/api/`): returns `401` JSON response

## GitHub Enterprise

Set `GitHubAPIBaseURL` to your GHE API endpoint. The URL must use HTTPS.

```go
&githuboauth.Config{
    GitHubAPIBaseURL: "https://github.example.com/api/v3",
    AuthURL:          "https://github.example.com/login/oauth/authorize",
    TokenURL:         "https://github.example.com/login/oauth/access_token",
    // ...
}
```
