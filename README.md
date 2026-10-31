> [!IMPORTANT]
> **Archived: superseded by [govengers/auth](https://github.com/govengers/auth).** This repository gets no further updates, security fixes included. Released versions of `github.com/mxcd/github-fwd-auth` keep resolving through the Go module proxy, so existing builds keep working. Migrate with the guide: [github-fwd-auth to `github`](https://github.com/govengers/auth/blob/main/docs/migration.md#3-github-fwd-auth-library-v14x-to-github), and for the image [the forward-auth binaries to `ghcr.io/govengers/forwardauth`](https://github.com/govengers/auth/blob/main/docs/migration.md#4-the-forward-auth-binaries-to-forwardauth).

## GitHub Forward Auth

This project is a `traefik` forward auth middleware that uses GitHub OAuth to authenticate users.
A GitHub OAuth App is required to use this middleware.
If configured, it can create a JWT holding the user's GitHub username and the teams the user is a member of.
A `/JWKS` endpoint is available to retrieve the public key to verify the JWT.

The OAuth and session management functionality is available as a standalone library at [`pkg/githuboauth`](pkg/githuboauth/). See the [library documentation](pkg/githuboauth/README.md) for usage in your own Go applications.

## Configuration

The forward auth middleware can be configured using environment variables or a `.env` file called `github-fwd-auth.env`. In the docker image, the `.env` file is located at `/github-fwd-auth.env`.

| Environment Variable             | Type     | Default Value            | Comment                      |
| -------------------------------- | -------- | ------------------------ | ---------------------------- |
| `BASE_URL`                       | String   | "http://localhost:8080"  | Must not be empty            |
| `LOG_LEVEL`                      | String   | "info"                   | Must not be empty            |
| `DEV`                            | Boolean  | false                    | Enable DEV mode              |
| `PORT`                           | Integer  | 8080                     |                              |
| `GITHUB_API_BASE_URL`            | String   | "https://api.github.com" | Must not be empty            |
| `OAUTH_CLIENT_ID`                | String   |                          | Must not be empty            |
| `OAUTH_CLIENT_SECRET`            | String   |                          | Must not be empty, Sensitive |
| `OAUTH_REDIRECT_URI`             | String   |                          | Must not be empty            |
| `OAUTH_PROVIDER_AUTH_URL`        | String   |                          | Must not be empty            |
| `OAUTH_PROVIDER_TOKEN_URL`       | String   |                          | Must not be empty            |
| `OAUTH_PROVIDER_DEVICE_AUTH_URL` | String   |                          |                              |
| `OAUTH_SCOPES`                   | String   |                          | Must not be empty            |
| `ALLOWED_GITHUB_TEAMS`           | String[] |                          |                              |
| `ADMIN_GITHUB_TEAMS`             | String[] |                          |                              |
| `CREATE_JWT`                     | Boolean  | false                    |                              |
| `JWT_ALGORITHM`                  | String   | "RS512"                  |                              |
| `JWT_PRIVATE_KEY`                | String   |                          | Sensitive                    |
| `JWT_ISSUER`                     | String   |                          |                              |
| `API_KEYS`                       | String[] | ""                       | Sensitive                    |
| `COOKIE_DOMAIN`                  | String   | "localhost"              | Must not be empty            |
| `COOKIE_INSECURE`                | Boolean  | false                    | Set true only for local dev  |
| `SESSION_COOKIE_NAME`            | String   | "session_id"             | Must not be empty            |
| `SESSION_MAX_AGE`                | Integer  | 604800                   | (3600 * 24 * 7) - 1 week    |
| `SESSION_SECRET_KEY`             | String   |                          | Must not be empty, Sensitive, Base64-encoded 64-byte key |
| `SESSION_ENCRYPTION_KEY`         | String   |                          | Must not be empty, Sensitive, Base64-encoded 32-byte key |

### Session Keys

The middleware uses encrypted session cookies. You must provide two keys:

- `SESSION_SECRET_KEY` - A base64-encoded 64-byte key for HMAC-SHA512 cookie signing
- `SESSION_ENCRYPTION_KEY` - A base64-encoded 32-byte key for AES-256 cookie encryption

Generate keys using the library helpers or any method that produces cryptographically random bytes:

```go
package main

import (
    "fmt"
    "github.com/mxcd/github-fwd-auth/pkg/githuboauth"
)

func main() {
    secret, _ := githuboauth.GenerateSessionSecretKey()
    encryption, _ := githuboauth.GenerateSessionEncryptionKey()
    fmt.Println("SESSION_SECRET_KEY=" + githuboauth.EncodeKeyToBase64(secret))
    fmt.Println("SESSION_ENCRYPTION_KEY=" + githuboauth.EncodeKeyToBase64(encryption))
}
```

Or using `openssl`:

```bash
echo "SESSION_SECRET_KEY=$(openssl rand -base64 64)"
echo "SESSION_ENCRYPTION_KEY=$(openssl rand -base64 32)"
```

### JWT Configuration

Only if `CREATE_JWT` is set to `true`, a JWT will be created and injected into the `Authorization` header of the request.
Note that the header needs to be allowed in `traefik` using the `traefik.http.middlewares.ui-fwd-auth.forwardauth.authResponseHeaders=Authorization` directive

### API Keys

The provided `API_KEYS` can be used to bypass the GitHub OAuth authentication. When handling a request, the middleware will check the `X-API-Key` header (or `Authorization: Bearer <key>`) and compare it to the provided `API_KEYS`. If the key matches any of the `API_KEYS`, the request will be allowed to pass through.
The `API_KEYS` are comma separated, e.g. `API_KEYS=123456,789012` which would result in the valid API keys `123456` and `789012`.
If no `API_KEYS` are provided, the API key check will be disabled.

### Allowed Teams

It is possible to restrict access to users that are members of specific GitHub teams. The `ALLOWED_GITHUB_TEAMS` environment variable can be used to provide a list of team names that are allowed to pass through. If no teams are provided, all users are allowed to pass through.
The format of the team name is the entire slug, e.g. `my-org/my-team`. Multiple teams can be provided as a comma separated list, e.g. `ALLOWED_GITHUB_TEAMS=my-org/my-team,my-org/my-other-team`.

### Admin Teams

The `ADMIN_GITHUB_TEAMS` environment variable can be used to designate teams with admin privileges. Admin status can be checked by downstream services via the JWT claims or user info endpoint.
The format is the same as `ALLOWED_GITHUB_TEAMS`, e.g. `ADMIN_GITHUB_TEAMS=my-org/platform-admins`.

## Traefik Setup

### docker compose example

```
version: "3"

services:
  traefik:
    image: "traefik:v3.0"
    container_name: "traefik"
    command:
      - "--log.level=DEBUG"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entryPoints.web.address=:80"
    ports:
      - "8080:80"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
  github-fwd-auth:
    image: "github-fwd-auth"
    container_name: "github-fwd-auth"
    env_file: ../../github-fwd-auth.env
  whoami:
    image: "traefik/whoami"
    container_name: "whoami"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`localhost`)"
      - "traefik.http.routers.whoami.entrypoints=web"
      - "traefik.http.middlewares.ui-fwd-auth.forwardauth.address=http://github-fwd-auth:8080/ui-auth"
      - "traefik.http.middlewares.ui-fwd-auth.forwardauth.authResponseHeaders=Authorization"
      - "traefik.http.routers.whoami.middlewares=ui-fwd-auth@docker"
```

Minimal configuration for the traefik example:

```
OAUTH_CLIENT_ID=<INSERT CLIENT ID>
OAUTH_CLIENT_SECRET=<INSERT CLIENT SECRET>
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_PROVIDER_AUTH_URL=https://github.com/login/oauth/authorize
OAUTH_PROVIDER_TOKEN_URL=https://github.com/login/oauth/access_token
OAUTH_SCOPES="user:email,read:org"
SESSION_SECRET_KEY=<BASE64 ENCODED 64 BYTE KEY>
SESSION_ENCRYPTION_KEY=<BASE64 ENCODED 32 BYTE KEY>
```

### Kubernetes example

```
# middleware
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: github-fwd-auth
  namespace: default
spec:
  forwardAuth:
    address: http://github-fwd-auth.default.svc.cluster.local/ui-auth
    trustForwardHeader: true
    # enable for JWT
    authResponseHeaders:
      - Authorization
```
```
# ingress
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: some-ingress-name
  namespace: default
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.tls: 'true'
    # middlewares are defined using the name of the namespace and the name of the middleware
    # <namespace>-<middleware-name>@kubernetescrd
    traefik.ingress.kubernetes.io/router.middlewares: "default-github-fwd-auth@kubernetescrd"
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-com-tls-secret
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: some-service-name
                port:
                  number: 80
```

## Library Usage

The GitHub OAuth functionality is available as a reusable Go library at `pkg/githuboauth`. Use it to add GitHub OAuth authentication to your own Gin applications without the forward auth server.

See the [library documentation](pkg/githuboauth/README.md) for the full API reference, configuration options, and usage examples.
