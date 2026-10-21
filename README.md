# Spring Authorization Service

An OAuth2 and OpenID Connect authorization server built with Spring Boot 4.1.1. PostgreSQL stores users and the root issuer's registered clients, authorizations, and consent. Two sample tenants have separate embedded databases. The code follows MVC for the sign-in flow: `LoginController` renders `login.html`, `CustomUserDetailsService` loads the `User` entity through `UserRepository`, and Spring Security processes credentials and OAuth2 protocol requests.

## Run locally

```bash
docker compose up -d postgres
./gradlew bootRun
```

The Compose database listens on local port `5433`. Flyway applies the migrations in `src/main/resources/db/migration` on startup. The authorization server listens on `http://localhost:9000`.
The local PostgreSQL defaults are username `postgres` and password `12345`; set `AUTH_DB_USER` and `AUTH_DB_PASSWORD` to override them.

## OAuth2 endpoints

Spring Security provides `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, `/oauth2/introspect`, and `/oauth2/revoke`. OpenID Connect discovery is at `/.well-known/openid-configuration`. The application provides `/login` as its sign-in page and an authenticated `/` response after direct login.

Import `postman/OAuth2-token-working.postman_collection.json` into Postman for preconfigured token requests. Set the collection variable `auth_code` to a fresh code from the browser callback before sending **2 - Authorization code token**.

### Machine client

Use Basic Auth with client ID `postman-client` and secret `dev-secret-change-me` at `POST /oauth2/token`. Send form fields `grant_type=client_credentials` and `scope=api.read` or `scope=api.write`. The response contains an access token.

### User client

Use Postman's **Authorization Code (With PKCE)** flow with:

| Setting | Value |
| --- | --- |
| Callback URL | `https://oauth.pstmn.io/v1/browser-callback` |
| Auth URL | `http://localhost:9000/oauth2/authorize` |
| Access Token URL | `http://localhost:9000/oauth2/token` |
| Client ID / secret | `oidc-client` / `secret` |
| Scope | `openid profile api.read` |
| Client authentication | Basic Auth header |
| Code challenge method | SHA-256 |

Select **Authorize using browser**. The seeded user is `user` / `password`. After sign-in and consent, Postman exchanges the code for access, ID, and refresh tokens. The OIDC client also accepts `http://127.0.0.1:8080/login/oauth2/code/oidc-client` as a redirect URI for a separate Spring OAuth2 client application.

### OpenID Connect UserInfo

The server follows Spring's [UserInfo guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-userinfo.html): it adds database-backed standard claims to ID tokens, which the OIDC UserInfo endpoint returns according to the authorized scopes. After an Authorization Code exchange, call `GET http://localhost:9000/userinfo` with `Authorization: Bearer <access_token>`. `openid` returns `sub`; `profile` adds `preferred_username` and `name`; `email` adds `email` and `email_verified=false`. The server does not verify email addresses. Request `openid profile email` to receive all of these claims.

`AUTH_USER_DISPLAY_NAME` and `AUTH_USER_EMAIL` set initial profile values for the seeded user; defaults are `Demo User` and `user@example.com`. On startup, missing profile values for an existing seeded user are filled without overwriting populated values. New client registrations include the `email` scope. Existing database client registrations are not rewritten by the seeder, so add `email` to a persisted client before requesting that scope.

### Role claims in access tokens

Following Spring's [authorities claim guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-custom-claims-authorities.html), JWT access tokens issued for a signed-in user include a `roles` claim derived from the principal's `ROLE_` authorities. For the seeded user, the claim is `["USER"]`. The role prefix is omitted in the claim. Machine client tokens have no resource owner and therefore no `roles` claim. ID tokens retain only the UserInfo claims described above. This application currently assigns `ROLE_USER` to every enabled user in `CustomUserDetailsService`; change that service if roles should come from stored user permissions.

### Dynamic client registration

Following Spring's [dynamic client registration guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-dynamic-client-registration.html), the root issuer exposes `POST /connect/register` and `GET /connect/register?client_id=...`. The endpoint appears as `registration_endpoint` in OIDC discovery. The seeded `registrar-client` uses Basic authentication and has `client.create` and `client.read` scopes. Set `AUTH_REGISTRAR_CLIENT_ID` and `AUTH_REGISTRAR_CLIENT_SECRET` before first startup outside local development; the local defaults are `registrar-client` and `registrar-secret-change-me`.

First obtain an initial token from `POST /oauth2/token` using Basic credentials for the registrar and form fields `grant_type=client_credentials&scope=client.create`. The scope must be exactly `client.create`. Then send `POST /connect/register` with `Authorization: Bearer <initial_access_token>`, `Content-Type: application/json`, and a body such as:

```json
{
  "client_name": "example-client",
  "grant_types": ["authorization_code"],
  "redirect_uris": ["https://client.example.org/callback"],
  "scope": "openid email profile",
  "logo_uri": "https://client.example.org/logo",
  "contacts": ["admin@client.example.org"]
}
```

The response includes a new client ID and secret, `registration_access_token`, and `registration_client_uri`. The initial token is single use. Retrieve the client with `GET <registration_client_uri>` and `Authorization: Bearer <registration_access_token>`. The custom `logo_uri` and `contacts` metadata are stored with the registered client and returned on retrieval. The registrar is seeded for the root issuer only; the sample tenants have separate client stores. Registration tokens and client secrets are credentials and should be kept private.

With the server running, `python3 scripts/test_dynamic_registration.py` tests this flow using only Python's standard library. It creates a new client on each run. Set `AUTH_BASE_URL`, `AUTH_REGISTRAR_CLIENT_ID`, and `AUTH_REGISTRAR_CLIENT_SECRET` if you changed the defaults.

### Browser SPA with PKCE

The seeded `public-client` is a public Authorization Code client for a SPA at `http://127.0.0.1:4200`. It has no client secret, requires user consent and PKCE, and allows cross-origin requests from that origin. This follows the [Spring Authorization Server SPA with PKCE guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-pkce.html).

Use a framework-supported OAuth2 client library to generate a fresh `code_verifier` and its SHA-256 `code_challenge`. Redirect the browser to `/oauth2/authorize` with `response_type=code`, `client_id=public-client`, `redirect_uri=http://127.0.0.1:4200`, `scope=openid profile`, `state`, `code_challenge`, and `code_challenge_method=S256`. After login and consent, exchange the returned code at `/oauth2/token` with `grant_type=authorization_code`, `client_id=public-client`, the same `redirect_uri`, and the original `code_verifier`. Do not send a client secret. The public client does not receive refresh tokens.

Set `AUTH_PUBLIC_CLIENT_ID`, `AUTH_PUBLIC_ORIGIN`, and `AUTH_PUBLIC_REDIRECT_URI` to match your SPA deployment. The origin is the scheme, host, and port only; the redirect URI may include a callback path. Both defaults use `http://127.0.0.1:4200`. For an existing database, changing these values does not update the seeded client: update its registration in the database or use a new client ID.

### Custom code extension grant

The `custom-code-client` follows Spring Authorization Server's [extension grant guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-ext-grant-type.html). Unlike the guide's placeholder code check, this implementation issues random, five-minute, single-use codes and stores only their SHA-256 hashes. A signed-in user can submit a CSRF-protected `POST /custom-codes` with `clientId=custom-code-client`; the JSON response contains the code. Deliver that code to the confidential client through a trusted channel. The client then sends Basic Auth (`custom-code-client` / `custom-code-secret-change-me`) and form fields `grant_type=urn:ietf:params:oauth:grant-type:custom_code` and `code=<issued code>` to `POST /oauth2/token`. The response contains an `api.read` access token for the user who requested the code. A code cannot be reused or exchanged by another client.

Set `AUTH_CUSTOM_CLIENT_ID` and `AUTH_CUSTOM_CLIENT_SECRET` before first startup outside local development. Existing seeded clients are not updated automatically when these values change. This sample code issuance endpoint is intended for a trusted first-party flow; integrate it with your own user-facing authorization and delivery flow before exposing it broadly.

### Multiple issuers

The authorization server follows Spring's [multitenancy guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-multitenancy.html). It allows issuer paths on one host and delegates registered clients, authorizations, consents, signing keys, and JWT decoding by the requested issuer. The root issuer (`http://localhost:9000` by default) retains the PostgreSQL-backed clients and flows above. Two sample tenants are available at `http://localhost:9000/issuer1` and `http://localhost:9000/issuer2`.

Each sample tenant has its own embedded H2 database and RSA signing key, as in the guide. Its data and signing key are recreated on restart. The seeded clients are `issuer1-client` and `issuer2-client`, each with the configured `AUTH_TENANT_CLIENT_SECRET` (default `tenant-secret-change-me`) and `api.read` scope. For example, send Basic Auth for `issuer1-client` to `POST http://localhost:9000/issuer1/oauth2/token` with form fields `grant_type=client_credentials&scope=api.read`. The equivalent issuer 2 endpoint is under `/issuer2`. Discovery is at `/issuer1/.well-known/openid-configuration` and `/issuer2/.well-known/openid-configuration`; each issuer has its own `/oauth2/jwks` endpoint. A tenant client cannot request a token from the other tenant's endpoint.

`AUTH_ISSUER` sets the root issuer used by the component registry. It must match the externally visible scheme, host, and port used for requests. Deployments with a proxy must pass the correct forwarded host and scheme to Spring Security. Replace the embedded tenant databases and generated keys with durable tenant-specific resources before relying on their tokens across restarts.

## Configuration and persistence

The root issuer's three OAuth2 core services follow Spring's [JPA how-to guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html): `JpaRegisteredClientRepository`, `JpaOAuth2AuthorizationService`, and `JpaOAuth2AuthorizationConsentService` map Spring Security's domain objects to JPA entities and Spring Data repositories. `User` is also a JPA entity. All four use the same PostgreSQL database. Flyway owns the table definitions; Hibernate validates them on startup.

`AUTH_DB_URL`, `AUTH_DB_USER`, and `AUTH_DB_PASSWORD` override the PostgreSQL connection. `AUTH_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_OIDC_CLIENT_ID`, `AUTH_OIDC_CLIENT_SECRET`, `AUTH_OIDC_REDIRECT_URI`, `AUTH_POSTMAN_REDIRECT_URI`, `AUTH_PUBLIC_CLIENT_ID`, `AUTH_PUBLIC_ORIGIN`, `AUTH_PUBLIC_REDIRECT_URI`, `AUTH_CUSTOM_CLIENT_ID`, `AUTH_CUSTOM_CLIENT_SECRET`, `AUTH_REGISTRAR_CLIENT_ID`, `AUTH_REGISTRAR_CLIENT_SECRET`, `AUTH_TENANT_CLIENT_SECRET`, `AUTH_USER_NAME`, `AUTH_USER_PASSWORD`, `AUTH_USER_DISPLAY_NAME`, and `AUTH_USER_EMAIL` override initial setup values. Root clients and the user are inserted only when absent; changing a client setting later does not overwrite an existing PostgreSQL record. Missing profile values for the seeded user are populated on startup.

The sample secrets are for local use. The RSA signing key is generated on startup, so existing JWTs stop validating after a restart even though authorization records persist. A durable deployment needs a managed signing key.

Run tests with `./gradlew test`. Tests use an in-memory database with PostgreSQL compatibility mode for the root issuer. The sample tenants use separate in-memory databases in both tests and the running application.
# build-from-scratch-Oauth2
