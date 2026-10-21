package istad.ha.springauthorizationservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import istad.ha.springauthorizationservice.oauth.CustomCodeGrant;
import istad.ha.springauthorizationservice.multitenancy.TenantPerIssuerComponentRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import istad.ha.springauthorizationservice.service.JpaOAuth2AuthorizationService;
import istad.ha.springauthorizationservice.service.JpaOAuth2AuthorizationConsentService;
import istad.ha.springauthorizationservice.service.JpaRegisteredClientRepository;
import istad.ha.springauthorizationservice.repository.ClientRepository;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcBuilderCustomizer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import istad.ha.springauthorizationservice.repository.UserRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.util.StringUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class SpringAuthorizationServiceApplicationTests {

    @TestConfiguration
    static class MockIssuerConfiguration {
        @Bean
        MockMvcBuilderCustomizer issuerPort() {
            return builder -> builder.defaultRequest(get("/").with(request -> {
                request.setServerPort(9000);
                return request;
            }));
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private OAuth2AuthorizationConsentService authorizationConsentService;

    @Autowired
    private UserRepository users;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private TenantPerIssuerComponentRegistry tenantRegistry;

    @Autowired
    private JpaRegisteredClientRepository jpaClients;

    @Autowired
    private JpaOAuth2AuthorizationService jpaAuthorizations;

    @Autowired
    private JpaOAuth2AuthorizationConsentService jpaConsents;

    @Autowired
    private ClientRepository clientEntities;

    @Test
    void jpaStoresAreReadyAndSeeded() {
        assertInstanceOf(JpaRegisteredClientRepository.class,
            tenantRegistry.get("http://localhost:9000", RegisteredClientRepository.class));
        assertInstanceOf(JpaOAuth2AuthorizationService.class,
            tenantRegistry.get("http://localhost:9000", OAuth2AuthorizationService.class));
        assertInstanceOf(JpaOAuth2AuthorizationConsentService.class,
            tenantRegistry.get("http://localhost:9000", OAuth2AuthorizationConsentService.class));
        assertNotNull(registeredClientRepository.findByClientId("postman-client"));
        assertNotNull(registeredClientRepository.findByClientId("oidc-client"));
        assertNotNull(registeredClientRepository.findByClientId("public-client"));
        assertTrue(users.existsByUsername("user"));
        assertNotNull(registeredClientRepository.findByClientId("custom-code-client"));
        assertNotNull(registeredClientRepository.findByClientId("registrar-client"));
        assertEquals(5, jdbcTemplate.queryForObject("select count(*) from oauth2_registered_client where client_id in ('postman-client', 'oidc-client', 'public-client', 'custom-code-client', 'registrar-client')", Integer.class));
    }

    @Test
    void jpaCoreServicesRoundTripClientAuthorizationAndConsent() {
        String suffix = UUID.randomUUID().toString();
        RegisteredClient client = RegisteredClient.withId(suffix)
            .clientId("jpa-test-" + suffix)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://127.0.0.1:4200/callback")
            .scope("openid")
            .scope("profile")
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .build();
        jpaClients.save(client);
        try {
            RegisteredClient loadedClient = jpaClients.findByClientId(client.getClientId());
            assertEquals(client.getId(), loadedClient.getId());
            assertTrue(loadedClient.getClientSettings().isRequireProofKey());
            assertEquals(client.getRedirectUris(), loadedClient.getRedirectUris());

            Instant issued = Instant.now();
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(loadedClient)
                .principalName("user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("openid", "profile"))
                .attribute("test-attribute", "persisted")
                .token(new OAuth2AuthorizationCode("code-" + suffix, issued, issued.plusSeconds(300)),
                    metadata -> metadata.put("test-metadata", "persisted"))
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    "access-" + suffix, issued, issued.plusSeconds(300), Set.of("openid", "profile")))
                .token(new OAuth2RefreshToken("refresh-" + suffix, issued, issued.plusSeconds(3600)))
                .token(new OidcIdToken("id-" + suffix, issued, issued.plusSeconds(300),
                    Map.of("sub", "user", "name", "JPA User")),
                    metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of("sub", "user", "name", "JPA User")))
                .build();
            jpaAuthorizations.save(authorization);
            OAuth2Authorization loaded = jpaAuthorizations.findByToken("access-" + suffix, OAuth2TokenType.ACCESS_TOKEN);
            assertEquals(authorization.getId(), loaded.getId());
            assertEquals("persisted", loaded.getAttribute("test-attribute"));
            assertEquals("persisted", loaded.getToken(OAuth2AuthorizationCode.class).getMetadata().get("test-metadata"));
            assertEquals("JPA User", loaded.getToken(OidcIdToken.class).getClaims().get("name"));
            assertEquals(Set.of("openid", "profile"), loaded.getAccessToken().getToken().getScopes());
            assertNotNull(jpaAuthorizations.findByToken("refresh-" + suffix, OAuth2TokenType.REFRESH_TOKEN));

            OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(client.getId(), "user")
                .authority(new SimpleGrantedAuthority("SCOPE_profile")).build();
            jpaConsents.save(consent);
            assertEquals(consent.getAuthorities(), jpaConsents.findById(client.getId(), "user").getAuthorities());
            jpaConsents.remove(consent);
            assertNull(jpaConsents.findById(client.getId(), "user"));
            jpaAuthorizations.remove(loaded);
            assertNull(jpaAuthorizations.findById(authorization.getId()));
        } finally {
            clientEntities.deleteById(client.getId());
        }
    }

    @Test
    void tenantsHaveSeparateClientsTokensAndSigningKeys() throws Exception {
        mockMvc.perform(get("/issuer1/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("http://localhost:9000/issuer1"))
            .andExpect(jsonPath("$.token_endpoint").value("http://localhost:9000/issuer1/oauth2/token"));
        mockMvc.perform(get("/issuer2/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("http://localhost:9000/issuer2"));

        String keys1 = mockMvc.perform(get("/issuer1/oauth2/jwks"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String keys2 = mockMvc.perform(get("/issuer2/oauth2/jwks"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String key1 = new ObjectMapper().readTree(keys1).get("keys").get(0).get("kid").asText();
        String key2 = new ObjectMapper().readTree(keys2).get("keys").get(0).get("kid").asText();
        assertFalse(key1.equals(key2));

        String response = mockMvc.perform(post("/issuer1/oauth2/token")
                .with(httpBasic("issuer1-client", "test-tenant-secret"))
                .param("grant_type", "client_credentials")
                .param("scope", "api.read"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isString())
            .andReturn().getResponse().getContentAsString();
        String token = new ObjectMapper().readTree(response).get("access_token").asText();
        assertEquals("http://localhost:9000/issuer1", tenantRegistry.get("http://localhost:9000/issuer1", JwtDecoder.class)
            .decode(token).getIssuer().toString());
        assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,
            () -> tenantRegistry.get("http://localhost:9000/issuer2", JwtDecoder.class).decode(token));
        assertNotNull(tenantRegistry.get("http://localhost:9000/issuer1", OAuth2AuthorizationService.class)
            .findByToken(token, OAuth2TokenType.ACCESS_TOKEN));
        assertEquals(null, tenantRegistry.get("http://localhost:9000/issuer2", OAuth2AuthorizationService.class)
            .findByToken(token, OAuth2TokenType.ACCESS_TOKEN));

        mockMvc.perform(post("/issuer2/oauth2/token")
                .with(httpBasic("issuer1-client", "test-tenant-secret"))
                .param("grant_type", "client_credentials"))
            .andExpect(status().isUnauthorized());
        assertEquals("http://localhost:9000/issuer1", com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet().getIssuer());
        assertNotNull(tenantRegistry.get("http://localhost:9000/issuer1", RegisteredClientRepository.class)
            .findByClientId("issuer1-client"));
        assertEquals(null, tenantRegistry.get("http://localhost:9000/issuer2", RegisteredClientRepository.class)
            .findByClientId("issuer1-client"));

        String issuer1ClientId = tenantRegistry.get("http://localhost:9000/issuer1", RegisteredClientRepository.class)
            .findByClientId("issuer1-client").getId();
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(issuer1ClientId, "user")
            .authority(new SimpleGrantedAuthority("SCOPE_api.read")).build();
        tenantRegistry.get("http://localhost:9000/issuer1", OAuth2AuthorizationConsentService.class).save(consent);
        assertNotNull(tenantRegistry.get("http://localhost:9000/issuer1", OAuth2AuthorizationConsentService.class)
            .findById(issuer1ClientId, "user"));
        assertEquals(null, tenantRegistry.get("http://localhost:9000/issuer2", OAuth2AuthorizationConsentService.class)
            .findById(issuer1ClientId, "user"));
    }

    @Test
    void customCodeGrantIsSingleUseAndBoundToClient() throws Exception {
        MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", "user")
                .param("password", "test-password"))
            .andExpect(status().is3xxRedirection())
            .andReturn().getRequest().getSession(false);

        String issued = mockMvc.perform(post("/custom-codes")
                .session(session)
                .with(csrf())
                .param("clientId", "custom-code-client"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").isString())
            .andReturn().getResponse().getContentAsString();
        String code = new ObjectMapper().readTree(issued).get("code").asText();

        mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("postman-client", "test-machine-secret"))
                .param("grant_type", CustomCodeGrant.GRANT_TYPE.getValue())
                .param("code", code))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("unauthorized_client"));

        String tokenResponse = mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("custom-code-client", "test-custom-secret"))
                .param("grant_type", CustomCodeGrant.GRANT_TYPE.getValue())
                .param("code", code))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isString())
            .andReturn().getResponse().getContentAsString();
        String accessToken = new ObjectMapper().readTree(tokenResponse).get("access_token").asText();
        assertEquals("user", authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN).getPrincipalName());
        assertEquals("user", jwtDecoder.decode(accessToken).getSubject());
        assertEquals(java.util.List.of("USER"), jwtDecoder.decode(accessToken).getClaimAsStringList("roles"));

        mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("custom-code-client", "test-custom-secret"))
                .param("grant_type", CustomCodeGrant.GRANT_TYPE.getValue())
                .param("code", code))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void customCodeGrantRejectsMissingCodeAndUnauthenticatedIssuance() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("custom-code-client", "test-custom-secret"))
                .param("grant_type", CustomCodeGrant.GRANT_TYPE.getValue()))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_request"));

        mockMvc.perform(post("/custom-codes")
                .with(csrf())
                .param("clientId", "custom-code-client"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void publicClientRequiresPkceAndAllowsSpaTokenRequests() throws Exception {
        var client = registeredClientRepository.findByClientId("public-client");
        assertEquals(java.util.Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        assertEquals(java.util.Set.of(AuthorizationGrantType.AUTHORIZATION_CODE), client.getAuthorizationGrantTypes());
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertTrue(client.getClientSettings().isRequireAuthorizationConsent());
        assertFalse(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));

        mockMvc.perform(options("/oauth2/token")
                .header("Origin", "http://127.0.0.1:4200")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "content-type"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "http://127.0.0.1:4200"))
            .andExpect(header().string("Access-Control-Allow-Credentials", "true"));

        mockMvc.perform(get("/oauth2/authorize")
                .with(user("user"))
                .queryParam("response_type", "code")
                .queryParam("client_id", "public-client")
                .queryParam("redirect_uri", "http://127.0.0.1:4200")
                .queryParam("scope", "openid profile")
                .queryParam("state", "missing-pkce"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_request")));
    }

    @Test
    void publicClientExchangesCodeWithVerifierWithoutSecret() throws Exception {
        var client = registeredClientRepository.findByClientId("public-client");
        authorizationConsentService.save(OAuth2AuthorizationConsent.withId(client.getId(), "user")
            .authority(new SimpleGrantedAuthority("SCOPE_openid"))
            .authority(new SimpleGrantedAuthority("SCOPE_profile"))
            .authority(new SimpleGrantedAuthority("SCOPE_email"))
            .build());
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));

        MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", "user")
                .param("password", "test-password"))
            .andExpect(status().is3xxRedirection())
            .andReturn().getRequest().getSession(false);

        String location = mockMvc.perform(get("/oauth2/authorize")
                .session(session)
                .queryParam("response_type", "code")
                .queryParam("client_id", "public-client")
                .queryParam("redirect_uri", "http://127.0.0.1:4200")
                .queryParam("scope", "openid profile email")
                .queryParam("state", "pkce-state")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256"))
            .andExpect(status().is3xxRedirection())
            .andReturn().getResponse().getRedirectedUrl();
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(location)
            .build().getQueryParams().getFirst("code");
        assertNotNull(code);

        String tokenResponse = mockMvc.perform(post("/oauth2/token")
                .header("Origin", "http://127.0.0.1:4200")
                .param("grant_type", "authorization_code")
                .param("client_id", "public-client")
                .param("redirect_uri", "http://127.0.0.1:4200")
                .param("code", code)
                .param("code_verifier", verifier))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "http://127.0.0.1:4200"))
            .andExpect(jsonPath("$.access_token").isString())
            .andExpect(jsonPath("$.refresh_token").doesNotExist())
            .andReturn().getResponse().getContentAsString();
        var tokens = new ObjectMapper().readTree(tokenResponse);
        String accessToken = tokens.get("access_token").asText();
        String idToken = tokens.get("id_token").asText();
        assertEquals(java.util.List.of("USER"), jwtDecoder.decode(accessToken).getClaimAsStringList("roles"));
        assertNull(jwtDecoder.decode(idToken).getClaim("roles"));
        assertEquals("Test User", jwtDecoder.decode(idToken).getClaimAsString("name"));
        assertEquals("user@example.com", jwtDecoder.decode(idToken).getClaimAsString("email"));

        mockMvc.perform(get("/userinfo")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sub").value("user"))
            .andExpect(jsonPath("$.preferred_username").value("user"))
            .andExpect(jsonPath("$.name").value("Test User"))
            .andExpect(jsonPath("$.email").value("user@example.com"))
            .andExpect(jsonPath("$.email_verified").value(false));

        String limitedLocation = mockMvc.perform(get("/oauth2/authorize")
                .session(session)
                .queryParam("response_type", "code")
                .queryParam("client_id", "public-client")
                .queryParam("redirect_uri", "http://127.0.0.1:4200")
                .queryParam("scope", "openid profile")
                .queryParam("state", "limited-state")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256"))
            .andExpect(status().is3xxRedirection())
            .andReturn().getResponse().getRedirectedUrl();
        String limitedCode = org.springframework.web.util.UriComponentsBuilder.fromUriString(limitedLocation)
            .build().getQueryParams().getFirst("code");
        String limitedResponse = mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("client_id", "public-client")
                .param("redirect_uri", "http://127.0.0.1:4200")
                .param("code", limitedCode)
                .param("code_verifier", verifier))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        var limitedTokens = new ObjectMapper().readTree(limitedResponse);
        assertNull(jwtDecoder.decode(limitedTokens.get("id_token").asText()).getClaim("email"));
        mockMvc.perform(get("/userinfo")
                .header("Authorization", "Bearer " + limitedTokens.get("access_token").asText()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void clientCredentialsTokenIsPersisted() throws Exception {
        String response = mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("postman-client", "test-machine-secret"))
                .param("grant_type", "client_credentials")
                .param("scope", "api.read"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isString())
            .andReturn().getResponse().getContentAsString();
        String accessToken = new ObjectMapper().readTree(response).get("access_token").asText();
        assertNotNull(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN));
        assertNull(jwtDecoder.decode(accessToken).getClaim("roles"));
        assertTrue(jdbcTemplate.queryForObject("select count(*) from oauth2_authorization where access_token_value = ?", Integer.class, accessToken) > 0);
    }

    @Test
    void dynamicClientRegistrationPersistsMetadataAndAllowsRetrieval() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.registration_endpoint").value("http://localhost:9000/connect/register"));

        String tokenResponse = mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("registrar-client", "test-registrar-secret"))
                .param("grant_type", "client_credentials")
                .param("scope", "client.create"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        String initialToken = mapper.readTree(tokenResponse).get("access_token").asText();
        String request = """
            {
              "client_name": "registered-test-client",
              "grant_types": ["authorization_code"],
              "redirect_uris": ["https://client.example.org/callback"],
              "scope": "openid email profile",
              "logo_uri": "https://client.example.org/logo",
              "contacts": ["admin@client.example.org"]
            }
            """;
        mockMvc.perform(post("/connect/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().is3xxRedirection());

        String registrationResponse = mockMvc.perform(post("/connect/register")
                .header("Authorization", "Bearer " + initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.client_name").value("registered-test-client"))
            .andExpect(jsonPath("$.logo_uri").value("https://client.example.org/logo"))
            .andExpect(jsonPath("$.contacts[0]").value("admin@client.example.org"))
            .andReturn().getResponse().getContentAsString();
        var registration = mapper.readTree(registrationResponse);
        String clientId = registration.get("client_id").asText();
        String registrationToken = registration.get("registration_access_token").asText();
        String registrationUri = registration.get("registration_client_uri").asText();
        assertFalse(registration.get("client_secret").asText().isBlank());
        assertFalse(registrationToken.isBlank());
        RegisteredClient stored = registeredClientRepository.findByClientId(clientId);
        assertNotNull(stored);
        assertEquals("https://client.example.org/logo", stored.getClientSettings().getSetting("logo_uri"));
        assertEquals(java.util.List.of("admin@client.example.org"), stored.getClientSettings().getSetting("contacts"));

        mockMvc.perform(post("/connect/register")
                .header("Authorization", "Bearer " + initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(request))
            .andExpect(status().is4xxClientError());
        mockMvc.perform(get(java.net.URI.create(registrationUri))
                .header("Authorization", "Bearer " + registrationToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.client_id").value(clientId))
            .andExpect(jsonPath("$.logo_uri").value("https://client.example.org/logo"))
            .andExpect(jsonPath("$.contacts[0]").value("admin@client.example.org"))
            .andExpect(jsonPath("$.registration_access_token").doesNotExist());
    }

    @Test
    void dynamicRegistrationCannotGrantRegistrarScopes() throws Exception {
        String tokenResponse = mockMvc.perform(post("/oauth2/token")
                .with(httpBasic("registrar-client", "test-registrar-secret"))
                .param("grant_type", "client_credentials")
                .param("scope", "client.create"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        String initialToken = new ObjectMapper().readTree(tokenResponse).get("access_token").asText();

        mockMvc.perform(post("/connect/register")
                .header("Authorization", "Bearer " + initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "client_name": "privileged-client",
                      "grant_types": ["authorization_code"],
                      "redirect_uris": ["https://client.example.org/callback"],
                      "scope": "client.create client.read"
                    }
                    """))
            .andExpect(status().is4xxClientError())
            .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    void consentCanBeSavedAndLoaded() {
        String clientId = registeredClientRepository.findByClientId("oidc-client").getId();
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(clientId, "user")
            .authority(new SimpleGrantedAuthority("SCOPE_api.read"))
            .build();
        authorizationConsentService.save(consent);
        assertNotNull(authorizationConsentService.findById(clientId, "user"));
        authorizationConsentService.remove(consent);
    }

    @Test
    void oidcDiscoveryAndAuthorizationCodeEntryPointWork() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("http://localhost:9000"));

        mockMvc.perform(get("/oauth2/authorize")
                .accept(MediaType.TEXT_HTML)
                .queryParam("response_type", "code")
                .queryParam("client_id", "oidc-client")
                .queryParam("redirect_uri", "https://oauth.pstmn.io/v1/browser-callback")
                .queryParam("scope", "openid profile api.read")
                .queryParam("state", "test-state")
                .queryParam("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .queryParam("code_challenge_method", "S256"))
            .andExpect(status().is3xxRedirection())
            .andExpect(result -> assertTrue(result.getResponse().getRedirectedUrl().endsWith("/login")));
    }

    @Test
    void loginPageRenders() throws Exception {
        String loginPage = mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andReturn().getResponse().getContentAsString();
        assertEquals(1, StringUtils.countOccurrencesOf(loginPage, "name=\"_csrf\""));

        mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", "user")
                .param("password", "test-password"))
            .andExpect(status().is3xxRedirection())
            .andExpect(authenticated().withUsername("user"));

        mockMvc.perform(get("/").with(user("user")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("user"));
    }

}
