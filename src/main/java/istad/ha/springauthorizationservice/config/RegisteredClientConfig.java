package istad.ha.springauthorizationservice.config;

import java.util.UUID;
import istad.ha.springauthorizationservice.oauth.CustomCodeGrant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Configuration
public class RegisteredClientConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    ApplicationRunner seedRegisteredClients(
            RegisteredClientRepository registeredClientRepository,
            @Value("${app.oauth.client-id}") String clientId,
            @Value("${app.oauth.client-secret}") String clientSecret,
            @Value("${app.oauth.oidc-client-id}") String oidcClientId,
            @Value("${app.oauth.oidc-client-secret}") String oidcClientSecret,
            @Value("${app.oauth.oidc-redirect-uri}") String oidcRedirectUri,
            @Value("${app.oauth.postman-redirect-uri}") String postmanRedirectUri,
            @Value("${app.oauth.public-client-id}") String publicClientId,
            @Value("${app.oauth.public-redirect-uri}") String publicRedirectUri,
            @Value("${app.oauth.custom-client-id}") String customClientId,
            @Value("${app.oauth.custom-client-secret}") String customClientSecret,
            @Value("${app.oauth.registrar-client-id}") String registrarClientId,
            @Value("${app.oauth.registrar-client-secret}") String registrarClientSecret,
            PasswordEncoder passwordEncoder) {
        RegisteredClient postmanClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(passwordEncoder.encode(clientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("api.read")
            .scope("api.write")
            .build();

        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(oidcClientId)
            .clientSecret(passwordEncoder.encode(oidcClientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(oidcRedirectUri)
            .redirectUri(postmanRedirectUri)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("api.read")
            .clientSettings(ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true)
                .build())
            .build();

        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(publicClientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(publicRedirectUri)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)
                .build())
            .build();

        RegisteredClient customClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(customClientId)
            .clientSecret(passwordEncoder.encode(customClientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(CustomCodeGrant.GRANT_TYPE)
            .scope("api.read")
            .build();

        RegisteredClient registrarClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(registrarClientId)
            .clientSecret(passwordEncoder.encode(registrarClientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("client.create")
            .scope("client.read")
            .build();

        return args -> {
            if (registeredClientRepository.findByClientId(clientId) == null) {
                registeredClientRepository.save(postmanClient);
            }
            if (registeredClientRepository.findByClientId(oidcClientId) == null) {
                registeredClientRepository.save(oidcClient);
            }
            if (registeredClientRepository.findByClientId(publicClientId) == null) {
                registeredClientRepository.save(publicClient);
            }
            if (registeredClientRepository.findByClientId(customClientId) == null) {
                registeredClientRepository.save(customClient);
            }
            if (registeredClientRepository.findByClientId(registrarClientId) == null) {
                registeredClientRepository.save(registrarClient);
            }
        };
    }
}
