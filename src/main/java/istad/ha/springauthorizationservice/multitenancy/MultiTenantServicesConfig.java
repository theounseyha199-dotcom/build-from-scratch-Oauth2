package istad.ha.springauthorizationservice.multitenancy;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import istad.ha.springauthorizationservice.service.JpaOAuth2AuthorizationConsentService;
import istad.ha.springauthorizationservice.service.JpaOAuth2AuthorizationService;
import istad.ha.springauthorizationservice.service.JpaRegisteredClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;

@Configuration
public class MultiTenantServicesConfig {
    @Bean
    @Primary
    DataSource rootDataSource(DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }

    @Bean("issuer1-data-source")
    EmbeddedDatabase issuer1DataSource() {
        return tenantDataSource("issuer1-db");
    }

    @Bean("issuer2-data-source")
    EmbeddedDatabase issuer2DataSource() {
        return tenantDataSource("issuer2-db");
    }

    private EmbeddedDatabase tenantDataSource(String name) {
        return new EmbeddedDatabaseBuilder().setName(name).setType(EmbeddedDatabaseType.H2)
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
            .build();
    }

    @Bean
    @Primary
    RegisteredClientRepository tenantRegisteredClientRepository(JpaRegisteredClientRepository root,
            TenantPerIssuerComponentRegistry registry,
            @org.springframework.beans.factory.annotation.Qualifier("issuer1-data-source") EmbeddedDatabase issuer1,
            @org.springframework.beans.factory.annotation.Qualifier("issuer2-data-source") EmbeddedDatabase issuer2) {
        registry.register(registry.rootIssuer(), RegisteredClientRepository.class, root);
        registry.register(registry.issuer("issuer1"), RegisteredClientRepository.class,
            new JdbcRegisteredClientRepository(new JdbcTemplate(issuer1)));
        registry.register(registry.issuer("issuer2"), RegisteredClientRepository.class,
            new JdbcRegisteredClientRepository(new JdbcTemplate(issuer2)));
        return new RegisteredClientRepository() {
            private RegisteredClientRepository delegate() {
                return required(registry.get(RegisteredClientRepository.class), "RegisteredClientRepository");
            }
            public void save(RegisteredClient client) { delegate().save(client); }
            public RegisteredClient findById(String id) { return delegate().findById(id); }
            public RegisteredClient findByClientId(String id) { return delegate().findByClientId(id); }
        };
    }

    @Bean
    ApplicationRunner seedTenantClients(TenantPerIssuerComponentRegistry registry,
            PasswordEncoder passwordEncoder,
            @Value("${app.oauth.tenant-client-secret}") String tenantClientSecret) {
        return args -> {
            for (String tenantId : java.util.List.of("issuer1", "issuer2")) {
                RegisteredClientRepository clients = required(registry.get(registry.issuer(tenantId), RegisteredClientRepository.class),
                    "RegisteredClientRepository");
                String clientId = tenantId + "-client";
                if (clients.findByClientId(clientId) == null) {
                    clients.save(RegisteredClient.withId(java.util.UUID.randomUUID().toString())
                        .clientId(clientId)
                        .clientSecret(passwordEncoder.encode(tenantClientSecret))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("api.read")
                        .build());
                }
            }
        };
    }

    @Bean
    @Primary
    OAuth2AuthorizationService tenantAuthorizationService(JpaOAuth2AuthorizationService root,
            TenantPerIssuerComponentRegistry registry,
            @org.springframework.beans.factory.annotation.Qualifier("issuer1-data-source") EmbeddedDatabase issuer1,
            @org.springframework.beans.factory.annotation.Qualifier("issuer2-data-source") EmbeddedDatabase issuer2) {
        registry.register(registry.rootIssuer(), OAuth2AuthorizationService.class, root);
        registry.register(registry.issuer("issuer1"), OAuth2AuthorizationService.class,
            new JdbcOAuth2AuthorizationService(new JdbcTemplate(issuer1),
                required(registry.get(registry.issuer("issuer1"), RegisteredClientRepository.class), "RegisteredClientRepository")));
        registry.register(registry.issuer("issuer2"), OAuth2AuthorizationService.class,
            new JdbcOAuth2AuthorizationService(new JdbcTemplate(issuer2),
                required(registry.get(registry.issuer("issuer2"), RegisteredClientRepository.class), "RegisteredClientRepository")));
        return new OAuth2AuthorizationService() {
            private OAuth2AuthorizationService delegate() {
                return required(registry.get(OAuth2AuthorizationService.class), "OAuth2AuthorizationService");
            }
            public void save(OAuth2Authorization authorization) { delegate().save(authorization); }
            public void remove(OAuth2Authorization authorization) { delegate().remove(authorization); }
            public OAuth2Authorization findById(String id) { return delegate().findById(id); }
            public OAuth2Authorization findByToken(String token, OAuth2TokenType type) { return delegate().findByToken(token, type); }
        };
    }

    @Bean
    @Primary
    OAuth2AuthorizationConsentService tenantConsentService(JpaOAuth2AuthorizationConsentService root,
            TenantPerIssuerComponentRegistry registry,
            @org.springframework.beans.factory.annotation.Qualifier("issuer1-data-source") EmbeddedDatabase issuer1,
            @org.springframework.beans.factory.annotation.Qualifier("issuer2-data-source") EmbeddedDatabase issuer2) {
        registry.register(registry.rootIssuer(), OAuth2AuthorizationConsentService.class, root);
        registry.register(registry.issuer("issuer1"), OAuth2AuthorizationConsentService.class,
            new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(issuer1),
                required(registry.get(registry.issuer("issuer1"), RegisteredClientRepository.class), "RegisteredClientRepository")));
        registry.register(registry.issuer("issuer2"), OAuth2AuthorizationConsentService.class,
            new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(issuer2),
                required(registry.get(registry.issuer("issuer2"), RegisteredClientRepository.class), "RegisteredClientRepository")));
        return new OAuth2AuthorizationConsentService() {
            private OAuth2AuthorizationConsentService delegate() {
                return required(registry.get(OAuth2AuthorizationConsentService.class), "OAuth2AuthorizationConsentService");
            }
            public void save(OAuth2AuthorizationConsent consent) { delegate().save(consent); }
            public void remove(OAuth2AuthorizationConsent consent) { delegate().remove(consent); }
            public OAuth2AuthorizationConsent findById(String clientId, String name) { return delegate().findById(clientId, name); }
        };
    }

    @Bean
    @Primary
    JWKSource<SecurityContext> tenantJwkSource(RSAKey rootKey, TenantPerIssuerComponentRegistry registry) {
        registry.register(registry.rootIssuer(), JWKSet.class, new JWKSet(rootKey));
        registry.register(registry.issuer("issuer1"), JWKSet.class, new JWKSet(generateKey()));
        registry.register(registry.issuer("issuer2"), JWKSet.class, new JWKSet(generateKey()));
        return (selector, context) -> selector.select(required(registry.get(JWKSet.class), "JWKSet"));
    }

    @Bean
    @Primary
    JwtDecoder tenantJwtDecoder(@Qualifier("jwtDecoder") JwtDecoder rootDecoder,
            JWKSource<SecurityContext> jwkSource, TenantPerIssuerComponentRegistry registry) {
        registry.register(registry.rootIssuer(), JwtDecoder.class, rootDecoder);
        for (String tenantId : java.util.List.of("issuer1", "issuer2")) {
            String issuer = registry.issuer(tenantId);
            RSAKey key = (RSAKey) required(registry.get(issuer, JWKSet.class), "JWKSet").getKeys().get(0);
            try {
                NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
                decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
                registry.register(issuer, JwtDecoder.class, decoder);
            } catch (com.nimbusds.jose.JOSEException ex) {
                throw new IllegalStateException("Could not configure tenant JWT decoder", ex);
            }
        }
        return token -> required(registry.get(JwtDecoder.class), "JwtDecoder").decode(token);
    }

    private static <T> T required(T value, String name) {
        Assert.state(value != null, name + " not found for requested issuer");
        return value;
    }

    private static RSAKey generateKey() {
        try {
            var generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) pair.getPublic())
                .privateKey((java.security.interfaces.RSAPrivateKey) pair.getPrivate())
                .keyID(java.util.UUID.randomUUID().toString()).build();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not create tenant signing key", ex);
        }
    }
}
