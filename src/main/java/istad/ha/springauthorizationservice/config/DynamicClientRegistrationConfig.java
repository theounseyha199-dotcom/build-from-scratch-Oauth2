package istad.ha.springauthorizationservice.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

final class DynamicClientRegistrationConfig {

    private static final List<String> CUSTOM_METADATA = List.of("logo_uri", "contacts");

    private DynamicClientRegistrationConfig() {
    }

    static Consumer<List<AuthenticationProvider>> authenticationProviders() {
        Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter = registration -> {
            RegisteredClient client = new OidcClientRegistrationRegisteredClientConverter().convert(registration);
            ClientSettings.Builder settings = ClientSettings.withSettings(client.getClientSettings().getSettings());
            CUSTOM_METADATA.forEach(key -> {
                Object value = registration.getClaims().get(key);
                if (value != null) {
                    settings.setting(key, value);
                }
            });
            return RegisteredClient.from(client).clientSettings(settings.build()).build();
        };

        Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter = client -> {
            OidcClientRegistration registration = new RegisteredClientOidcClientRegistrationConverter().convert(client);
            Map<String, Object> claims = new HashMap<>(registration.getClaims());
            CUSTOM_METADATA.forEach(key -> {
                Object value = client.getClientSettings().getSetting(key);
                if (value != null) {
                    claims.put(key, value);
                }
            });
            return OidcClientRegistration.withClaims(claims).build();
        };

        return providers -> providers.forEach(authenticationProvider -> {
            if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
                provider.setAuthenticationValidator(
                    OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                        .andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
                        .andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
                        .andThen(OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR));
                provider.setRegisteredClientConverter(registeredClientConverter);
                provider.setClientRegistrationConverter(clientRegistrationConverter);
            }
            if (authenticationProvider instanceof OidcClientConfigurationAuthenticationProvider provider) {
                provider.setClientRegistrationConverter(clientRegistrationConverter);
            }
        });
    }
}
