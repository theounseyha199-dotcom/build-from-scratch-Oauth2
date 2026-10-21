package istad.ha.springauthorizationservice.oauth;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public final class CustomCodeGrant {
    public static final AuthorizationGrantType GRANT_TYPE =
        new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:custom_code");

    private CustomCodeGrant() {
    }
}
