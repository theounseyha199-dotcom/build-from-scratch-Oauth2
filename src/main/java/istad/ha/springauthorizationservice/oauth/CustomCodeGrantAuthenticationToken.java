package istad.ha.springauthorizationservice.oauth;

import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomCodeGrantAuthenticationToken extends AbstractAuthenticationToken {
    private final String code;
    private final Authentication clientPrincipal;
    private final Map<String, Object> additionalParameters;

    public CustomCodeGrantAuthenticationToken(String code, Authentication clientPrincipal,
                                               Map<String, Object> additionalParameters) {
        super(java.util.Collections.emptyList());
        this.code = code;
        this.clientPrincipal = clientPrincipal;
        this.additionalParameters = Map.copyOf(additionalParameters);
    }

    public AuthorizationGrantType getGrantType() {
        return CustomCodeGrant.GRANT_TYPE;
    }

    public String getCode() {
        return code;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    @Override
    public Object getPrincipal() {
        return clientPrincipal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }
}
