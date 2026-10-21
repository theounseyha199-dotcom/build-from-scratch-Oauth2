package istad.ha.springauthorizationservice.oauth;

import istad.ha.springauthorizationservice.service.CustomCodeService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class CustomCodeGrantAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizations;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final CustomCodeService codes;
    private final UserDetailsService userDetailsService;

    public CustomCodeGrantAuthenticationProvider(OAuth2AuthorizationService authorizations,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, CustomCodeService codes,
            UserDetailsService userDetailsService) {
        this.authorizations = authorizations;
        this.tokenGenerator = tokenGenerator;
        this.codes = codes;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomCodeGrantAuthenticationToken grant = (CustomCodeGrantAuthenticationToken) authentication;
        if (!(grant.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal)
            || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        RegisteredClient client = clientPrincipal.getRegisteredClient();
        if (!client.getAuthorizationGrantTypes().contains(grant.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        String principalName = codes.consume(grant.getCode(), client.getId());
        if (principalName == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(principalName);
        } catch (UsernameNotFoundException ex) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (!user.isEnabled()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
            .registeredClient(client)
            .principal(UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()))
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(grant.getGrantType())
            .authorizationGrant(grant)
            .authorizedScopes(client.getScopes())
            .build();
        OAuth2Token generated = tokenGenerator.generate(context);
        if (generated == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
            generated.getTokenValue(), generated.getIssuedAt(), generated.getExpiresAt(), client.getScopes());
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
            .principalName(principalName)
            .authorizationGrantType(grant.getGrantType())
            .authorizedScopes(client.getScopes());
        if (generated instanceof ClaimAccessor claims) {
            builder.token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims.getClaims()));
        } else {
            builder.accessToken(accessToken);
        }
        authorizations.save(builder.build());
        return new OAuth2AccessTokenAuthenticationToken(client, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
