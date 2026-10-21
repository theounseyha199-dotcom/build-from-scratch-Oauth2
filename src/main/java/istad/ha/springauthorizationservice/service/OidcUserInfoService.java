package istad.ha.springauthorizationservice.service;

import java.util.Set;

import istad.ha.springauthorizationservice.entity.User;
import istad.ha.springauthorizationservice.repository.UserRepository;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class OidcUserInfoService {
    private final UserRepository users;

    public OidcUserInfoService(UserRepository users) {
        this.users = users;
    }

    public OidcUserInfo loadUser(String username, Set<String> scopes) {
        User user = users.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("OIDC user was not found"));
        OidcUserInfo.Builder info = OidcUserInfo.builder().subject(user.getUsername());
        if (scopes.contains(OidcScopes.PROFILE)) {
            info.preferredUsername(user.getUsername());
            if (StringUtils.hasText(user.getDisplayName())) {
                info.name(user.getDisplayName());
            }
        }
        if (scopes.contains(OidcScopes.EMAIL) && StringUtils.hasText(user.getEmail())) {
            info.email(user.getEmail()).emailVerified(false);
        }
        return info.build();
    }
}
