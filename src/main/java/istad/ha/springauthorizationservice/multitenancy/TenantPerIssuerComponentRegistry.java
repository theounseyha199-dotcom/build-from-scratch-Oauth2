package istad.ha.springauthorizationservice.multitenancy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class TenantPerIssuerComponentRegistry {
    private final ConcurrentMap<String, Map<Class<?>, Object>> registry = new ConcurrentHashMap<>();
    private final String defaultIssuer;

    public TenantPerIssuerComponentRegistry(@org.springframework.beans.factory.annotation.Value("${app.oauth.issuer}") String defaultIssuer) {
        this.defaultIssuer = defaultIssuer.replaceAll("/+$", "");
    }

    public <T> void register(String issuer, Class<T> componentClass, T component) {
        Assert.hasText(issuer, "issuer cannot be empty");
        Assert.notNull(componentClass, "componentClass cannot be null");
        Assert.notNull(component, "component cannot be null");
        registry.computeIfAbsent(issuer, ignored -> new ConcurrentHashMap<>()).put(componentClass, component);
    }

    public <T> T get(Class<T> componentClass) {
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        String issuer = context == null ? defaultIssuer : context.getIssuer();
        return get(issuer, componentClass);
    }

    public <T> T get(String issuer, Class<T> componentClass) {
        Map<Class<?>, Object> components = registry.get(issuer);
        return components == null ? null : componentClass.cast(components.get(componentClass));
    }

    public String issuer(String tenantId) {
        return defaultIssuer + "/" + tenantId;
    }

    public String rootIssuer() {
        return defaultIssuer;
    }
}
