package istad.ha.springauthorizationservice.config;

import istad.ha.springauthorizationservice.entity.User;
import istad.ha.springauthorizationservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

@Configuration
public class UserConfig {

    @Bean
    ApplicationRunner seedUser(
            UserRepository users,
            @Value("${app.oauth.user-name}") String userName,
            @Value("${app.oauth.user-password}") String userPassword,
            @Value("${app.oauth.user-display-name}") String displayName,
            @Value("${app.oauth.user-email}") String email,
            PasswordEncoder passwordEncoder) {
        return args -> {
            users.findByUsername(userName).ifPresentOrElse(existing -> {
                boolean changed = false;
                if (!StringUtils.hasText(existing.getDisplayName()) && StringUtils.hasText(displayName)) {
                    existing.setDisplayName(displayName);
                    changed = true;
                }
                if (!StringUtils.hasText(existing.getEmail()) && StringUtils.hasText(email)) {
                    existing.setEmail(email);
                    changed = true;
                }
                if (changed) {
                    users.save(existing);
                }
            }, () -> users.save(new User(userName, passwordEncoder.encode(userPassword), true, displayName, email)));
        };
    }
}
