package istad.ha.springauthorizationservice.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class CustomCodeService {
    private final JdbcTemplate jdbcTemplate;
    private final SecureRandom random = new SecureRandom();

    public CustomCodeService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String issue(String registeredClientId, String principalName) {
        jdbcTemplate.update("delete from custom_grant_code where expires_at < ?",
            java.sql.Timestamp.from(Instant.now()));
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        jdbcTemplate.update("insert into custom_grant_code (code_hash, registered_client_id, principal_name, expires_at, used) values (?, ?, ?, ?, false)",
            hash(code), registeredClientId, principalName, java.sql.Timestamp.from(Instant.now().plusSeconds(300)));
        return code;
    }

    public String consume(String code, String registeredClientId) {
        String codeHash = hash(code);
        int updated = jdbcTemplate.update("update custom_grant_code set used = true where code_hash = ? and registered_client_id = ? and used = false and expires_at > ?",
            codeHash, registeredClientId, java.sql.Timestamp.from(Instant.now()));
        if (updated != 1) {
            return null;
        }
        return jdbcTemplate.queryForObject("select principal_name from custom_grant_code where code_hash = ?", String.class, codeHash);
    }

    private static String hash(String code) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(code.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
