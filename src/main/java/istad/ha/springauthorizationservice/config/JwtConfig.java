package istad.ha.springauthorizationservice.config;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;

@Configuration
public class JwtConfig {

    private static final Logger logger = LoggerFactory.getLogger(JwtConfig.class);

    @Bean
    RSAKey rsaKey(
            @Value("${app.oauth.signing-private-key-file:}") String privateKeyFile,
            @Value("${app.oauth.signing-public-key-file:}") String publicKeyFile) {
        if (StringUtils.hasText(privateKeyFile) != StringUtils.hasText(publicKeyFile)) {
            throw new IllegalStateException("Set both AUTH_SIGNING_PRIVATE_KEY_FILE and AUTH_SIGNING_PUBLIC_KEY_FILE");
        }
        try {
            KeyPair pair;
            if (StringUtils.hasText(privateKeyFile)) {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
                    decodePem(Path.of(privateKeyFile), "PRIVATE KEY")));
                RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(
                    decodePem(Path.of(publicKeyFile), "PUBLIC KEY")));
                pair = new KeyPair(publicKey, privateKey);
                verifyPair(pair);
            } else {
                logger.warn("Using a temporary signing key. Configure both signing key files to keep JWTs valid after restart.");
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                pair = generator.generateKeyPair();
            }
            String keyId = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded()));
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID(keyId)
                .build();
        } catch (Exception exception) {
            throw new IllegalStateException("Could not load the RSA signing key", exception);
        }
    }

    private static byte[] decodePem(Path path, String type) throws Exception {
        String pem = Files.readString(path, StandardCharsets.US_ASCII).trim();
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        if (!pem.startsWith(begin) || !pem.endsWith(end)) {
            throw new IllegalArgumentException("Expected " + type + " PEM in " + path);
        }
        return Base64.getMimeDecoder().decode(pem.substring(begin.length(), pem.length() - end.length()));
    }

    private static void verifyPair(KeyPair pair) throws Exception {
        byte[] challenge = "authorization-server-signing-key".getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(challenge);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(challenge);
        if (!verifier.verify(signer.sign())) {
            throw new IllegalArgumentException("Signing private and public keys do not match");
        }
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey, @Value("${app.oauth.issuer}") String issuer) throws JOSEException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
}
