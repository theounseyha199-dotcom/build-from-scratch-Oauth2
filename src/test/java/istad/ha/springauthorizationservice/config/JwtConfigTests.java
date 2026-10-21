package istad.ha.springauthorizationservice.config;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtConfigTests {

    @TempDir
    Path directory;

    @Test
    void loadsAStableSigningKeyFromPemFiles() throws Exception {
        KeyPair pair = newKeyPair();
        Path privateFile = writePem("private.pem", "PRIVATE KEY", pair.getPrivate().getEncoded());
        Path publicFile = writePem("public.pem", "PUBLIC KEY", pair.getPublic().getEncoded());

        JwtConfig config = new JwtConfig();
        var first = config.rsaKey(privateFile.toString(), publicFile.toString());
        var second = config.rsaKey(privateFile.toString(), publicFile.toString());

        assertEquals(first.getKeyID(), second.getKeyID());
        assertArrayEquals(pair.getPublic().getEncoded(), first.toRSAPublicKey().getEncoded());
        assertArrayEquals(pair.getPrivate().getEncoded(), first.toRSAPrivateKey().getEncoded());
    }

    @Test
    void rejectsMissingOrMismatchedKeyFiles() throws Exception {
        KeyPair privatePair = newKeyPair();
        KeyPair publicPair = newKeyPair();
        Path privateFile = writePem("private.pem", "PRIVATE KEY", privatePair.getPrivate().getEncoded());
        Path publicFile = writePem("public.pem", "PUBLIC KEY", publicPair.getPublic().getEncoded());

        JwtConfig config = new JwtConfig();
        assertThrows(IllegalStateException.class, () -> config.rsaKey(privateFile.toString(), ""));
        assertThrows(IllegalStateException.class,
            () -> config.rsaKey(privateFile.toString(), publicFile.toString()));
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private Path writePem(String name, String type, byte[] bytes) throws Exception {
        String pem = "-----BEGIN " + type + "-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(bytes)
            + "\n-----END " + type + "-----\n";
        return Files.writeString(directory.resolve(name), pem, StandardCharsets.US_ASCII);
    }
}
