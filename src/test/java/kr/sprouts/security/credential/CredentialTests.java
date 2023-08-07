package kr.sprouts.security.credential;

import kr.sprouts.security.credential.cipher.Cipher;
import kr.sprouts.security.credential.cipher.CipherAlgorithm;
import kr.sprouts.security.credential.jwt.Jwt;
import kr.sprouts.security.credential.jwt.JwtAlgorithm;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialTests {
    Logger log = Logger.getLogger(this.getClass().getName());

    private Principal initializePrincipal() {
        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();

        return Principal.of(issuer, audience, subject);
    }

    @Test
    void cipherProvideAndConsume() {
        Principal principal = initializePrincipal();

        for (CipherAlgorithm cipherAlgorithm : CipherAlgorithm.values()) {
            Cipher<?> cipher = cipherAlgorithm.getCipherSupplier().get();

            CipherCredentialProvider cipherCredentialProvider = CipherCredentialProvider.fromCipher(cipher);
            CipherCredentialConsumer cipherCredentialConsumer = CipherCredentialConsumer.fromCipher(cipher);

            Object secret = cipher.generateSecret();
            
            if (secret instanceof SecretKey) {  // 대칭키
                SecretKey secretKey = (SecretKey) secret;

                CipherCredential cipherCredential = cipherCredentialProvider.provide(CipherCredentialParameter.of(principal), secretKey.getEncoded());
                Principal consumedPrincipal = cipherCredentialConsumer.consume(cipherCredential, secretKey.getEncoded());

                assertEquals(principal.getProviderId(), consumedPrincipal.getProviderId());
            } else if (secret instanceof KeyPair) { // 비대칭키
                KeyPair keyPair = (KeyPair) secret;

                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                CipherCredential cipherCredential = cipherCredentialProvider.provide(CipherCredentialParameter.of(principal), privateKey.getEncoded());
                Principal consumedPrincipal = cipherCredentialConsumer.consume(cipherCredential, publicKey.getEncoded());

                assertEquals(principal.getProviderId(), consumedPrincipal.getProviderId());
            } else if (secret instanceof byte[]) { // 비밀번호 암호화
                byte[] password = (byte[]) secret;

                CipherCredential cipherCredential = cipherCredentialProvider.provide(CipherCredentialParameter.of(principal), password);
                Principal consumedPrincipal = cipherCredentialConsumer.consume(cipherCredential, password);

                assertEquals(principal.getProviderId(), consumedPrincipal.getProviderId());
            }

            log.info(String.format("Cipher algorithm '%s' test complete.", cipherAlgorithm.getName()));
        }
    }

    @Test
    void jwtCreateAndParse() {
        Principal principal = initializePrincipal();
        Long validityInMinute  = 60L;

        for (JwtAlgorithm jwtAlgorithm : JwtAlgorithm.values()) {
            Jwt<?> jwt = jwtAlgorithm.getJwtSupplier().get();

            JwtCredentialProvider jwtCredentialProvider = JwtCredentialProvider.fromJwt(jwt);
            JwtCredentialConsumer jwtCredentialConsumer = JwtCredentialConsumer.fromJwt(jwt);

            Object secret = jwt.generateSecret();

            if (secret instanceof SecretKey) { // 대칭키
                SecretKey secretKey = (SecretKey) secret;

                JwtCredential jwtCredential = jwtCredentialProvider.provide(JwtCredentialParameter.of(principal, validityInMinute), secretKey.getEncoded());
                Principal consumedPrincipal = jwtCredentialConsumer.consume(jwtCredential, secretKey.getEncoded());

                assertEquals(principal.getProviderId(), consumedPrincipal.getProviderId());
            } else if (secret instanceof KeyPair) { // 비대칭키
                KeyPair keyPair = (KeyPair) secret;

                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                JwtCredential jwtCredential = jwtCredentialProvider.provide(JwtCredentialParameter.of(principal, validityInMinute), privateKey.getEncoded());
                Principal consumedPrincipal = jwtCredentialConsumer.consume(jwtCredential, publicKey.getEncoded());

                assertEquals(principal.getProviderId(), consumedPrincipal.getProviderId());
            }

            log.info(String.format("Jwt algorithm '%s' test complete.", jwtAlgorithm.getName()));
        }
    }
}