package kr.sprouts.security.credential.cipher;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CipherTests {
    Logger log = Logger.getLogger(this.getClass().getName());
    @Test
    void encryptAndDecrypt() {
        String plainText = "Plain text.";

        for (CipherAlgorithm cipherAlgorithm : CipherAlgorithm.values()) {
            Cipher<?> cipher = cipherAlgorithm.getCipherSupplier().get();

            Object secret = cipher.generateSecret();

            if (secret instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) secret;

                byte[] encryptedText = cipher.encrypt(plainText, secretKey.getEncoded());
                String decryptedText = cipher.decryptToString(encryptedText, secretKey.getEncoded());

                assertEquals(plainText, decryptedText);
            } else if (secret instanceof byte[]) {
                byte[] password = (byte[]) secret;

                byte[] encryptedText = cipher.encrypt(plainText, password);
                String decryptedText = cipher.decryptToString(encryptedText, password);

                assertEquals(plainText, decryptedText);
            } else if (secret instanceof KeyPair) {
                KeyPair keyPair = (KeyPair) secret;

                byte[] publicKey = keyPair.getPublic().getEncoded();
                byte[] privateKey = keyPair.getPrivate().getEncoded();

                byte[] encryptedText = cipher.encrypt(plainText, privateKey);
                String decryptedText = cipher.decryptToString(encryptedText, publicKey);

                assertEquals(plainText, decryptedText);
            }

            if (log.isLoggable(Level.INFO)) {
                log.info(String.format("Cipher algorithm '%s' test complete.", cipherAlgorithm.getName()));
            }
        }
    }
}
