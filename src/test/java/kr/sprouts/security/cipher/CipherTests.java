package kr.sprouts.security.cipher;

import kr.sprouts.security.codec.Codec;
import kr.sprouts.security.codec.CodecType;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CipherTests {
    Logger log = Logger.getLogger(this.getClass().getName());
    Codec codec = CodecType.BASE64_URL.getCodecSupplier().get();
    String plainText = "Plain text.";

    @Test
    void encryptAndDecrypt() {

        for (CipherAlgorithm cipherAlgorithm : CipherAlgorithm.values()) {
            log.info("name : " + cipherAlgorithm.name());

            Cipher<?> cipher = cipherAlgorithm.getCipherSupplier().get();

            Object secret = cipher.generateSecret();

            if (secret instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) secret;

                String encodedSecretKey = codec.encodeToString(secretKey.getEncoded());
                log.info("EncodedSecretKey : " + encodedSecretKey);

                byte[] encryptedText = cipher.encrypt(plainText, secretKey.getEncoded());
                String encodeAndEncryptedText = codec.encodeToString(encryptedText);
                log.info("EncodeAndEncryptedText : " + encodeAndEncryptedText);

                String decryptedText = cipher.decryptToString(encryptedText, secretKey.getEncoded());
                log.info(decryptedText);

                assertEquals(plainText, decryptedText);
            } else if (secret instanceof byte[]) {
                byte[] password = (byte[]) secret;

                String encodedPassword = codec.encodeToString(password);
                log.info("EncodedPassword : " + encodedPassword);

                byte[] encryptedText = cipher.encrypt(plainText, password);
                String encodeAndEncryptedText = codec.encodeToString(encryptedText);
                log.info("EncodeAndEncryptedText" + encodeAndEncryptedText);

                String decryptedText = cipher.decryptToString(encryptedText, password);
                log.info(decryptedText);

                assertEquals(plainText, decryptedText);
            } else if (secret instanceof KeyPair) {
                KeyPair keyPair = (KeyPair) secret;

                byte[] publicKey = keyPair.getPublic().getEncoded();
                byte[] privateKey = keyPair.getPrivate().getEncoded();

                String encodedPublicKey = codec.encodeToString(publicKey);
                String encodedPrivateKey = codec.encodeToString(privateKey);

                log.info("EncodedPublicKey : " + encodedPublicKey);
                log.info("EncodedPrivateKey : " + encodedPrivateKey);

                byte[] encryptedText = cipher.encrypt(plainText, privateKey);
                String encodeAndEncryptedText = codec.encodeToString(encryptedText);

                log.info("EncodeAndEncryptedText: " + encodeAndEncryptedText);

                String decryptedText = cipher.decryptToString(encryptedText, publicKey);
                log.info(decryptedText);

                assertEquals(plainText, decryptedText);
            }
        }
    }
}
