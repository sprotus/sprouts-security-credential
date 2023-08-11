package kr.sprouts.security.credential.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class CipherWithKeyPair implements Cipher<KeyPair> {
    private final String encryptAlgorithm;
    private final String keyAlgorithm;
    private final Integer keySize;

    CipherWithKeyPair(String encryptAlgorithm, String keyAlgorithm, Integer keySize) {
        this.encryptAlgorithm = encryptAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
    }

    @Override
    public KeyPair generateSecret() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm);
            keyPairGen.initialize(keySize);

            return keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public byte[] encrypt(String plainText, byte[] privateKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, privateKey);

            return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new EncryptException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedBytes, byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, publicKey);

            return cipher.doFinal(encryptedBytes);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new DecryptException(e);
        }
    }

    @Override
    public String decryptToString(byte[] encryptedBytes, byte[] publicKeyBytes) {
        return new String(decrypt(encryptedBytes, publicKeyBytes));
    }
}
