package kr.sprouts.security.credential.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

class CipherWithSecretKey implements Cipher<SecretKey> {
    @NotBlank
    private final String encryptAlgorithm;
    @NotBlank
    private final String keyAlgorithm;
    @NotNull @Size
    private final Integer ivSize;
    @NotNull @Size
    private final Integer keySize;

    CipherWithSecretKey(@NotBlank String encryptAlgorithm, @NotBlank String keyAlgorithm, @NotNull @Size Integer ivSize, @NotNull @Size Integer keySize) {
        this.encryptAlgorithm = encryptAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.ivSize = ivSize;
        this.keySize = keySize;
    }

    @Override
    public SecretKey generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
            keyGenerator.init(keySize);

            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public byte[] encrypt(@NotBlank String plainText, @NotEmpty byte[] secret) {
        try {
            SecretKey secretKey = new SecretKeySpec(secret, keyAlgorithm);

            int secretKeySize = (secretKey.getEncoded().length * 8);

            if(secretKeySize != keySize) throw new EncryptException(String.format("The expected secret key size is %s bits, but %s bits were provided.", keySize, secretKeySize));

            byte[] iv = new byte[ivSize];
            new SecureRandom().nextBytes(iv);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(iv);
            outputStream.write(encryptedText);

            return outputStream.toByteArray();
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | BadPaddingException | IOException | InvalidKeyException e) {
            throw new EncryptException(e);
        }
    }

    @Override
    public byte[] decrypt(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret) {
        try {
            SecretKey secretKey = new SecretKeySpec(secret, keyAlgorithm);

            if (encryptedBytes.length < ivSize) throw new DecryptException();

            byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, ivSize);
            byte[] encryptedText = Arrays.copyOfRange(encryptedBytes, ivSize, encryptedBytes.length);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            return cipher.doFinal(encryptedText);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new DecryptException(e);
        }
    }

    @Override
    public String decryptToString(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret) {
        return new String(decrypt(encryptedBytes, secret));
    }
}
