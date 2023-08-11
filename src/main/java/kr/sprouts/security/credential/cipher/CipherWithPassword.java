package kr.sprouts.security.credential.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

class CipherWithPassword implements Cipher<byte[]> {
    @NotBlank
    private final String encryptAlgorithm;
    @NotBlank
    private final String keyAlgorithm;
    @NotNull @Size
    private final Integer ivSize;
    @NotNull @Size
    private final Integer saltSize;
    @NotNull @Size
    private final Integer keySize;
    @NotNull @Size
    private final Integer keySpecIterationCount;
    @NotNull @Size
    private final Integer parameterIterationCount;

    CipherWithPassword(@NotBlank String encryptAlgorithm, @NotNull @Size Integer ivSize, @NotNull @Size Integer saltSize, @NotNull @Size Integer keySize, @NotNull @Size Integer keySpecIterationCount, @NotNull @Size Integer parameterIterationCount) {
        this.encryptAlgorithm = encryptAlgorithm;
        this.keyAlgorithm = encryptAlgorithm;
        this.ivSize = ivSize;
        this.saltSize = saltSize;
        this.keySize = keySize;
        this.keySpecIterationCount = keySpecIterationCount;
        this.parameterIterationCount = parameterIterationCount;
    }

    @Override
    public byte[] generateSecret() {
        try {
            byte[] password = new byte[keySize];
            new SecureRandom().nextBytes(password);

            return password;
        } catch (RuntimeException e) {
            throw new GenerateSecretException(e);
        }
    }

    private char[] toCharArray(@NotEmpty byte[] bytes) {
        StringBuilder buffer = new StringBuilder();

        for (byte aByte : bytes) {
            if (aByte >= 32 && aByte != 92 && aByte != 127) {
                buffer.append((char) aByte);
            } else {
                String temp;
                if (aByte == 92) {
                    buffer.append("\\\\");
                } else {
                    temp = String.format("\\0x%02x", aByte);
                    buffer.append(temp);
                }
            }
        }

        return buffer.toString().toCharArray();
    }

    @Override
    public byte[] encrypt(@NotBlank String plainText, @NotEmpty byte[] secret) {
        try {
            byte[] salt = new byte[saltSize];
            new SecureRandom().nextBytes(salt);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            KeySpec keySpec = new PBEKeySpec(toCharArray(secret), salt, keySpecIterationCount, keySize);
            SecretKey key = keyFactory.generateSecret(keySpec);

            byte[] iv = new byte[ivSize];
            new SecureRandom().nextBytes(iv);

            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, parameterIterationCount, new IvParameterSpec(iv));

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);

            byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(salt);
            outputStream.write(iv);
            outputStream.write(encryptedText);

            return outputStream.toByteArray();
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IOException |
                 InvalidKeyException e) {
            throw new EncryptException(e);
        }
    }

    @Override
    public byte[] decrypt(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret) {
        try {
            if (encryptedBytes.length < saltSize + ivSize) throw new DecryptException();

            byte[] salt = Arrays.copyOfRange(encryptedBytes, 0, saltSize);
            byte[] iv = Arrays.copyOfRange(encryptedBytes, saltSize, (saltSize + ivSize));
            byte[] encryptedText = Arrays.copyOfRange(encryptedBytes, (saltSize + ivSize), encryptedBytes.length);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(encryptAlgorithm);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            KeySpec keySpec = new PBEKeySpec(toCharArray(secret), salt, keySpecIterationCount, keySize);
            SecretKey key = keyFactory.generateSecret(keySpec);
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, parameterIterationCount, new IvParameterSpec(iv));

            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, paramSpec);

            return cipher.doFinal(encryptedText);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new DecryptException(e);
        }
    }

    @Override
    public String decryptToString(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret) {
        return new String(decrypt(encryptedBytes, secret));
    }
}
