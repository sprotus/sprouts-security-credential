package kr.sprouts.security.credential.cipher;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
public interface Cipher<T> {
    T generateSecret();
    byte[] encrypt(@NotBlank String plainText, @NotEmpty byte[] secret);
    byte[] decrypt(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret);
    String decryptToString(@NotEmpty byte[] encryptedBytes, @NotEmpty byte[] secret);
}
