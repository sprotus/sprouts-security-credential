package kr.sprouts.security.credential.codec;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

public interface Codec {
    byte[] encode(@NotEmpty byte[] decodedBytes);
    String encodeToString(@NotEmpty byte[] decodedBytes);
    byte[] decode(@NotEmpty byte[] encodedBytes);
    byte[] decode(@NotBlank String encodedString);
}
