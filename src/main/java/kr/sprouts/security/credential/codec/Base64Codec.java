package kr.sprouts.security.credential.codec;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.Base64;

class Base64Codec implements Codec {
    Base64Codec() { }

    @Override
    public byte[] encode(@NotEmpty byte[] decodedBytes) {
        return Base64.getEncoder().encode(decodedBytes);
    }

    @Override
    public String encodeToString(@NotEmpty byte[] decodedBytes) {
        return Base64.getEncoder().encodeToString(decodedBytes);
    }

    @Override
    public byte[] decode(@NotEmpty byte[] encodedBytes) {
        return Base64.getDecoder().decode(encodedBytes);
    }

    @Override
    public byte[] decode(@NotBlank String encodedString) {
        return Base64.getDecoder().decode(encodedString);
    }
}
