package kr.sprouts.security.credential.codec;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.Base64;

class Base64UrlCodec implements Codec {
    Base64UrlCodec() { }

    @Override
    public byte[] encode(@NotEmpty byte[] decodedBytes) {
        return Base64.getUrlEncoder().encode(decodedBytes);
    }

    @Override
    public String encodeToString(@NotEmpty byte[] decodedBytes) {
        return Base64.getUrlEncoder().encodeToString(decodedBytes);
    }

    @Override
    public byte[] decode(@NotEmpty byte[] encodedBytes) {
        return Base64.getUrlDecoder().decode(encodedBytes);
    }

    @Override
    public byte[] decode(@NotBlank String encodedString) {
        return Base64.getUrlDecoder().decode(encodedString);
    }
}
