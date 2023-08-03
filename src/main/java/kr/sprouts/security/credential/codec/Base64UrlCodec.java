package kr.sprouts.security.credential.codec;

import java.util.Base64;

class Base64UrlCodec implements Codec {
    Base64UrlCodec() { }

    @Override
    public byte[] encode(byte[] decodedBytes) {
        return Base64.getUrlEncoder().encode(decodedBytes);
    }

    @Override
    public String encodeToString(byte[] decodedBytes) {
        return Base64.getUrlEncoder().encodeToString(decodedBytes);
    }

    @Override
    public byte[] decode(byte[] encodedBytes) {
        return Base64.getUrlDecoder().decode(encodedBytes);
    }

    @Override
    public byte[] decode(String encodedString) {
        return Base64.getUrlDecoder().decode(encodedString);
    }
}
