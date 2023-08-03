package kr.sprouts.security.credential.codec;

import java.util.Base64;

class Base64Codec implements Codec {
    Base64Codec() { }

    @Override
    public byte[] encode(byte[] decodedBytes) {
        return Base64.getEncoder().encode(decodedBytes);
    }

    @Override
    public String encodeToString(byte[] decodedBytes) {
        return Base64.getEncoder().encodeToString(decodedBytes);
    }

    @Override
    public byte[] decode(byte[] encodedBytes) {
        return Base64.getDecoder().decode(encodedBytes);
    }

    @Override
    public byte[] decode(String encodedString) {
        return Base64.getDecoder().decode(encodedString);
    }
}
