package kr.sprouts.security.codec;

public interface Codec {
    byte[] encode(byte[] decodedBytes);
    String encodeToString(byte[] decodedBytes);
    byte[] decode(byte[] encodedBytes);
    byte[] decode(String encodedString);
}
