package kr.sprouts.security.credential.crypto;

public interface Cipher<T> {
    T generateSecret();
    byte[] encrypt(String plainText, byte[] secret);
    byte[] decrypt(byte[] encryptedBytes, byte[] secret);
    String decryptToString(byte[] encryptedBytes, byte[] secret);
}
