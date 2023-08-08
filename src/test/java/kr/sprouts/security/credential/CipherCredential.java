package kr.sprouts.security.credential;

class CipherCredential extends Credential<byte[]> {

    public CipherCredential(String key, byte[] value) {
        super(key, value);
    }

    public static CipherCredential of(String key, byte[] value) {
        return new CipherCredential(key, value);
    }
}
