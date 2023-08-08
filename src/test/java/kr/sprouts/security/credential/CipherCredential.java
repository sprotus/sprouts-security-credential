package kr.sprouts.security.credential;

class CipherCredential extends Credential<byte[]> {

    private CipherCredential(byte[] value) {
        super(value);
    }

    public static CipherCredential of(byte[] value) {
        return new CipherCredential(value);
    }
}
