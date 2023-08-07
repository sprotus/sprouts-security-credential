package kr.sprouts.security.credential;

import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;

class CipherCredential implements Credential<byte[]> {
    private static final Codec codec = CodecType.BASE64_URL.getCodecSupplier().get();
    private final byte[] value;

    private CipherCredential(byte[] value) {
        this.value = value;
    }

    static CipherCredential of(byte[] encryptedBytes) {
        return new CipherCredential(encryptedBytes);
    }

    byte[] getEncoded() {
        return getValue();
    }

    String getEncodedString() {
        return codec.encodeToString(getValue());
    }

    @Override
    public byte[] getValue() {
        return value;
    }
}
