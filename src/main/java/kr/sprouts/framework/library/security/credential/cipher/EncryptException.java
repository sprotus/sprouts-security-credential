package kr.sprouts.framework.library.security.credential.cipher;

public class EncryptException extends RuntimeException {

    public EncryptException(String message) {
        super(message);
    }

    public EncryptException(Throwable cause) {
        super(cause);
    }
}
