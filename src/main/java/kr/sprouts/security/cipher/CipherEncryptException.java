package kr.sprouts.security.cipher;

class CipherEncryptException extends RuntimeException {

    CipherEncryptException(String message) {
        super(message);
    }

    CipherEncryptException(Throwable cause) {
        super(cause);
    }
}
