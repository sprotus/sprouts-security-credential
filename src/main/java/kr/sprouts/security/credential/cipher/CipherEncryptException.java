package kr.sprouts.security.credential.cipher;

class CipherEncryptException extends RuntimeException {

    CipherEncryptException(String message) {
        super(message);
    }

    CipherEncryptException(Throwable cause) {
        super(cause);
    }
}
