package kr.sprouts.security.credential.codec;

class UnsupportedCodecException extends RuntimeException {
    UnsupportedCodecException() {
        super("Unsupported codec.");
    }
}
