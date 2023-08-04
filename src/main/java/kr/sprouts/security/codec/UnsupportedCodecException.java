package kr.sprouts.security.codec;

class UnsupportedCodecException extends RuntimeException {
    UnsupportedCodecException() {
        super("Unsupported codec.");
    }
}
