package kr.sprouts.security.jwt;

class JwtParseException extends RuntimeException {
    JwtParseException(Throwable cause) {
        super(cause);
    }
}
