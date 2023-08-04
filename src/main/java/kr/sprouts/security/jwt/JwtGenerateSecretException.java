package kr.sprouts.security.jwt;

class JwtGenerateSecretException extends RuntimeException {
    JwtGenerateSecretException(Throwable cause) {
        super(cause);
    }
}
