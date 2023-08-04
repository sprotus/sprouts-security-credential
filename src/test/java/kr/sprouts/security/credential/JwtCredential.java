package kr.sprouts.security.credential;

class JwtCredential extends Credential<String> {
    private JwtCredential(String value) {
        super(value);
    }

    static JwtCredential of(String value) {
        return new JwtCredential(value);
    }
}
