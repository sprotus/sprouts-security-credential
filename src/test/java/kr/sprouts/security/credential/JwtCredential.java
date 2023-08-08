package kr.sprouts.security.credential;

public class JwtCredential extends Credential<String> {
    private JwtCredential(String value) {
        super(value);
    }

    public static JwtCredential of(String value) {
        return new JwtCredential(value);
    }
}
