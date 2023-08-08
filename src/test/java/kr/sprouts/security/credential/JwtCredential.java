package kr.sprouts.security.credential;

public class JwtCredential extends Credential<String> {
    private JwtCredential(String key, String value) {
        super(key, value);
    }

    public static JwtCredential of(String key, String value) {
        return new JwtCredential(key, value);
    }
}
