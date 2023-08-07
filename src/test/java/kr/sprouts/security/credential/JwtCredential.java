package kr.sprouts.security.credential;

class JwtCredential implements Credential<String> {
    private final String value;
    private JwtCredential(String value) {
        this.value = value;
    }

    static JwtCredential of(String value) {
        return new JwtCredential(value);
    }

    @Override
    public String getValue() {
        return value;
    }
}
