package kr.sprouts.security.credential;

public class JwtCredentialParameter extends CredentialParameter<Principal> {
    private final Long validityInMinute;

    private JwtCredentialParameter(Principal principal, Long validityInMinute) {
        super(principal);
        this.validityInMinute = validityInMinute;
    }

    public static JwtCredentialParameter of(Principal principal, Long validityInMinute) {
        return new JwtCredentialParameter(principal, validityInMinute);
    }

    public Long getValidityInMinute() {
        return validityInMinute;
    }
}
