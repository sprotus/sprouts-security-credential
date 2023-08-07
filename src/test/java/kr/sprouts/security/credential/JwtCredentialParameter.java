package kr.sprouts.security.credential;

public class JwtCredentialParameter implements CredentialParameter<Principal> {
    private final Principal principal;
    private final Long validityInMinute;

    private JwtCredentialParameter(Principal principal, Long validityInMinute) {
        this.principal = principal;
        this.validityInMinute = validityInMinute;
    }

    static JwtCredentialParameter of(Principal principal, Long validityInMinute) {
        return new JwtCredentialParameter(principal, validityInMinute);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    public Long getValidityInMinute() {
        return validityInMinute;
    }
}
