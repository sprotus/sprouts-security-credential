package kr.sprouts.security.credential;

class JwtCredentialParam implements CredentialParam<Principal> {
    private final Principal principal;
    private final Long validityInMinute;

    private JwtCredentialParam(Principal principal, Long validityInMinute) {
        this.principal = principal;
        this.validityInMinute = validityInMinute;
    }

    static JwtCredentialParam of(Principal principal, Long validityInMinute) {
        return new JwtCredentialParam(principal, validityInMinute);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    public Long getValidityInMinute() {
        return validityInMinute;
    }
}
