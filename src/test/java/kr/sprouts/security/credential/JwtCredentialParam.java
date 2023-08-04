package kr.sprouts.security.credential;

class JwtCredentialParam extends CredentialParam {
    private final Long validityInMinute;

    private JwtCredentialParam(Principal principal, Long validityInMinute) {
        super(principal);
        this.validityInMinute = validityInMinute;
    }

    static JwtCredentialParam of(Principal principal, Long validityInMinute) {
        return new JwtCredentialParam(principal, validityInMinute);
    }

    Long getValidityInMinute() {
        return validityInMinute;
    }
}
