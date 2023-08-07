package kr.sprouts.security.credential;

class CipherCredentialParam implements CredentialParam<Principal> {
    private final Principal principal;

    public CipherCredentialParam(Principal principal) {
        this.principal = principal;
    }

    static CipherCredentialParam of(Principal principal) {
        return new CipherCredentialParam(principal);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }
}
