package kr.sprouts.security.credential;

class CipherCredentialParameter implements CredentialParameter<Principal> {
    private final Principal principal;

    public CipherCredentialParameter(Principal principal) {
        this.principal = principal;
    }

    static CipherCredentialParameter of(Principal principal) {
        return new CipherCredentialParameter(principal);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }
}
