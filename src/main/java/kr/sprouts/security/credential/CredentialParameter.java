package kr.sprouts.security.credential;

public class CredentialParameter<T extends Principal> {
    private final T principal;

    public CredentialParameter(T principal) {
        this.principal = principal;
    }

    T getPrincipal() {
        return principal;
    }
}
