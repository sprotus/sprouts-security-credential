package kr.sprouts.security.credential;

public class CredentialParam {
    Principal principal;

    public CredentialParam(Principal principal) {
        this.principal = principal;
    }

    public Principal getPrincipal() {
        return principal;
    }
}
