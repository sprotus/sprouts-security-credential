package kr.sprouts.security.credential;

class CipherCredentialParam extends CredentialParam {
    private CipherCredentialParam(Principal principal) {
        super(principal);
    }

    static CipherCredentialParam of(Principal principal) {
        return new CipherCredentialParam(principal);
    }
}
