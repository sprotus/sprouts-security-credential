package kr.sprouts.security.credential;

class CipherCredentialParameter extends CredentialParameter<Principal> {
    private CipherCredentialParameter(Principal principal) {
        super(principal);
    }

    public static CipherCredentialParameter of(Principal principal) {
        return new CipherCredentialParameter(principal);
    }
}
