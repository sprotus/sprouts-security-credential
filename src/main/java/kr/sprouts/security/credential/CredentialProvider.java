package kr.sprouts.security.credential;

public interface CredentialProvider<S extends CredentialParameter<? extends Principal>, T extends Credential<?>> {
    T provide(S credentialParam, byte[] secret);
}
