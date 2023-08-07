package kr.sprouts.security.credential;

public interface CredentialProvider<S extends CredentialParam<? extends Principal>, T extends Credential<?>> {
    T provide(S credentialParam, byte[] secret);
}
