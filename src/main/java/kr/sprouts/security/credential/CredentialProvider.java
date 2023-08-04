package kr.sprouts.security.credential;

public interface CredentialProvider<S extends CredentialParam, T extends Credential<?>> {
    T provide(S param, byte[] secret);
}
