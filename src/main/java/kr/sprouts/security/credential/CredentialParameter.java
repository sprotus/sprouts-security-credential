package kr.sprouts.security.credential;

public interface CredentialParameter<T extends Principal> {
    T getPrincipal();
}
