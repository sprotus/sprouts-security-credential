package kr.sprouts.security.credential;

public interface CredentialParam<T extends Principal> {
    T getPrincipal();
}
