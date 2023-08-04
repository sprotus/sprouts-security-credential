package kr.sprouts.security.credential;

public interface CredentialConsumer<T extends Credential<?>> {
    Principal consume(T credential, byte[] secret);
}
