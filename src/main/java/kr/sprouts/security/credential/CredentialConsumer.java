package kr.sprouts.security.credential;

import java.util.UUID;

public interface CredentialConsumer<S extends Subject> {
    UUID getId();
    String getName();
    Principal<S> consume(Credential credential);
}
