package kr.sprouts.security.credential;

import java.util.UUID;

public interface CredentialConsumer<C extends Credential, P extends Principal<S>, S extends Subject> {
    UUID getId();
    String getName();
    P consume(C credential);
}
