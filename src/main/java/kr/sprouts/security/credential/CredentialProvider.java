package kr.sprouts.security.credential;

import java.util.UUID;

public interface CredentialProvider<S extends Subject> {
    UUID getId();
    String getName();
    Credential provide(S subject);
}
