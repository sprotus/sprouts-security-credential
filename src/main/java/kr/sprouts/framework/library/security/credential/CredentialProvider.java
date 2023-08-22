package kr.sprouts.framework.library.security.credential;

import java.util.UUID;

public interface CredentialProvider<S extends Subject> {
    UUID getId();
    String getName();
    Credential provide(S subject);
}
