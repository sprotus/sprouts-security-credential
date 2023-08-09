package kr.sprouts.security.credential;

import java.util.UUID;

public interface CredentialProvider<S extends Subject, C extends Credential> {
    UUID getId();
    String getName();
    C provide(S subject);
}
