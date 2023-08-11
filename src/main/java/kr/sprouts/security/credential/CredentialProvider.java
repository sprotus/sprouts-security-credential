package kr.sprouts.security.credential;

import javax.validation.constraints.NotNull;
import java.util.UUID;

public interface CredentialProvider<S extends Subject> {
    UUID getId();
    String getName();
    Credential provide(@NotNull S subject);
}
