package kr.sprouts.security.credential;

import javax.validation.constraints.NotNull;
import java.util.UUID;

public interface CredentialConsumer<S extends Subject> {
    UUID getId();
    String getName();
    Principal<S> consume(@NotNull Credential credential);
}
