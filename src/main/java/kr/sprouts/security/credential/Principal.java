package kr.sprouts.security.credential;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.UUID;

public class Principal<S extends Subject> {
    @NotNull
    private UUID providerId;
    @NotEmpty
    private List<UUID> targetConsumers;
    @NotNull
    private S subject;

    private Principal() { }

    private Principal(@NotEmpty UUID providerId, @NotEmpty List<UUID> targetConsumers, @NotNull S subject) {
        this.providerId = providerId;
        this.targetConsumers = targetConsumers;
        this.subject = subject;
    }

    public static <S extends Subject> Principal<S> of(@NotEmpty UUID providerId, @NotEmpty List<UUID> targetConsumers, @NotNull S subject) {
        return new Principal<>(providerId, targetConsumers, subject);
    }

    public UUID getProviderId() {
        return providerId;
    }

    public List<UUID> getTargetConsumers() {
        return targetConsumers;
    }

    public S getSubject() {
        return subject;
    }
}
