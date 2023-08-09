package kr.sprouts.security.credential;

import java.util.List;
import java.util.UUID;

public class Principal<S extends Subject> {
    private UUID providerId;
    private List<UUID> targetConsumers;
    private S subject;

    public Principal() { }

    public Principal(UUID providerId, List<UUID> targetConsumers, S subject) {
        this.providerId = providerId;
        this.targetConsumers = targetConsumers;
        this.subject = subject;
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
