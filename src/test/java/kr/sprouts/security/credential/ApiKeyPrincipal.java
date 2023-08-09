package kr.sprouts.security.credential;

import java.util.List;
import java.util.UUID;

public class ApiKeyPrincipal extends Principal<ApiKeySubject> {
    private ApiKeyPrincipal() { }

    private ApiKeyPrincipal(UUID providerId, List<UUID> targetConsumers, ApiKeySubject subject) {
        super(providerId, targetConsumers, subject);
    }

    public static ApiKeyPrincipal of(UUID providerId, List<UUID> targetConsumers, ApiKeySubject subject) {
        return new ApiKeyPrincipal(providerId, targetConsumers, subject);
    }
}
