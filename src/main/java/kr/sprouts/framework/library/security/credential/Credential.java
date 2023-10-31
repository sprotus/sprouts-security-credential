package kr.sprouts.framework.library.security.credential;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

public class Credential implements Serializable {
    @NotNull
    private final UUID providerId;
    @NotEmpty
    private final List<UUID> consumerIds;
    @NotBlank
    private final String value;

    private Credential(UUID providerId, List<UUID> consumerIds, String value) {
        this.providerId = providerId;
        this.consumerIds = consumerIds;
        this.value = value;
    }

    public static Credential of(UUID providerId, List<UUID> consumerIds, String value) {
        return new Credential(providerId, consumerIds, value);
    }

    public UUID getProviderId() {
        return providerId;
    }

    public List<UUID> getConsumerIds() {
        return consumerIds;
    }

    public String getValue() {
        return value;
    }
}
