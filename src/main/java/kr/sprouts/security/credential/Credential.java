package kr.sprouts.security.credential;

import java.util.List;
import java.util.UUID;

public class Credential {
    private UUID providerId;
    private List<UUID> consumerIds;
    private String value;

    public Credential() { }

    public Credential(UUID providerId, List<UUID> consumerIds, String value) {
        this.providerId = providerId;
        this.consumerIds = consumerIds;
        this.value = value;
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
