package kr.sprouts.security.credential;

import java.util.List;
import java.util.UUID;

public class ApiKeyCredential extends Credential {

    public ApiKeyCredential(UUID providerId, List<UUID> targetConsumerIds, String value) {
        super(providerId, targetConsumerIds, value);
    }

    public static ApiKeyCredential of(UUID providerId, List<UUID> targetConsumerIds, String value) {
        return new ApiKeyCredential(providerId, targetConsumerIds, value);
    }
}
