package kr.sprouts.security.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sprouts.security.credential.cipher.Cipher;
import kr.sprouts.security.credential.cipher.CipherAlgorithm;
import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class ApiKeyCredentialConsumer implements CredentialConsumer<ApiKeyCredential, ApiKeyPrincipal, ApiKeySubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Cipher<?> cipher;
    private final byte[] decryptSecret;
    private final List<UUID> validProviderIds;

    private ApiKeyCredentialConsumer(String consumerId, String consumerName, String codec, String algorithmName, String encodedDecryptSecret, List<String> validProviderIds) {
        this.id = UUID.fromString(consumerId);
        this.name = consumerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.cipher = CipherAlgorithm.fromName(algorithmName).getCipherSupplier().get();
        this.decryptSecret = this.codec.decode(encodedDecryptSecret);
        this.validProviderIds = validProviderIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static ApiKeyCredentialConsumer of(CredentialConsumerSpec property) {
        return new ApiKeyCredentialConsumer(
                property.getId(),
                property.getName(),
                property.getCodec(),
                property.getAlgorithm(),
                property.getEncodedSecret(),
                property.getValidProviders().stream().map(CredentialConsumerSpec.ValidProvider::getId).collect(Collectors.toList())
        );
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public ApiKeyPrincipal consume(ApiKeyCredential credential) {
        try {
            ApiKeyPrincipal apiKeyPrincipal = objectMapper.readValue(cipher.decryptToString(codec.decode(credential.getValue()), decryptSecret), ApiKeyPrincipal.class);

            if (!isValidProvider(apiKeyPrincipal.getProviderId())) throw new RuntimeException("Invalid provider.");

            return apiKeyPrincipal;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private Boolean isValidProvider(UUID providerId) {
        return validProviderIds.contains(providerId) ? Boolean.TRUE : Boolean.FALSE;
    }
}
