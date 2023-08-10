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

public class CipherCredentialProvider implements CredentialProvider<CipherSubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Cipher<?> cipher;
    private final byte[] encryptSecret;
    private final List<UUID> targetConsumerIds;

    private CipherCredentialProvider(String providerId, String providerName, String codec, String algorithm, String encodedEncryptSecret, List<String> targetConsumerIds) {
        this.id = UUID.fromString(providerId);
        this.name = providerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.cipher = CipherAlgorithm.fromName(algorithm).getCipherSupplier().get();
        this.encryptSecret = this.codec.decode(encodedEncryptSecret);
        this.targetConsumerIds = targetConsumerIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static CipherCredentialProvider of(CredentialProviderSpec property) {
        return new CipherCredentialProvider(
                property.getId(),
                property.getName(),
                property.getCodec(),
                property.getAlgorithm(),
                property.getEncodedSecret(),
                property.getTargetConsumers().stream().map(CredentialProviderSpec.TargetConsumer::getId).collect(Collectors.toList())
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
    public Credential provide(CipherSubject subject) {
        try {
            return Credential.of(
                    id,
                    targetConsumerIds,
                    codec.encodeToString(cipher.encrypt(objectMapper.writeValueAsString(Principal.of(id, targetConsumerIds, subject)), encryptSecret))
            );
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
