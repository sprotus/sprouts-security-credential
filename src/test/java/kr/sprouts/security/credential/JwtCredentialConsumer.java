package kr.sprouts.security.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;
import kr.sprouts.security.credential.jwt.Jwt;
import kr.sprouts.security.credential.jwt.JwtAlgorithm;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class JwtCredentialConsumer implements CredentialConsumer<JwtSubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Jwt<?> jwt;
    private final byte[] decryptSecret;
    private final List<UUID> validProviderIds;

    private JwtCredentialConsumer(String consumerId, String consumerName, String codec, String algorithm, String encodedDecryptSecret, List<String> validProviderIds) {
        this.id = UUID.fromString(consumerId);
        this.name = consumerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.jwt = JwtAlgorithm.fromName(algorithm).getJwtSupplier().get();
        this.decryptSecret = this.codec.decode(encodedDecryptSecret);
        this.validProviderIds = validProviderIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static JwtCredentialConsumer of(CredentialConsumerSpec spec) {
        return new JwtCredentialConsumer(
                spec.getId(),
                spec.getName(),
                spec.getCodec(),
                spec.getAlgorithm(),
                spec.getEncodedSecret(),
                spec.getValidProviders().stream().map(CredentialConsumerSpec.ValidProvider::getId).collect(Collectors.toList())
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
    public Principal<JwtSubject> consume(Credential credential) {
        try {
            Principal<JwtSubject> principal = principal(jwt.parseClaimsJws(credential.getValue(), decryptSecret));

            if (!isValidProvider(principal.getProviderId())) throw new RuntimeException("Invalid provider.");

            return principal;
        } catch (RuntimeException | JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private Principal<JwtSubject> principal(Claims claims) throws JsonProcessingException {
        return Principal.of(
                UUID.fromString(claims.getIssuer()),
                objectMapper.readValue(claims.getAudience(), new TypeReference<>() { }),
                JwtSubject.of(
                        UUID.fromString(claims.getSubject()),
                        TimeUnit.MINUTES.convert(Math.abs(claims.getExpiration().getTime() - claims.getIssuedAt().getTime()), TimeUnit.MILLISECONDS)
                )
        );
    }

    private Boolean isValidProvider(UUID providerId) {
        return validProviderIds.contains(providerId) ? Boolean.TRUE : Boolean.FALSE;
    }
}
