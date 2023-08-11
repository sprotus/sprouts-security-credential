package kr.sprouts.security.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;
import kr.sprouts.security.credential.jwt.Jwt;
import kr.sprouts.security.credential.jwt.JwtAlgorithm;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class JwtCredentialProvider implements CredentialProvider<JwtSubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Jwt<?> jwt;
    private final byte[] encryptSecret;
    private final List<UUID> targetConsumerIds;

    private JwtCredentialProvider(String providerId, String providerName, String codec, String algorithm, String encodedEncryptSecret, List<String> targetConsumerIds) {
        this.id = UUID.fromString(providerId);
        this.name = providerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.jwt = JwtAlgorithm.fromName(algorithm).getJwtSupplier().get();
        this.encryptSecret = this.codec.decode(encodedEncryptSecret);
        this.targetConsumerIds = targetConsumerIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    public static JwtCredentialProvider of(CredentialProviderSpec spec) {
        return new JwtCredentialProvider(
                spec.getId(),
                spec.getName(),
                spec.getCodec(),
                spec.getAlgorithm(),
                spec.getEncodedSecret(),
                spec.getTargetConsumers().stream().map(CredentialProviderSpec.TargetConsumer::getId).collect(Collectors.toList())
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
    public Credential provide(JwtSubject subject) {
        try {
            return Credential.of(
                    id,
                    targetConsumerIds,
                    jwt.createClaimsJws(claims(Principal.of(id, targetConsumerIds, subject)), encryptSecret)
            );
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private Claims claims(Principal<JwtSubject> principal) throws JsonProcessingException {
        LocalDateTime currentDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setIssuer(principal.getProviderId().toString());
        claims.setSubject(principal.getSubject().getMemberId().toString());
        claims.setAudience(objectMapper.writeValueAsString(principal.getTargetConsumers()));
        claims.setIssuedAt(Timestamp.valueOf(currentDateTime));
        claims.setNotBefore(Timestamp.valueOf(currentDateTime.minusSeconds(60)));
        claims.setExpiration(Timestamp.valueOf(currentDateTime.plusMinutes(principal.getSubject().getValidityInMinutes())));

        return claims;
    }
}
