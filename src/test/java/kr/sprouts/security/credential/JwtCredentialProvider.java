package kr.sprouts.security.credential;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import kr.sprouts.security.credential.jwt.Jwt;
import kr.sprouts.security.credential.jwt.JwtAlgorithm;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

public class JwtCredentialProvider implements CredentialProvider<JwtCredentialParameter, JwtCredential> {
    private final Jwt<?> jwt;

    private JwtCredentialProvider(Jwt<?> jwt) {
        this.jwt = jwt;
    }

    public static JwtCredentialProvider fromJwt(Jwt<?> jwt) {
        return new JwtCredentialProvider(jwt);
    }

    static JwtCredentialProvider fromJwtAlgorithm(JwtAlgorithm jwtAlgorithm) {
        return new JwtCredentialProvider(jwtAlgorithm.getJwtSupplier().get());
    }

    static JwtCredentialProvider fromJwtAlgorithmName(String jwtAlgorithmName) {
        return new JwtCredentialProvider(JwtAlgorithm.fromName(jwtAlgorithmName).getJwtSupplier().get());
    }

    @Override
    public JwtCredential provide(JwtCredentialParameter param, byte[] secret) {
        return JwtCredential.of(jwt.createClaimsJws(convertToClaims(param), secret));
    }

    private Claims convertToClaims(JwtCredentialParameter param) {
        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(UUID.randomUUID().toString());
        claims.setSubject(param.getPrincipal().getMemberId());
        claims.setIssuer(param.getPrincipal().getProviderId());
        claims.setAudience(param.getPrincipal().getConsumerId());
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime.minusSeconds(10)));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusMinutes(param.getValidityInMinute())));

        return claims;
    }
}
