package kr.sprouts.security.credential;

import io.jsonwebtoken.Claims;
import kr.sprouts.security.credential.jwt.Jwt;
import kr.sprouts.security.credential.jwt.JwtAlgorithm;

public class JwtCredentialConsumer implements CredentialConsumer<JwtCredential> {

    private final Jwt<?> jwt;

    private JwtCredentialConsumer(Jwt<?> jwt) {
        this.jwt = jwt;
    }

    static JwtCredentialConsumer fromJwt(Jwt<?> jwt) {
        return new JwtCredentialConsumer(jwt);
    }

    static JwtCredentialConsumer fromJwtAlgorithm(JwtAlgorithm jwtAlgorithm) {
        return new JwtCredentialConsumer(jwtAlgorithm.getJwtSupplier().get());
    }

    static JwtCredentialConsumer fromJwtAlgorithmName(String jwtAlgorithmName) {
        return new JwtCredentialConsumer(JwtAlgorithm.fromName(jwtAlgorithmName).getJwtSupplier().get());
    }

    @Override
    public Principal consume(JwtCredential credential, byte[] secret) {
        return convertToPrincipal(jwt.parseClaimsJws(credential.getValue(), secret));
    }

    private Principal convertToPrincipal(Claims claims) {
        return Principal.of(claims.getIssuer(), claims.getAudience(), claims.getSubject());
    }
}
