package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import jakarta.validation.constraints.NotNull;

import javax.crypto.SecretKey;

class JwtWithSecretKey implements Jwt<SecretKey> {
    @NotNull
    private final MacAlgorithm macAlgorithm;

    JwtWithSecretKey(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    @Override
    public SecretKey generateSecret() {
        try {
            return macAlgorithm.key().build();
        } catch (RuntimeException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public String createClaimsJws(Claims claims, byte[] secret) {
        try {
            return Jwts.builder()
                    .claims(claims)
                    .signWith(Keys.hmacShaKeyFor(secret))
                    .compact();
        } catch (RuntimeException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(String claimsJws, byte[] secret) {
        try {
            return Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secret))
                    .build()
                    .parseSignedClaims(claimsJws)
                    .getPayload();
        } catch (RuntimeException e) {
            throw new ClaimsJwsParseException(e);
        }
    }
}
