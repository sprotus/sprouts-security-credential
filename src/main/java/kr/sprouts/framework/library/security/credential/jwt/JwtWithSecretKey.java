package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.constraints.NotNull;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class JwtWithSecretKey implements Jwt<SecretKey> {
    @NotNull
    private final SignatureAlgorithm signatureAlgorithm;

    JwtWithSecretKey(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public SecretKey generateSecret() {
        try {
            return Keys.secretKeyFor(signatureAlgorithm);
        } catch (RuntimeException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public String createClaimsJws(Claims claims, byte[] secret) {
        try {
            return Jwts.builder()
                    .claims(claims)
                    .signWith(new SecretKeySpec(secret, signatureAlgorithm.getJcaName()))
                    .compact();
        } catch (RuntimeException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(String claimsJws, byte[] secret) {
        try {
            return Jwts.parser()
                    .verifyWith(new SecretKeySpec(secret, signatureAlgorithm.getJcaName()))
                    .build()
                    .parseSignedClaims(claimsJws)
                    .getPayload();
        } catch (RuntimeException e) {
            throw new ClaimsJwsParseException(e);
        }
    }
}
