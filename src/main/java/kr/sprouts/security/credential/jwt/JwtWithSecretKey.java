package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

class JwtWithSecretKey implements Jwt<SecretKey> {
    @NotNull
    private final SignatureAlgorithm signatureAlgorithm;

    JwtWithSecretKey(@NotNull SignatureAlgorithm signatureAlgorithm) {
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
    public String createClaimsJws(@NotNull Claims claims, @NotEmpty byte[] secret) {
        try {
            return Jwts.builder()
                    .setClaims(claims)
                    .signWith(new SecretKeySpec(secret, signatureAlgorithm.getJcaName()), signatureAlgorithm)
                    .compact();
        } catch (RuntimeException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(@NotBlank String claimsJws, @NotEmpty byte[] secret) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(new SecretKeySpec(secret, signatureAlgorithm.getJcaName()))
                    .build()
                    .parseClaimsJws(claimsJws)
                    .getBody();
        } catch (RuntimeException e) {
            throw new ClaimsJwsParseException(e);
        }
    }
}
