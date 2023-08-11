package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class JwtWithSecretKey implements Jwt<SecretKey> {
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
                    .setClaims(claims)
                    .signWith(new SecretKeySpec(secret, signatureAlgorithm.getJcaName()), signatureAlgorithm)
                    .compact();
        } catch (RuntimeException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(String claimsJws, byte[] secret) {
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
