package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class JwtWithKeyPair implements Jwt<KeyPair> {
    private final SignatureAlgorithm signatureAlgorithm;

    public JwtWithKeyPair(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public KeyPair generateSecret() {
        try {
            return Keys.keyPairFor(signatureAlgorithm);
        } catch (Throwable e) {
            throw new JwtGenerateSecretException(e);
        }
    }

    @Override
    public String createClaimsJws(Claims claims, byte[] privateKeyBytes) {
        try {
            return Jwts.builder()
                    .setClaims(claims)
                    .signWith(KeyFactory.getInstance(signatureAlgorithm.getFamilyName()).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)), signatureAlgorithm)
                    .compact();
        } catch (Throwable e) {
            throw new JwtCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(String claimsJws, byte[] publicKeyBytes) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(KeyFactory.getInstance(signatureAlgorithm.getFamilyName()).generatePublic(new X509EncodedKeySpec(publicKeyBytes)))
                    .build()
                    .parseClaimsJws(claimsJws)
                    .getBody();
        } catch (Throwable e) {
            throw new JwtParseException(e);
        }
    }
}
