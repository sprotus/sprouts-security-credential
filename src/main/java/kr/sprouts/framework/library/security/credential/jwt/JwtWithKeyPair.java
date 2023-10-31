package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import jakarta.validation.constraints.NotNull;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class JwtWithKeyPair implements Jwt<KeyPair> {
    @NotNull
    private final SignatureAlgorithm signatureAlgorithm;
    @NotNull
    private final String familyName;

    public JwtWithKeyPair(SignatureAlgorithm signatureAlgorithm, String familyName) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.familyName = familyName;
    }

    @Override
    public KeyPair generateSecret() {
        try {
            return signatureAlgorithm.keyPair().build();
        } catch (RuntimeException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public String createClaimsJws(Claims claims, byte[] privateKeyBytes) {
        try {
            return Jwts.builder()
                    .claims(claims)
                    .signWith(KeyFactory.getInstance(familyName).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)))
                    .compact();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(String claimsJws, byte[] publicKeyBytes) {
        try {
            return Jwts.parser()
                    .verifyWith(KeyFactory.getInstance(familyName).generatePublic(new X509EncodedKeySpec(publicKeyBytes)))
                    .build()
                    .parseSignedClaims(claimsJws)
                    .getPayload();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ClaimsJwsParseException(e);
        }
    }
}
