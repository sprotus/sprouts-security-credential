package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class JwtWithKeyPair implements Jwt<KeyPair> {
    @NotNull
    private final SignatureAlgorithm signatureAlgorithm;

    JwtWithKeyPair(@NotNull SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public KeyPair generateSecret() {
        try {
            return Keys.keyPairFor(signatureAlgorithm);
        } catch (RuntimeException e) {
            throw new GenerateSecretException(e);
        }
    }

    @Override
    public String createClaimsJws(@NotNull Claims claims, @NotEmpty byte[] privateKeyBytes) {
        try {
            return Jwts.builder()
                    .setClaims(claims)
                    .signWith(KeyFactory.getInstance(signatureAlgorithm.getFamilyName()).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)), signatureAlgorithm)
                    .compact();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ClaimsJwsCreateException(e);
        }
    }

    @Override
    public Claims parseClaimsJws(@NotBlank String claimsJws, @NotEmpty byte[] publicKeyBytes) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(KeyFactory.getInstance(signatureAlgorithm.getFamilyName()).generatePublic(new X509EncodedKeySpec(publicKeyBytes)))
                    .build()
                    .parseClaimsJws(claimsJws)
                    .getBody();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ClaimsJwsParseException(e);
        }
    }
}
