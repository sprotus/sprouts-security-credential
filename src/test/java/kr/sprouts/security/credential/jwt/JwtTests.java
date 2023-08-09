package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.logging.Logger;

class JwtTests {
    Logger log = Logger.getLogger(this.getClass().getName());
    Codec codec = CodecType.fromName("BASE64_URL").getCodecSupplier().get();
    @Test
    void createAndParse() {
        Claims claims = initializeClaims();

        for (JwtAlgorithm jwtAlgorithm : JwtAlgorithm.values()) {
            Jwt<?> jwt = jwtAlgorithm.getJwtSupplier().get();

            Object secret = jwt.generateSecret();

            if (secret instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) secret;

                String claimsJws = jwt.createClaimsJws(claims, secretKey.getEncoded());
                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, secretKey.getEncoded());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());

                log.info(jwtAlgorithm.getName() + ": " + codec.encodeToString(secretKey.getEncoded()));
            } else if (secret instanceof KeyPair) {
                KeyPair keyPair = (KeyPair) secret;
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                String claimsJws = jwt.createClaimsJws(claims, privateKey.getEncoded());
                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, publicKey.getEncoded());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());
            }

            log.info(String.format("Jwt algorithm '%s' test complete.", jwtAlgorithm.getName()));
        }
    }

    private Claims initializeClaims() {
        LocalDateTime current = LocalDateTime.now();

        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();

        Claims claims = Jwts.claims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpiration(Timestamp.valueOf(current.plusSeconds(60)));

        return claims;
    }
}
