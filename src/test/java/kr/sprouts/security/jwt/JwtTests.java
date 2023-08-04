package kr.sprouts.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import kr.sprouts.security.codec.CodecType;
import kr.sprouts.security.codec.Codec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.logging.Logger;

class JwtTests {
    Logger log = Logger.getLogger(this.getClass().getName());
    Codec codec = CodecType.BASE64_URL.getCodecSupplier().get();

    @Test
    void createAndParse() {
        for (JwtAlgorithm jwtAlgorithm : JwtAlgorithm.values()) {
            log.info("name : " + jwtAlgorithm.name());

            Jwt<?> jwt = jwtAlgorithm.getJwtSupplier().get();
            Object secret = jwt.generateSecret();

            if (secret instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) secret;
                log.info(codec.encodeToString(secretKey.getEncoded()));

                Claims claims = initializeClaims();
                String claimsJws = jwt.createClaimsJws(claims, secretKey.getEncoded());
                log.info(claimsJws);

                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, secretKey.getEncoded());
                log.info(parsedClaims.getSubject());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());
            } else if (secret instanceof KeyPair) {
                KeyPair keyPair = (KeyPair) secret;
                log.info("PrivateKey: " + codec.encodeToString(keyPair.getPrivate().getEncoded()));
                log.info("PublicKey: " + codec.encodeToString(keyPair.getPublic().getEncoded()));

                Claims claims = initializeClaims();
                String claimsJws = jwt.createClaimsJws(claims, keyPair.getPrivate().getEncoded());
                log.info("ClaimsJws: " + claimsJws);

                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, keyPair.getPublic().getEncoded());
                log.info("ParsedSubject: " + parsedClaims.getSubject());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());
            }
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
