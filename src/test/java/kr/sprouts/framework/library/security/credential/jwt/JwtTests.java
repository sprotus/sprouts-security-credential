package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

class JwtTests {
    Logger log = Logger.getLogger(this.getClass().getName());

    @Test
    void createAndParse() {
        Security.addProvider(new BouncyCastleProvider());

        Claims claims = initializeClaims();

        for (JwtAlgorithm jwtAlgorithm : JwtAlgorithm.values()) {
            Jwt<?> jwt = jwtAlgorithm.getJwtSupplier().get();

            Object secret = jwt.generateSecret();

            if (secret instanceof SecretKey secretKey) {
                String claimsJws = jwt.createClaimsJws(claims, secretKey.getEncoded());
                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, secretKey.getEncoded());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());
            } else if (secret instanceof KeyPair keyPair) {
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                String claimsJws = jwt.createClaimsJws(claims, privateKey.getEncoded());
                Claims parsedClaims = jwt.parseClaimsJws(claimsJws, publicKey.getEncoded());

                Assertions.assertEquals(claims.getSubject(), parsedClaims.getSubject());
            }

            if (log.isLoggable(Level.INFO)) {
                log.info(String.format("Jwt algorithm '%s' test complete.", jwtAlgorithm.getName()));
            }
        }
    }

    private Claims initializeClaims() {
        LocalDateTime current = LocalDateTime.now();

        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();

        LocalDateTime currentDateTime = LocalDateTime.now();

        return Jwts.claims()
                .issuer(issuer)
                .subject(subject)
                .audience().add(audience).and()
                .issuedAt(Timestamp.valueOf(currentDateTime))
                .notBefore(Timestamp.valueOf(currentDateTime.minusSeconds(60)))
                .expiration(Timestamp.valueOf(current.plusSeconds(60)))
                .build();
    }
}
