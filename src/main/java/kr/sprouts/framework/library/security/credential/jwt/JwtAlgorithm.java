package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Jwts;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.function.Supplier;

public enum JwtAlgorithm {
    HS256("HS256", () -> new JwtWithSecretKey(Jwts.SIG.HS256)),
    HS384("HS384", () -> new JwtWithSecretKey(Jwts.SIG.HS384)),
    HS512("HS512", () -> new JwtWithSecretKey(Jwts.SIG.HS512)),
    RS256("RS256", () -> new JwtWithKeyPair(Jwts.SIG.RS256, JwtAlgorithm.RSA_FAMILY_NAME)),
    RS384("RS384", () -> new JwtWithKeyPair(Jwts.SIG.RS384, JwtAlgorithm.RSA_FAMILY_NAME)),
    RS512("RS512", () -> new JwtWithKeyPair(Jwts.SIG.RS512, JwtAlgorithm.RSA_FAMILY_NAME)),
    ES256("ES256", () -> new JwtWithKeyPair(Jwts.SIG.ES256, JwtAlgorithm.ECDSA_FAMILY_NAME)),
    ES384("ES384", () -> new JwtWithKeyPair(Jwts.SIG.ES384, JwtAlgorithm.ECDSA_FAMILY_NAME)),
    ES512("ES512", () -> new JwtWithKeyPair(Jwts.SIG.ES512, JwtAlgorithm.ECDSA_FAMILY_NAME)),
    PS256("PS256", () -> new JwtWithKeyPair(Jwts.SIG.PS256, JwtAlgorithm.RSA_FAMILY_NAME)),
    PS384("PS384", () -> new JwtWithKeyPair(Jwts.SIG.PS384, JwtAlgorithm.RSA_FAMILY_NAME)),
    PS512("PS512", () -> new JwtWithKeyPair(Jwts.SIG.PS512, JwtAlgorithm.RSA_FAMILY_NAME)),
    ;

    private static final String RSA_FAMILY_NAME = "RSA";
    private static final String ECDSA_FAMILY_NAME = "ECDSA";

    JwtAlgorithm(String name, Supplier<Jwt<?>> jwtSupplier) {
        this.name = name;
        this.jwtSupplier = jwtSupplier;
    }

    @NotBlank
    private final String name;
    @NotNull
    private final Supplier<Jwt<?>> jwtSupplier;

    public static JwtAlgorithm fromName(String name) {
        for (JwtAlgorithm jwtAlgorithm : values()) {
            if (jwtAlgorithm.getName().equalsIgnoreCase(name)) return jwtAlgorithm;
        }

        throw new UnsupportedJwtAlgorithmException();
    }

    public String getName() {
        return name;
    }

    public Supplier<Jwt<?>> getJwtSupplier() {
        return jwtSupplier;
    }
}
